import { writeFileSync } from "node:fs";
import { createHash } from "crypto";
import { join } from "node:path";
import { Protocol } from "devtools-protocol";
import type { CDPSession } from "puppeteer-core";

// Match crawl.ts's loose CDP typing so `.send`/`.on` accept raw method strings.
type CDPSessionType = typeof CDPSession;

export interface DebugStackOptions {
  // Arm breakpoints on native functions (the document.cookie setter, and with
  // `encoding` also btoa/atob/XHR.send). Off by default: halting on a native
  // C++ builtin that is also a PageGraph probe point can trip an engine CHECK
  // (renderer SIGTRAP / "error code 5"). Prefer `breakpoints` (pure-JS offsets).
  native: boolean;
  // Also break on btoa/atob/XMLHttpRequest.send (only when `native` is set).
  encoding: boolean;
  // Arbitrary extra sites: "<urlRegex>#<byteOffset>" or "<urlRegex>@<line>:<col>".
  // These break in JS bytecode (safe), and the byte offset matches the
  // "script position" PageGraph records on cookie storage-set edges.
  breakpoints: string[];
  // Global cap on paused captures so high-frequency calls don't stall the crawl.
  maxCaptures: number;
  // Max captured length per variable value; object variables are JSON-stringified
  // up to this length. Raise to capture full payloads/sensor objects.
  maxValue: number;
  // If set, write the *loaded* source of every script whose URL matches a
  // breakpoint's URL regex into this directory (one file per URL). Prod/obfuscated
  // third-party bundles are often served differently to an out-of-band fetch, so
  // breakpoint coordinates must be computed against the exact bytes the renderer
  // ran — this dump provides them. Requires at least one `breakpoints` spec.
  saveScriptsDir?: string;
}

interface CapturedVariable {
  name: string;
  value: string;
}

interface CapturedScope {
  type: string;
  variables: CapturedVariable[];
  // Set when this scope object was already captured in an earlier (inner) frame
  // of the same stack; its variables are omitted to avoid duplication.
  shared?: boolean;
  // Set when the scope had more variables than MAX_VARS_PER_SCOPE.
  truncated?: boolean;
}

interface CapturedFrame {
  functionName: string;
  url: string;
  lineNumber: number;
  columnNumber: number;
  scopes: CapturedScope[];
}

interface StackRecord {
  target: string;
  seq: number;
  ts: number;
  frames: CapturedFrame[];
}

interface NativeTarget {
  label: string;
  // Expression evaluated in the page context to resolve the function object.
  expression: string;
}

// Capping a few hot dimensions keeps the sidecar (and the crawl) bounded.
// Without these, a single capture can run to megabytes: an obfuscated bundle's
// "closure"/"script" scope can enumerate the entire module (1000+ vars, many of
// them function sources), and the same closure object repeats in every frame.
const MAX_FRAMES = 12;
const MAX_VARS_PER_SCOPE = 100;
// Bounds for the side-effect-free recursive object reader.
const MAX_OBJ_DEPTH = 4;
const MAX_OBJ_PROPS = 50;
// Shared budget of object-property reads PER CAPTURE (across every object in
// every frame). Without this, a single frame in a big framework (React/Next)
// fans out to tens of thousands of getProperties round-trips and stalls the
// crawl. Object expansion stops once this is exhausted.
const CAPTURE_NODE_BUDGET = 800;
// "script" = module-top-level scope; huge and rarely the interesting state.
// `global` is skipped because it is the whole window object — thousands of
// bindings, none of them the page's own work. `with` is skipped as unbounded.
// `script` and `module` are NOT skipped: they hold the top-level bindings of the
// script being paused in, which is precisely where an inline <script> keeps the
// value it is about to write (a top-level `const` in a classic script is a
// script-scope binding, not a local). Skipping them made every top-level inline
// write capture an empty scope chain — the pause landed correctly and reported
// nothing. Both are bounded by one script's own declarations, and the existing
// node budget and value cap still apply.
const SKIP_SCOPE_TYPES = new Set(["global", "with"]);

// Cookie-write boundaries (always armed when --debug-stacks is set).
const COOKIE_TARGETS: NativeTarget[] = [
  {
    label: "document.cookie",
    expression:
      "Object.getOwnPropertyDescriptor(Document.prototype,'cookie').set",
  },
  {
    label: "CookieStore.set",
    expression: "self.CookieStore ? CookieStore.prototype.set : undefined",
  },
];

// Encoding/exfiltration boundaries (armed with --debug-encoding).
const ENCODING_TARGETS: NativeTarget[] = [
  { label: "btoa", expression: "self.btoa" },
  { label: "atob", expression: "self.atob" },
  { label: "XHR.send", expression: "XMLHttpRequest.prototype.send" },
];

interface OffsetBreakpoint {
  spec: string;
  label: string;
  regex: RegExp;
  offset: number;
  // SHA-256 the script had when pass 1 derived this offset, if known. An offset
  // is only meaningful against the exact bytes it was computed from: if the
  // bundle has rotated, the same offset points into unrelated code and would
  // yield confident, wrong evidence. Set => verify before arming.
  expectedSha256?: string;
  // The SHA-256 of the script's pass-1 RESPONSE BODY, when that is all pass 1
  // could supply. It is NOT enforced — a response body and the parsed source
  // can legitimately differ — but it is reported next to the observed hash so
  // the comparison can be made rather than assumed either way.
  pass1ResponseSha256?: string;
  // Inline-script disambiguator. Every inline script in a document shares the
  // document's URL, so a URL+offset target is ambiguous by construction — and
  // an offset valid for one inline script is often in range for another, where
  // it lands in unrelated code. When set, the source immediately preceding the
  // offset must end with this string, which identifies the intended script by
  // its content instead of trusting position alone. Verified at arm time
  // against the bytes the renderer parsed, so it needs nothing from pass 1.
  requirePrecedingSource?: string;
}

// A target that was armed, and the bytes it was armed against. A target here
// with no capture ran nothing; a target in no list never parsed at all.
interface ArmedTarget {
  spec: string;
  label: string;
  url: string;
  line: number;
  col: number;
  observedSha256: string;
  expectedSha256?: string;
  pass1ResponseSha256?: string;
  hashMatchesPass1Response?: boolean;
}

// A target that was deliberately NOT armed, recorded so the gap is visible in
// the output rather than looking like a site that simply never hit the code.
interface SkippedTarget {
  skipped: string;
  spec: string;
  label: string;
  url: string;
  expectedSha256?: string;
  actualSha256?: string;
}

// PageGraph records a flat character offset ("script position") into the
// script source, but CDP breakpoints are addressed by (line, column). Convert
// against the actual source so an offset spec lands at the right statement even
// when the script spans multiple lines.
const offsetToLineCol = (
  source: string,
  offset: number,
): { lineNumber: number; columnNumber: number } => {
  const end = Math.min(offset, source.length);
  let lineNumber = 0;
  let lineStart = 0;
  for (let i = 0; i < end; i++) {
    if (source.charCodeAt(i) === 10 /* \n */) {
      lineNumber++;
      lineStart = i + 1;
    }
  }
  return { lineNumber, columnNumber: end - lineStart };
};

/**
 * Attaches the CDP Debugger and, at each targeted call site (cookie writes,
 * optional encoding boundaries, and arbitrary user offsets), pauses to record
 * the JS call stack plus the local/closure scope variable values, then resumes.
 *
 * This recovers intermediate values that PageGraph's boundary instrumentation
 * cannot see (e.g. the pre-encryption state a tracker feeds into a pure-JS
 * cipher). Offset specs ("#<offset>") are placed at the exact (line, column)
 * derived from the script source; "@line:col" specs use setBreakpointByUrl.
 * Native functions (opt-in) use setBreakpointOnFunctionCall — note that halting
 * on a native builtin can crash PageGraph builds (renderer SIGTRAP).
 */
export class DebugStackTracker {
  readonly #logger: Logger | undefined;
  readonly #opts: DebugStackOptions;
  #client: CDPSessionType | undefined;
  #records: StackRecord[] = [];
  #seq = 0;
  #scriptUrls = new Map<string, string>();
  #breakpointLabels = new Map<string, string>();
  #armedContexts = new Set<number>();
  #offsetBreakpoints: OffsetBreakpoint[] = [];
  #armedOffsetKeys = new Set<string>();
  #skippedTargets: SkippedTarget[] = [];
  #armedTargets: ArmedTarget[] = [];
  #instrumentationPauseActive = false;
  #inlineMisses: SkippedTarget[] = [];
  // Where each script begins inside its document. Zero for an external file, but
  // an inline <script> starts partway down the page and CDP addresses its
  // breakpoints in DOCUMENT coordinates, while a PageGraph offset is relative to
  // the script's OWN source. Without this the location is short by the script's
  // start position and setBreakpoint answers "Could not resolve breakpoint".
  #scriptStarts = new Map<string, { line: number; column: number }>();
  // URL regexes from every breakpoint spec, used to decide which loaded scripts
  // to dump (see saveScriptsDir); and the set of URLs already written.
  #breakpointUrlRegexes: RegExp[] = [];
  #savedScriptUrls = new Set<string>();
  #capping = false;

  constructor(logger: Logger | undefined, opts: DebugStackOptions) {
    this.#logger = logger;
    this.#opts = opts;
  }

  #log(methodName: string, msg: string): void {
    if (!this.#logger) {
      return;
    }
    this.#logger.info(`DebugStackTracker.${methodName}) `, msg);
  }

  // Must be called before page.goto so breakpoints exist when scripts parse.
  async enable(client: CDPSessionType): Promise<void> {
    this.#client = client;
    await client.send("Runtime.enable");
    await client.send("Debugger.enable");
    await client.send("Debugger.setPauseOnExceptions", { state: "none" });

    client.on(
      "Debugger.scriptParsed",
      (event: Protocol.Debugger.ScriptParsedEvent) => {
        this.#scriptUrls.set(event.scriptId, event.url);
        this.#scriptStarts.set(event.scriptId, {
          line: event.startLine,
          column: event.startColumn,
        });
        // Offset breakpoints can only be placed once we can read the source to
        // convert offset -> (line, column), which is when the script parses.
        // But scriptParsed does not hold execution, so when the instrumentation
        // pause is available we arm from there instead: arming from both would
        // let this racing path win, mark the target armed, and leave the pause
        // handler with nothing to do — a breakpoint placed just after the code
        // it was meant to catch.
        if (!this.#instrumentationPauseActive) {
          void this.#armOffsetsForScript(event);
        }
        // Dump the loaded source of breakpoint-targeted scripts so coordinates
        // can be verified against the exact bytes the renderer ran.
        void this.#maybeSaveScript(event);
      },
    );

    // Native-function breakpoints are opt-in: halting on a native builtin that
    // is also a PageGraph probe can crash the renderer (SIGTRAP) on this build.
    if (this.#opts.native) {
      client.on(
        "Runtime.executionContextCreated",
        (event: Protocol.Runtime.ExecutionContextCreatedEvent) => {
          void this.#armNativeTargets(event.context);
        },
      );
    }

    client.on("Debugger.paused", (event: Protocol.Debugger.PausedEvent) => {
      void this.#onPaused(event);
    });

    // Register the user breakpoint specs. "@line:col" specs apply immediately
    // via setBreakpointByUrl; "#offset" specs are deferred until the matching
    // script parses (so we can convert the offset to a line/column).
    for (const spec of this.#opts.breakpoints) {
      await this.#registerSpec(spec);
    }

    // Offset targets are placed from inside the beforeScriptExecution pause,
    // so the breakpoint must exist before navigation. Only armed when there is
    // something to place: it pauses on every script, which is wasted work
    // otherwise.
    if (this.#offsetBreakpoints.length > 0) {
      try {
        await client.send("Debugger.setInstrumentationBreakpoint", {
          instrumentation: "beforeScriptExecution",
        });
        this.#instrumentationPauseActive = true;
        this.#log(
          "enable",
          "armed beforeScriptExecution instrumentation pause",
        );
      } catch (err) {
        this.#log(
          "enable",
          `could not set the beforeScriptExecution pause (${String(err)}); ` +
            "offset targets may miss code that runs at load",
        );
      }
    }

    if (
      !this.#opts.native &&
      this.#opts.breakpoints.length === 0 &&
      this.#offsetBreakpoints.length === 0
    ) {
      this.#log(
        "enable",
        "no targets armed: pass --debug-breakpoint '<urlRegex>#<offset>' " +
          "(offsets come from the 'script position' on cookie edges), or " +
          "--debug-native to break on native functions (may be unstable).",
      );
    }
  }

  getRecords(): StackRecord[] {
    return this.#records;
  }

  // Targets deliberately left unarmed (script rotated since pass 1). Reported
  // alongside the captures so a missing value reads as "not attempted, and
  // here is why" rather than "the site never ran that code".
  getSkippedTargets(): SkippedTarget[] {
    return this.#skippedTargets;
  }

  // Every target that was armed, with the hash of the bytes it was armed
  // against. A target present here with no capture ran nothing; a target in
  // neither list never parsed at all. The three lists together mean an absent
  // value always has a stated reason.
  getArmedTargets(): ArmedTarget[] {
    return this.#armedTargets;
  }

  // Targets whose script never parsed at all, so nothing was even attempted.
  // The commonest cause is a content blocker in the pass-2 browser: it blocks
  // exactly the tracker scripts a probe exists to pause in, and the run then
  // looks like a site that quietly stopped setting the cookie. Naming it here
  // is the difference between a stated gap and a wrong conclusion.
  getUnarmedTargets(): SkippedTarget[] {
    const seen = new Set([
      ...this.#armedTargets.map((a) => a.spec),
      ...this.#skippedTargets.map((s) => s.spec),
    ]);
    // An inline target that matched no script at all: report the near-misses,
    // which say what was actually at that offset, rather than a bare "never
    // parsed" that would point at the wrong cause entirely.
    const unmatchedInline = this.#inlineMisses.filter(
      (m) => !this.#armedTargets.some((a) => a.spec === m.spec),
    );
    return this.#offsetBreakpoints
      .filter((ob) => !seen.has(ob.spec))
      .filter((ob) => !unmatchedInline.some((m) => m.spec === ob.spec))
      .map((ob) => ({
        skipped:
          "script never parsed — no script matching this URL pattern loaded. " +
          "If the pass-2 browser blocks trackers (Brave with shields on, an " +
          "extension, a filtering DNS), it blocked the target itself; verify " +
          "the request was answered before reading anything into the absence.",
        spec: ob.spec,
        label: ob.label,
        url: "",
      }))
      .concat(unmatchedInline);
  }

  /**
   * Register probe targets derived from a pass-1 crawl. Unlike a bare
   * `--debug-breakpoint` spec these carry the SHA-256 the script had when the
   * offset was computed, which is what makes the offset trustworthy: it is
   * verified against the bytes the renderer parses before the breakpoint is
   * armed. Must be called before page.goto, like registerSpec.
   */
  registerTargets(
    targets: {
      urlRegex: string;
      offset: number;
      expectedSha256?: string;
      pass1ResponseSha256?: string;
      requirePrecedingSource?: string;
      label?: string;
    }[],
  ): void {
    for (const tgt of targets) {
      try {
        const regex = new RegExp(tgt.urlRegex);
        this.#breakpointUrlRegexes.push(regex);
        this.#offsetBreakpoints.push({
          spec: `${tgt.urlRegex}#${String(tgt.offset)}`,
          label: tgt.label ?? `probe:${tgt.urlRegex}#${String(tgt.offset)}`,
          regex,
          offset: tgt.offset,
          expectedSha256: tgt.expectedSha256,
          pass1ResponseSha256: tgt.pass1ResponseSha256,
          requirePrecedingSource: tgt.requirePrecedingSource,
        });
      } catch (err) {
        this.#log(
          "registerTargets",
          `bad target ${tgt.urlRegex}: ${String(err)}`,
        );
      }
    }
    this.#log(
      "registerTargets",
      `registered ${String(targets.length)} probe target(s)`,
    );
  }

  // Stop debugging: deactivate breakpoints, resume any active pause, and detach
  // the Debugger domain. MUST be called before Page.generatePageGraph / page
  // teardown — a renderer paused at a breakpoint cannot generate the graph (it
  // times out) and closing it mid-pause throws "Session closed".
  async disable(): Promise<void> {
    const client = this.#client;
    if (!client) {
      return;
    }
    // Each is best-effort: resume throws if not currently paused; disable may
    // race teardown.
    try {
      await client.send("Debugger.setBreakpointsActive", { active: false });
    } catch {
      /* best effort */
    }
    try {
      await client.send("Debugger.resume");
    } catch {
      /* not paused */
    }
    try {
      await client.send("Debugger.disable");
    } catch {
      /* racing teardown */
    }
  }

  // Re-resolve and arm native function breakpoints for each new main-world
  // context (function object ids are per-execution-context).
  async #armNativeTargets(
    context: Protocol.Runtime.ExecutionContextDescription,
  ): Promise<void> {
    const client = this.#client;
    if (!client) {
      return;
    }
    const auxData = context.auxData as { isDefault?: boolean } | undefined;
    if (auxData?.isDefault === false) {
      return;
    }
    if (this.#armedContexts.has(context.id)) {
      return;
    }
    this.#armedContexts.add(context.id);

    const targets = this.#opts.encoding
      ? [...COOKIE_TARGETS, ...ENCODING_TARGETS]
      : COOKIE_TARGETS;

    for (const target of targets) {
      try {
        const evalRes = (await client.send("Runtime.evaluate", {
          expression: target.expression,
          contextId: context.id,
          silent: true,
        })) as Protocol.Runtime.EvaluateResponse;
        const remote = evalRes.result;
        if (remote.type !== "function" || remote.objectId === undefined) {
          continue;
        }
        const bp = (await client.send("Debugger.setBreakpointOnFunctionCall", {
          objectId: remote.objectId,
        })) as Protocol.Debugger.SetBreakpointOnFunctionCallResponse;
        this.#breakpointLabels.set(bp.breakpointId, target.label);
        this.#log("armNativeTargets", `armed ${target.label}`);
      } catch (err) {
        this.#log("armNativeTargets", `failed ${target.label}: ${String(err)}`);
      }
    }
  }

  // "<urlRegex>@<line>:<col>" -> armed immediately (no source needed).
  // "<urlRegex>#<offset>"     -> deferred to #armOffsetsForScript on parse.
  async #registerSpec(spec: string): Promise<void> {
    const client = this.#client;
    if (!client) {
      return;
    }
    const hashIdx = spec.lastIndexOf("#");
    const atIdx = spec.lastIndexOf("@");

    if (atIdx !== -1 && atIdx > hashIdx) {
      const urlRegex = spec.slice(0, atIdx);
      try {
        this.#breakpointUrlRegexes.push(new RegExp(urlRegex));
      } catch {
        /* invalid regex is reported below by setBreakpointByUrl */
      }
      const parts = spec.slice(atIdx + 1).split(":");
      const lineNumber = Number(parts[0]);
      const columnNumber = Number(parts[1] ?? "0");
      if (Number.isNaN(lineNumber) || Number.isNaN(columnNumber)) {
        this.#log("registerSpec", `ignoring non-numeric spec: ${spec}`);
        return;
      }
      try {
        const bp = (await client.send("Debugger.setBreakpointByUrl", {
          urlRegex,
          lineNumber,
          columnNumber,
        })) as Protocol.Debugger.SetBreakpointByUrlResponse;
        this.#breakpointLabels.set(bp.breakpointId, `bp:${spec}`);
        this.#log("registerSpec", `armed ${spec}`);
      } catch (err) {
        this.#log("registerSpec", `failed ${spec}: ${String(err)}`);
      }
      return;
    }

    if (hashIdx !== -1) {
      const urlRegex = spec.slice(0, hashIdx);
      const offset = Number(spec.slice(hashIdx + 1));
      if (Number.isNaN(offset)) {
        this.#log("registerSpec", `ignoring non-numeric offset: ${spec}`);
        return;
      }
      try {
        const regex = new RegExp(urlRegex);
        this.#breakpointUrlRegexes.push(regex);
        this.#offsetBreakpoints.push({
          spec,
          label: `bp:${spec}`,
          regex,
          offset,
        });
        this.#log(
          "registerSpec",
          `deferred ${spec} until matching script parses`,
        );
      } catch (err) {
        this.#log(
          "registerSpec",
          `invalid url regex in ${spec}: ${String(err)}`,
        );
      }
      return;
    }

    this.#log("registerSpec", `ignoring malformed spec: ${spec}`);
  }

  // For each parsed script, place any pending "#offset" breakpoints whose url
  // matches, converting the offset to a (line, column) against the real source.
  async #armOffsetsForScript(
    event: Protocol.Debugger.ScriptParsedEvent,
  ): Promise<void> {
    const client = this.#client;
    if (!client || this.#offsetBreakpoints.length === 0) {
      return;
    }
    for (const ob of this.#offsetBreakpoints) {
      if (!ob.regex.test(event.url)) {
        continue;
      }
      const key = `${ob.spec}@${event.scriptId}`;
      if (this.#armedOffsetKeys.has(key)) {
        continue;
      }
      this.#armedOffsetKeys.add(key);
      try {
        const src = (await client.send("Debugger.getScriptSource", {
          scriptId: event.scriptId,
        })) as Protocol.Debugger.GetScriptSourceResponse;
        // Script-identity guard. Without PageGraph there is no `response hash`
        // to lean on, so the probe hashes the bytes the renderer actually
        // parsed and compares them to what pass 1 saw. A mismatch is recorded
        // and the target left unarmed: a stated gap is worth more than a
        // capture from the wrong code.
        const actual = createHash("sha256")
          .update(src.scriptSource)
          .digest("hex");
        if (ob.expectedSha256 !== undefined) {
          if (actual !== ob.expectedSha256) {
            this.#skippedTargets.push({
              skipped: "script changed since pass 1 — offset not armed",
              spec: ob.spec,
              label: ob.label,
              url: event.url,
              expectedSha256: ob.expectedSha256,
              actualSha256: actual,
            });
            this.#log(
              "armOffsetsForScript",
              `SKIPPED ${ob.spec}: ${event.url} hash ${actual.slice(0, 12)} != ` +
                `pass-1 ${ob.expectedSha256.slice(0, 12)}`,
            );
            continue;
          }
        }
        if (ob.requirePrecedingSource !== undefined) {
          const preceding = src.scriptSource.slice(0, ob.offset).trimEnd();
          if (!preceding.endsWith(ob.requirePrecedingSource)) {
            // Not an error: on a document with several inline scripts this
            // fires for each one that is not the target, which is the point.
            // Only recorded if NO script ends up matching (see below).
            this.#inlineMisses.push({
              skipped:
                `inline script did not match the target's context (expected ` +
                `the source before offset ${String(ob.offset)} to end with ` +
                `"${ob.requirePrecedingSource}", found "${preceding.slice(-40)}")`,
              spec: ob.spec,
              label: ob.label,
              url: event.url,
            });
            this.#armedOffsetKeys.delete(key);
            continue;
          }
        }
        const inSource = offsetToLineCol(src.scriptSource, ob.offset);
        // Translate source coordinates into the document coordinates CDP wants.
        // The column shifts only on the script's first line, where the source
        // and the document share a line.
        const start = this.#scriptStarts.get(event.scriptId) ?? {
          line: 0,
          column: 0,
        };
        const lineNumber = start.line + inSource.lineNumber;
        const columnNumber =
          inSource.lineNumber === 0
            ? start.column + inSource.columnNumber
            : inSource.columnNumber;
        const bp = (await client.send("Debugger.setBreakpoint", {
          location: { scriptId: event.scriptId, lineNumber, columnNumber },
        })) as Protocol.Debugger.SetBreakpointResponse;
        this.#breakpointLabels.set(bp.breakpointId, ob.label);
        // Record what was armed and against which bytes. The hash is emitted
        // even when it was not enforced, so a target whose pass-1 hash came
        // from a non-authoritative source (a response body rather than the
        // parsed source) can still be reconciled after the fact instead of
        // being either trusted blindly or skipped needlessly.
        this.#armedTargets.push({
          spec: ob.spec,
          label: ob.label,
          url: event.url,
          line: lineNumber,
          col: columnNumber,
          observedSha256: actual,
          expectedSha256: ob.expectedSha256,
          pass1ResponseSha256: ob.pass1ResponseSha256,
          hashMatchesPass1Response:
            ob.pass1ResponseSha256 === undefined
              ? undefined
              : ob.pass1ResponseSha256 === actual,
        });
        this.#log(
          "armOffsetsForScript",
          `armed ${ob.spec} at ${event.url} ${String(lineNumber)}:${String(columnNumber)} ` +
            `(actual ${String(bp.actualLocation.lineNumber)}:${String(bp.actualLocation.columnNumber ?? 0)})`,
        );
      } catch (err) {
        this.#log("armOffsetsForScript", `failed ${ob.spec}: ${String(err)}`);
      }
    }
  }

  // Write the loaded source of a script whose URL matches any breakpoint regex,
  // once per URL, into saveScriptsDir. The saved bytes are authoritative for
  // computing line:col — a separate fetch of the same URL can differ.
  async #maybeSaveScript(
    event: Protocol.Debugger.ScriptParsedEvent,
  ): Promise<void> {
    const client = this.#client;
    const dir = this.#opts.saveScriptsDir;
    if (!client || dir === undefined || event.url === "") {
      return;
    }
    if (!this.#breakpointUrlRegexes.some((re) => re.test(event.url))) {
      return;
    }
    if (this.#savedScriptUrls.has(event.url)) {
      return;
    }
    this.#savedScriptUrls.add(event.url);
    try {
      const src = (await client.send("Debugger.getScriptSource", {
        scriptId: event.scriptId,
      })) as Protocol.Debugger.GetScriptSourceResponse;
      const safe = event.url.replace(/[^A-Za-z0-9._-]/g, "_").slice(-150);
      const outPath = join(dir, `script_${safe}.loaded.js`);
      writeFileSync(outPath, src.scriptSource);
      this.#log(
        "maybeSaveScript",
        `wrote loaded source of ${event.url} -> ${outPath}`,
      );
    } catch (err) {
      this.#savedScriptUrls.delete(event.url);
      this.#log("maybeSaveScript", `failed ${event.url}: ${String(err)}`);
    }
  }

  async #onPaused(event: Protocol.Debugger.PausedEvent): Promise<void> {
    const client = this.#client;
    if (!client) {
      return;
    }
    try {
      // An instrumentation pause is not a capture: it is the renderer holding
      // still, just before a script runs, so the offset breakpoints for that
      // script can be placed. Without it there is a race — Debugger.scriptParsed
      // fires but does not block, so a script that writes its cookie at load
      // finishes before the async setBreakpoint round-trip lands, and the probe
      // reports a clean run with no captures. Arm here, then resume.
      if (event.reason === "instrumentation") {
        const scriptId = (event.data as { scriptId?: string } | undefined)
          ?.scriptId;
        if (scriptId !== undefined) {
          const url = this.#scriptUrls.get(scriptId) ?? "";
          await this.#armOffsetsForScript({
            scriptId,
            url,
          } as Protocol.Debugger.ScriptParsedEvent);
        }
        return;
      }
      // Once at the cap, deactivate ALL breakpoints so we stop pausing — a hot
      // offset would otherwise pause+resume thousands of times and stall the
      // crawl. We still resume this pause below.
      if (this.#records.length >= this.#opts.maxCaptures) {
        if (!this.#capping) {
          this.#capping = true;
          this.#log(
            "onPaused",
            `reached max captures (${String(this.#opts.maxCaptures)}); deactivating breakpoints`,
          );
          try {
            await client.send("Debugger.setBreakpointsActive", {
              active: false,
            });
          } catch {
            // best effort
          }
        }
        return;
      }
      const frames = await this.#captureFrames(event.callFrames);
      this.#records.push({
        target: this.#labelForPause(event),
        seq: this.#seq++,
        ts: Date.now() / 1000,
        frames,
      });
    } catch (err) {
      this.#log("onPaused", String(err));
    } finally {
      try {
        await client.send("Debugger.resume");
      } catch {
        // Page/target may already be gone; nothing to resume.
      }
    }
  }

  #labelForPause(event: Protocol.Debugger.PausedEvent): string {
    const hit = event.hitBreakpoints?.[0];
    if (hit !== undefined) {
      const label = this.#breakpointLabels.get(hit);
      if (label !== undefined) {
        return label;
      }
    }
    return event.reason;
  }

  async #captureFrames(
    callFrames: Protocol.Debugger.CallFrame[],
  ): Promise<CapturedFrame[]> {
    const out: CapturedFrame[] = [];
    const limit = Math.min(callFrames.length, MAX_FRAMES);
    // Nested frames share parent closure scope objects; read each unique scope
    // object only once per capture to avoid multiplying a huge closure N times.
    const seenScopeIds = new Set<string>();
    // One object-read budget shared across all frames/scopes of this capture.
    const budget = { n: CAPTURE_NODE_BUDGET };
    for (let i = 0; i < limit; i++) {
      const frame = callFrames[i];
      const url =
        frame.url || this.#scriptUrls.get(frame.location.scriptId) || "";
      const scopes: CapturedScope[] = [];
      for (const scope of frame.scopeChain) {
        if (SKIP_SCOPE_TYPES.has(scope.type)) {
          continue;
        }
        const objectId = scope.object.objectId;
        if (objectId === undefined) {
          continue;
        }
        if (seenScopeIds.has(objectId)) {
          scopes.push({ type: scope.type, variables: [], shared: true });
          continue;
        }
        seenScopeIds.add(objectId);
        const { variables, truncated } = await this.#readScope(
          objectId,
          budget,
        );
        scopes.push({ type: scope.type, variables, truncated });
      }
      out.push({
        functionName: frame.functionName || "(anonymous)",
        url,
        lineNumber: frame.location.lineNumber,
        columnNumber: frame.location.columnNumber ?? 0,
        scopes,
      });
    }
    return out;
  }

  async #readScope(
    objectId: string,
    budget: { n: number },
  ): Promise<{ variables: CapturedVariable[]; truncated: boolean }> {
    const client = this.#client;
    if (!client) {
      return { variables: [], truncated: false };
    }
    try {
      // No generatePreview: we never read previews (#describe uses value/
      // description), and forcing preview generation on framework/DOM objects
      // is extra work that can trip CHECKs on the instrumented build.
      const res = (await client.send("Runtime.getProperties", {
        objectId,
        ownProperties: true,
      })) as Protocol.Runtime.GetPropertiesResponse;
      const vars: CapturedVariable[] = [];
      let truncated = false;
      for (const prop of res.result) {
        const remote = prop.value;
        if (remote === undefined) {
          continue;
        }
        if (vars.length >= MAX_VARS_PER_SCOPE) {
          truncated = true;
          break;
        }
        // Live objects/arrays only have a "description" ("Object"/"Array(n)"),
        // so expand them (bounded by the shared budget) to capture the actual
        // contents — this is what exposes the plaintext payload/sensor objects.
        // Functions keep their source (via #describe); primitives by value.
        const value =
          remote.type === "object" &&
          remote.subtype !== "null" &&
          remote.objectId !== undefined &&
          budget.n > 0
            ? await this.#expandObject(remote.objectId, budget)
            : this.#describe(remote);
        vars.push({ name: prop.name, value });
      }
      return { variables: vars, truncated };
    } catch (err) {
      this.#log("readScope", String(err));
      return { variables: [], truncated: false };
    }
  }

  // Reconstruct an object/array's contents WITHOUT executing any page JS:
  // recursive Runtime.getProperties reads property descriptors only (it never
  // invokes getters/toJSON), so it is safe to run while paused at a breakpoint
  // on a PageGraph build. (callFunctionOn / in-page JSON.stringify aborts the
  // renderer there.) The plain tree is then stringified in Node.
  async #expandObject(
    objectId: string,
    budget: { n: number },
  ): Promise<string> {
    const value = await this.#readObjectValue(objectId, 0, budget);
    let str: string;
    try {
      str = JSON.stringify(value);
    } catch {
      str = "[unserializable]";
    }
    if (str.length > this.#opts.maxValue) {
      str = str.slice(0, this.#opts.maxValue) + "…[truncated]";
    }
    return str;
  }

  async #readObjectValue(
    objectId: string,
    depth: number,
    budget: { n: number },
  ): Promise<unknown> {
    const client = this.#client;
    if (!client) {
      return "[object]";
    }
    try {
      const res = (await client.send("Runtime.getProperties", {
        objectId,
        ownProperties: true,
      })) as Protocol.Runtime.GetPropertiesResponse;
      const out: Record<string, unknown> = {};
      let count = 0;
      for (const prop of res.result) {
        const rv = prop.value;
        // Skip accessor-only properties: reading them would invoke getters.
        if (rv === undefined) {
          continue;
        }
        if (count >= MAX_OBJ_PROPS || budget.n <= 0) {
          out["…"] = "[truncated]";
          break;
        }
        count++;
        if (
          rv.type === "object" &&
          rv.subtype !== "null" &&
          rv.objectId !== undefined &&
          depth < MAX_OBJ_DEPTH
        ) {
          budget.n--;
          out[prop.name] = await this.#readObjectValue(
            rv.objectId,
            depth + 1,
            budget,
          );
        } else {
          out[prop.name] = this.#leafValue(rv);
        }
      }
      return out;
    } catch (err) {
      this.#log("readObjectValue", String(err));
      return "[object]";
    }
  }

  #leafValue(rv: Protocol.Runtime.RemoteObject): unknown {
    if (rv.unserializableValue !== undefined) {
      return rv.unserializableValue;
    }
    if (rv.type === "function") {
      const d = rv.description ?? "function";
      return "ƒ " + (d.length > 160 ? d.slice(0, 160) + "…" : d);
    }
    if (rv.value !== undefined) {
      return rv.value;
    }
    return rv.description ?? rv.type;
  }

  #describe(obj: Protocol.Runtime.RemoteObject): string {
    let str: string;
    if (obj.unserializableValue !== undefined) {
      str = obj.unserializableValue;
    } else if (obj.value !== undefined) {
      str =
        typeof obj.value === "string" ? obj.value : JSON.stringify(obj.value);
    } else {
      str = obj.description ?? obj.type;
    }
    if (str.length > this.#opts.maxValue) {
      str = str.slice(0, this.#opts.maxValue) + "…[truncated]";
    }
    return str;
  }
}
