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
const SKIP_SCOPE_TYPES = new Set(["global", "with", "module", "script"]);

// Cookie-write boundaries (always armed when --debug-stacks is set).
const COOKIE_TARGETS: NativeTarget[] = [
  {
    label: "document.cookie",
    expression: "Object.getOwnPropertyDescriptor(Document.prototype,'cookie').set",
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
        // Offset breakpoints can only be placed once we can read the source to
        // convert offset -> (line, column), which is when the script parses.
        void this.#armOffsetsForScript(event);
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

    if (!this.#opts.native && this.#opts.breakpoints.length === 0) {
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
        this.#offsetBreakpoints.push({
          spec,
          label: `bp:${spec}`,
          regex: new RegExp(urlRegex),
          offset,
        });
        this.#log("registerSpec", `deferred ${spec} until matching script parses`);
      } catch (err) {
        this.#log("registerSpec", `invalid url regex in ${spec}: ${String(err)}`);
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
        const { lineNumber, columnNumber } = offsetToLineCol(
          src.scriptSource,
          ob.offset,
        );
        const bp = (await client.send("Debugger.setBreakpoint", {
          location: { scriptId: event.scriptId, lineNumber, columnNumber },
        })) as Protocol.Debugger.SetBreakpointResponse;
        this.#breakpointLabels.set(bp.breakpointId, ob.label);
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

  async #onPaused(event: Protocol.Debugger.PausedEvent): Promise<void> {
    const client = this.#client;
    if (!client) {
      return;
    }
    try {
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
            await client.send("Debugger.setBreakpointsActive", { active: false });
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
        const { variables, truncated } = await this.#readScope(objectId, budget);
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
        typeof obj.value === "string"
          ? obj.value
          : JSON.stringify(obj.value);
    } else {
      str = obj.description ?? obj.type;
    }
    if (str.length > this.#opts.maxValue) {
      str = str.slice(0, this.#opts.maxValue) + "…[truncated]";
    }
    return str;
  }
}
