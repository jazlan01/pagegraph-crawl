# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A CLI tool that drives a PageGraph-enabled build of Brave (via puppeteer-core over the
DevTools/CDP protocol) to crawl a URL, then exports a `.graphml` file recording everything
the page did. PageGraph is a Brave feature that records page execution as a graph; this tool
orchestrates the browser, post-processes the output, and can optionally emit HAR files,
screenshots, and request-header logs.

`src/` is TypeScript compiled to `built/`. Tests are plain JavaScript run against the
compiled output in `built/`, not against `src/`.

## Commands

```bash
npm run build          # tsc -> built/ (REQUIRED before crawl or test; tests import from built/)
npm run lint           # eslint over src/
npm run lint:fix       # eslint --fix
npm run clean          # rm -Rf built/*
npm run test           # builds, then runs mocha test/test.js (60s timeout)
npm run crawl -- <args>  # run the CLI; see README for flags, or `npm run crawl -- -h`
```

Running a single test (after `npm run build`):
```bash
node ./node_modules/mocha/bin/mocha.js test/test.js --timeout 60000 --grep "cross-site"
```

Tests require a PageGraph-enabled Brave binary. The test harness reads it from the
`PAGEGRAPH_CRAWL_TEST_BINARY_PATH` env var (other overrides: `PAGEGRAPH_CRAWL_TEST_PORT`,
`PAGEGRAPH_CRAWL_TEST_BASE_URL`, `DEBUG`). The tests spin up a local `http-server` over
`test/pages/` and crawl those fixtures. CI (`.github/workflows/pr.yml`) installs
brave-browser-nightly and runs lint + test on every PR, also setting
`PAGEGRAPH_DISABLE_SETUID_SANDBOX=true`.

A `pre-push` git hook (`.githooks/pre-push`) runs `npm run build`.

## Architecture

Entry point `src/run.ts` defines all CLI flags (argparse), then hands raw args to
`validate()` and the validated `CrawlArgs` to `doCrawl()`. Everything else lives in
`src/brave/`.

**Validation boundary** — `validate.ts` is the single place that turns untrusted argparse
output (snake_case fields, strings) into a frozen `CrawlArgs` object (camelCase, typed). It
guesses the Brave binary location if `--binary` is omitted, creates the output dir, parses
the proxy/extra-args, and rejects conflicting profile flags. Downstream code trusts
`CrawlArgs`. Shared types (`CrawlArgs`, `Logger`, `PuppeteerConfig`, etc.) are declared
globally in `src/declarations.d.ts` — they are ambient, so no import is needed to use them.

**Crawl orchestration** — `crawl.ts` `doCrawl()` is the core loop. It:
1. Builds puppeteer launch options (`puppeteer.ts`) and sets up Xvfb on Linux/OpenBSD
   (skipped with `--interactive` or on unsupported platforms).
2. Launches Brave with retry/backoff (`launchWithRetry`), opens a page, attaches a CDP
   session.
3. Intercepts requests to detect **top-level navigation redirects**. When the page tries to
   navigate somewhere new, it stops loading, records the current PageGraph, and **recursively
   calls `doCrawl()` for the redirect target** — each hop in a redirect chain produces its
   own `.graphml` file. A `NavigationTracker` (`navigation_tracker.ts`) carries the URL
   history across recursive calls to detect redirect loops (broken unless `--crawl-duplicates`).
4. Waits for the dwell time (`-t`/`--secs`), then calls `Page.generatePageGraph` over CDP.
5. `--recursive-depth` is a separate recursion mechanism: after a crawl it picks a random
   child link (`page.ts`) and crawls that, decrementing depth.

**Request metadata stitching** — PageGraph's own graphml does not include HTTP headers or
body sizes. `RequestMetadataTracker` (`request_metadata_tracker.ts`) listens to puppeteer
`request`/`response` events and records headers + sizes keyed by request id. The tricky part
is `#simplifyRequestId`: puppeteer exposes three request-id formats (worker
`interception-job-N.0`, sub-resource `pid.reqid`, 32-char navigation ids) that must be
normalized to match the ids PageGraph writes into the graphml. After the crawl,
`rewriteGraphML()` streams the graphml through `PageGraphXMLRewriter` (`graphml_rewriter.ts`,
built on `xml-stream-editor`) and injects `headers`/`size` attributes onto request edges.

**Output** — `files.ts` owns all path/filename logic and writing. Output filenames are
`page_graph_<sanitized-url>_<timestamp>` with extensions appended (`.graphml`, `.har`,
`.headers.json`, `.png`); `--compress` gzips the graphml/headers. The graphml is first
written to a `.tmp` file, then the header-stitching rewrite produces the final file.

`writeGraphML` is **dual-mode** (`files.ts:~79`): on very large graphs the patched Brave build
streams the graphml straight to disk inside `PAGEGRAPH_OUT_DIR` (set by `puppeteer.ts:93` to
`resolve(args.outputPath)`) and `Page.generatePageGraph` returns that file's *path* instead of
inline XML — detected via `existsSync(data)`. **Consequence:** the `-o` output path must be an
existing directory, or the renderer can't create the streamed file and you get a 0-byte graphml
with exit 0 (false success). A healthy run logs `generatePageGraph { size: N }` where N is the
small returned path length (~80–90), not the graph size.

**Crash recovery (two classes)** — heavy sites can abort the renderer during graph generation.
`doCrawl` wraps `generatePageGraph`/`writeGraphML` in try/catch and, on failure, calls
`recoverPartialGraphML` (`files.ts`). Two crash classes, two recovery sources:
- *Serialization-time* (the graph is built; `ToGraphML` crashes mid-write): the streamed
  `pagegraph_*.graphml` on disk is a valid, truncatable prefix. `findOrphanGraphML` +
  `repairPartialGraphML` backward-scan it, drop any incomplete trailing `<node>`/`<edge>`, append the
  footer (never `readFileSync` a multi-GB file), then stitch headers → `*.partial.graphml`.
- *Recording-time* (renderer dies **before** `ToGraphML` runs, e.g. a JS-stack-overflow SIGBUS on
  pgatour-class React sites — no streamed file ever exists): opt-in **`--recording-event-log`** makes
  the renderer append every graph item to `pagegraph_eventlog_*.graphml.partial` as it records (tapped
  at `AddGraphItem` in the custom Brave build). `recoverPartialGraphML` falls back to `findEventLog` and
  reconstructs from it. Off by default (per-item disk writes during recording); enable for known-crashy
  pages. Recovered graphs are *partial* (node attrs mutated after creation may be missing; `pageUrl`
  can be empty). `cleanupEventLogs` deletes the redundant log after a healthy crawl.

**Cookie sidecars** — `--save-cookies` writes three crash-proof JSON sidecars *before* graph
generation (so they survive a graph-gen crash): `<name>.cookies.json` (full inventory via
`Network.getAllCookies`), `<name>.cookie-network.json` (per-cookie `{setBy, sentTo}` built by
`RequestMetadataTracker.toCookieNetworkJSON()` from the non-pausing `*ExtraInfo` CDP data), and
`<name>.redirects.json` (the per-hop chain of every request that redirected). These
are the network/HTTP channel of a cookie's life; the JS channel lives in the graphml edges.

**Request/response bodies** (`body_log.ts`) — PageGraph records a request's *size* but never its
content, so a value leaving the page in a POST body is invisible in the graph. The crawler already
pulled every body over CDP to measure that size and threw the bytes away; it now keeps them in
`<name>.bodies.ndjson`, **on by default** (`--no-save-bodies` to skip). NDJSON, not one JSON object:
bodies are large and must not accumulate in RAM, and each line is durable the moment it is written.
Records join to the graph by `requestId` — the same simplified id injected as the `request id` edge
attribute. Response bodies are limited to textual MIME types (`--save-bodies-full` to keep all);
request bodies are always kept. `--body-max` caps each body, `--bodies-budget-mb` caps the total;
every request/response emits a record even when its body was dropped, with `size` + `sha256` always
present, so "dropped" is never confused with "not observed". Known gap: `Network.getRequestPostData`
returns only UTF-8 text, so binary multipart uploads are unavailable (flagged as
`postDataUnavailable`).

**Redirect hops** — a redirect chain shares ONE request id, so storing response metadata per id
collapses the chain to its last hop: every intermediate `Set-Cookie` is lost and the survivors are
misattributed to the final URL. That is exactly the cookie-sync pattern (a tracker bouncing through
partners, each dropping an identifier), so `RequestMetadataTracker` keeps a hop array per request id
(`#hopsByRequest`), indexed by puppeteer's `redirectChain().length`. Two ordering facts, both verified
against `test/pages/redirect-subresource-chain.html` and easy to get wrong: raw CDP
`Network.requestWillBeSent` fires only **once** for an entire chain when request interception is on,
and `response.request()` on a redirect response returns the chain's *latest* request rather than the
one it answered — so responses and `*ExtraInfo` events are attributed positionally, to the most
recently started hop.

**Browser profiles** — `resources/shields-up-profile/` and `resources/shields-down-profile/`
are template Chromium user-data dirs. By default the chosen one is copied to a temp dir for
the crawl and deleted after; `--persist-user-data-dir` keeps it, `--existing-user-data-dir`
reuses one in place (mutually exclusive). `puppeteer.ts` also assembles the long list of
disabled Brave/Chrome features and the `--enable-features=PageGraph` flag that activates the
recording.

**Cookie auditing, debug harness & analysis** — beyond a plain crawl, the tool supports a
per-cookie lifecycle/provenance audit:
- **Debug harness** (`debug_stack_tracker.ts`): `--debug-stacks` attaches CDP `Debugger` to capture
  JS call stacks on cookie-write edges; `--debug-breakpoint`/`--debug-encoding` pause at write sites
  to recover pre-encryption values (pass 2 for hand-rolled-crypto cookies). Caps: `--debug-max-captures`,
  `--debug-max-value`. **Never `--debug-native`** — arming native breakpoints SIGTRAPs the renderer.
- **Probe mode (pass 2)** — `--probe` runs the debug harness on a **stock** Brave/Chromium: PageGraph
  is not enabled (`puppeteer.ts` gates the `--enable-features=PageGraph` push) and no graphml is
  produced, so the SIGTRAP/recording-crash hazards of a PageGraph build do not apply and pass 2 costs
  seconds. It exists to recover values a site transforms before any recorded boundary — pass 1's
  `script position` says exactly where, so pausing there reads the pre-image out of the call frame.
  Output is `<base>.probe.json` (distinct from a pass-1 `.stacks.json`) and carries its own caveat:
  **pass 2 is a separate page load**, so a value embedding time or randomness is *a* pre-transform
  value, not *the* one in the graph. Targets come from `--probe-targets <file>`
  (`analysis/plan-probe-targets.mjs`) or bare `--debug-breakpoint` specs.
  - **Offsets are armed from a `beforeScriptExecution` instrumentation pause, not from
    `Debugger.scriptParsed`.** scriptParsed does not hold execution, so a script that writes its
    cookie at load finishes before the async `setBreakpoint` round-trip lands — the probe then
    reports a clean run with zero captures. Arming from both races and the parsed path wins, so
    when the pause is active it owns arming (`#instrumentationPauseActive`).
  - **Inline `<script>` writes are targetable.** Every inline script in a document shares the
    document's URL, so a URL+offset spec is ambiguous — and an offset valid for one inline script
    is often in range for another, landing in unrelated code. Targets therefore carry
    `requirePrecedingSource: "document.cookie"`, checked at arm time against the parsed bytes, which
    identifies the intended script by content and needs nothing from pass 1. Two further facts,
    both verified against `test/pages/cookie-inline-write.html` (a decoy inline script writing a
    different cookie, so a mis-resolution lands somewhere visible): PageGraph's inline
    `script position` is relative to **the inline script's own source**, while CDP addresses inline
    breakpoints in **document coordinates** — so `scriptParsed`'s `startLine`/`startColumn` must be
    added or `setBreakpoint` answers "Could not resolve breakpoint".
  - **`script` and `module` scopes are captured** (only `global` and `with` are skipped). A
    top-level `const` in a classic inline script is a *script*-scope binding, so skipping that scope
    made every top-level inline write record a correct pause with an empty scope chain — a silent
    hole in pass 1 as much as in probe mode.
  - Three target lists, so an absent value always has a stated reason: `armedTargets` (with the
    SHA-256 actually armed against), `skippedTargets` (pass-1 hash mismatch — the offset would land
    in unrelated code), `neverParsedTargets` (**the script never loaded**; usually a content blocker
    in the pass-2 browser — stock Brave's shields, an extension, or a filtering DNS blocks precisely
    the tracker scripts a probe targets).
  - `expectedSha256` (from `--src`, a dump of the loaded source) is **enforced**;
    `pass1ResponseSha256` (from `.bodies.ndjson`) is advisory only — a response body and a parsed
    source can legitimately differ, so enforcing it would skip good targets.
  - **`analysis/plan-probe-targets.mjs`** derives the plan from a crawl dir, delegating decode and
    write-site resolution to the existing tools. It excludes **server-issued bot-defence tokens**
    behaviourally (no vendor names): a value echoed in an earlier response body was minted by the
    server, not computed by the page. Skips report **two independent axes** — `setChannel`
    (`js` / `set-cookie-header` / `not recorded`) and `valueEchoedByServer` — because they overlap:
    a first-match-wins single reason made "no JS write site" and "server-issued" look mutually
    exclusive when most header-set cookies are both. That check is **positive-evidence only** — bodies are
    truncated and textual-only and some XHR responses are never captured — so it never clears a
    cookie, every target carries `reviewBeforeProbing`, and the list is meant to be read first.
- **Consent crawling**: `--extensions-path <dir>` loads an unpacked extension (adds
  `--disable-extensions-except`/`--load-extension`). Used to load Consent-O-Matic (patched to accept-all)
  so the full post-consent tracker cookie set fires — see the `consent-o-matic-crawl` auto-memory.
- **Analysis** (`analysis/*.mjs`, run with Node 24): `cookie-reads.mjs` (per-cookie read sites + value
  consumers), `cookie-flow.mjs` (consumer→network taint over `js call`→`js result` edges: did a JS
  consumer actually `fetch`/XHR/`sendBeacon` the value, and where — `firedNetworkRequest` + `destUrl`;
  default `--rounds 1` for the reliable direct signal, short/non-unique values collide with page HTML at
  higher rounds), `cookie-sites.mjs` (JS write-site provenance), `edge-stacks.mjs`/`edge-stacks-stream.mjs`
  (cookie-edge stack traces; the `-stream` variant avoids `readFileSync`'s ~512 MB string cap on
  multi-GB graphs), `stacks-query.mjs`. **Never `readFileSync` a multi-GB graphml** — stream it.
- The `cookie-lifecycle` / `cookie-dossier` skills drive this end-to-end via the
  `cookie-lifecycle-analyst` / `cookie-analyst` subagents.

**Engine instrumentation added on top of upstream PageGraph** (all in `~/brave/src/brave`, covered by
the `engine instrumentation` tests, which fail against an older engine build):
- **`script position` on cookie READ edges** (`edge_storage_read_call.{h,cc}`, `RegisterStorageRead`).
  Writes already had the byte offset; reads did not, so call sites had to be recovered from stack
  traces — a workaround that fails when a frame's script has no recorded source. It was never a
  capability limit: the read hook called `GetCurrentActingNode(ctx)` while the write hook passed
  `&script_position`. Same V8 stack, same binding; the out-param doubles as the "include position"
  flag. Delete/clear still lack it.
- **`response hash` on `request complete`** (`edge_request_complete.{h,cc}`). The SHA-256 was already
  computed in `TrackedRequest` and passed to the edge, but never emitted — a declared attribute with
  no producer. Identifies a body without recording it, so it joins the body sidecar.
- **postMessage** (`chromium_src/.../bind_gen/interface.py`: `Window`, `MessagePort`, `Worker`,
  `ServiceWorker`, `DedicatedWorkerGlobalScope`, `BroadcastChannel`). Cross-frame identifier passing
  was invisible — `EdgeCrossDOM` is the frame-owner→document *structural* link with no attributes.
  Each send now produces a `js call` edge whose `args` holds the payload as **real JSON** (structured
  clones do not degrade to `[object Object]`), plus a `script position`. **Send side only**: PageGraph
  records no dispatch edge, and `AddGraphItem` drops cross-context edges, so cross-frame joins are
  made by matching the payload value.

Still open from the same review: shadow-root host edges (see the `pagegraph-shadow-dom-islands`
auto-memory — content is recorded but unreachable from the DOM root), per-hop redirect status on
`EdgeRequestRedirect`, request method, and response status/MIME via `DidReceiveResourceResponse`.

**Custom Brave build (out of this repo)** — the crawler needs a PageGraph-enabled Brave. The user's
build lives at `~/brave/src`; two local source patches matter (both documented in auto-memory):
`page_graph.cc` `ToGraphML` streams to `PAGEGRAPH_OUT_DIR` (the dual-mode above), and a `HandleScope`
fix in the `module_tree_linker.cc` chromium_src override (PageGraph's module hook called `V8Module()`
with no scope, SIGABRT-ing on ES-module sites at load). Rebuild: `autoninja -C out/Release_arm64 brave`.

## Conventions

- ESM throughout (`"type": "module"`). Intra-`src` imports use `.js` extensions even for
  `.ts` source files (TS ESM requirement) — e.g. `import { doCrawl } from "./brave/crawl.js"`.
- ESLint runs `strictTypeChecked` + `stylisticTypeChecked` + prettier. The `no-unsafe-*` and
  `no-explicit-any` rules are deliberately disabled because puppeteer-core, chrome-har,
  argparse, xml-stream, and xvfb are declared as untyped `any` modules in
  `declarations.d.ts`. Interaction with those libraries is inherently untyped.
- Logging goes through `getLogger(args)` returning one of three frozen loggers keyed by
  `--logging` (`none`/`info`/`verbose`); never `console.log` directly in `src/brave/`.
- `--logging verbose` also turns on browser stderr logging and `dumpio`.
