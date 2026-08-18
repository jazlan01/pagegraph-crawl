---
name: cookie-lifecycle
description: Audit every first- and third-party cookie on a page end-to-end — lifecycle, provenance of each modification, usage, and tracking — using a two-pass model over the PageGraph crawler (graph-only pass 1, then a debugger value-capture pass 2 only for hand-rolled-crypto cookies, falling back to graph-only if pausing crashes the renderer). Use when the user wants a full cookie/tracking audit of a site against a custom (PageGraph) Brave build. Invoke as "/cookie-lifecycle <braveBinary> <url> [cookieName]".
argument-hint: <braveBinary> <url> [cookieName]
---

# cookie-lifecycle

Run a full first- and third-party cookie audit of a page by delegating to the
**`cookie-lifecycle-analyst`** subagent, which drives the crawler
(`/Users/jazlan/Desktop/pagegraph-crawl`) and its analysis tools in two passes.

This is distinct from `/cookie-dossier` (which deep-dives a single named cookie). This skill audits
**all** cookies: pass 1 is a clean graph-only crawl for enumeration/profiling, and pass 2 attaches the
debugger (`--debug-stacks`) only for the few flagged hand-rolled-crypto cookies, falling back to a
graph-only dossier for any cookie whose write site crashes the renderer when paused.

## Parse the arguments

From the invocation `arguments`, extract in order:
1. `braveBinary` — path to the PageGraph-enabled Brave binary (required).
2. `url` — the page to audit, e.g. `https://www.walmart.com/` (required).
3. `cookieName` — optional. If given, focus the audit on this one cookie; otherwise audit every
   cookie on the page.

If `braveBinary` or `url` is missing, ask the user for it and stop — do not guess a binary path or URL.

## Delegate to the subagent

Launch the **`cookie-lifecycle-analyst`** agent (Agent tool, `subagent_type:
"cookie-lifecycle-analyst"`) with a task prompt including the parsed values, e.g.:

> Audit the cookies on **`<url>`** using the PageGraph binary at **`<braveBinary>`**
> (`<focus on cookie `<cookieName>` | audit every first- and third-party cookie>`). Crawl with consent
> auto-granted (`--extensions-path ~/Consent-O-Matic/build`, `-t 30`) and obey the Robustness &
> completeness rules below (consent-wall sanity check, code-10 retry, mkdir the `-o` dir, never
> `readFileSync` the graph). Follow your full two-pass procedure: pass 1 = graph-only crawl with
> `--save-cookies` (NO debugger) → enumerate &
> classify 1P/3P from the cookie-store dump → profile each cookie's lifecycle, reads/consumers
> (`cookie-reads.mjs`), consumer→network data-flow (`cookie-flow.mjs`: did a JS consumer actually fire a
> `fetch`/XHR/`sendBeacon` with the value, and to which 1P/3P host — report `firedNetworkRequest` +
> `destUrl`), per-modification provenance (`cookie-writes.mjs` + `edge-stacks-stream.mjs`), usage and
> tracking (behavior from the graph, never from the cookie's name) → triage opaque hand-rolled-crypto
> cookies. Pass 2 (only for flagged cookies) = a second `--debug-stacks --debug-breakpoint` crawl on
> the instrumented build at the located write sites to recover pre-encryption plaintext, condensed with
> `stacks-query.mjs`; if pausing crashes the renderer, fall back to that cookie's graph-only dossier.
> Obey the hard safety rules: pass 1 never attaches the debugger; never `--debug-native`;
> `--debug-max-captures ≤ 12`; never Read a raw stacks.json. Write per-cookie `<cookie>.dossier.json` +
> `.md` and a `_site-summary.md` into the run dir, and report the summary.

## Robustness & completeness (pass these to the subagent)

These are hard-won requirements; a crawl that skips them silently produces an incomplete or empty audit.

- **Consent wall → load Consent-O-Matic.** Major prod sites gate their tracker cookies behind a consent
  banner; crawling without consent captures only a handful of essential cookies (e.g. one Gigya
  `gig_canary`) and misses the entire adtech layer. Always crawl with consent auto-granted:
  `--extensions-path ~/Consent-O-Matic/build` (a pre-built, accept-all + no-popup MV3 unpacked
  extension; `crawl.ts` wires it via `--disable-extensions-except`/`--load-extension`). Use `-t 30`+ so
  the extension can detect and click accept before cookies fire. **Sanity check the result:** if a major
  site yields only 1–2 cookies after a 30s dwell, treat it as a consent-wall miss, not a real inventory.
- **"status code 10" / `TargetCloseError` during `generatePageGraph` is the KNOWN flaky renderer crash**
  on heavy sites in the dcheck-off debug build (renderer dies during dwell/graph-gen, flat RSS, no
  graphml — cookie sidecars still survive because they're dumped first). It is NOT a harness bug.
  **Just re-run** — it usually succeeds within 1–2 retries; keep `-t 30` so consent still fires. Only if
  it crashes repeatedly, drop the dwell (`-t 15` → `-t 8`) as a last resort (accepting fewer
  post-consent cookies). Do NOT keep re-issuing the identical failing command more than ~2× without
  changing something. Distinguish hang vs working: watch whether the intermediate
  `<outdir>/pagegraph_*.graphml` appears and grows (working) vs stays absent with flat RSS (crashed).
- **`mkdir -p` the `-o` output dir before crawling** — a missing/streamed dir yields a 0-byte graphml
  with exit 0 (false success). See the output-dir gotcha in CLAUDE.md.
- **Never `readFileSync` / Read a multi-GB graphml or stacks.json into context** (it stalls the agent
  and blows Node's ~512 MB string cap). Use the analysis `.mjs` scripts and the streaming
  `analysis/edge-stacks-stream.mjs` variant for large graphs.

## After it returns

Relay the subagent's summary (cookie count, 1P/3P split, how many needed pass 2) and the run-dir path.
Offer to open the `_site-summary.md` or drill into a specific cookie's dossier.

Notes:
- Needs `built/` present; the subagent runs `npm run build` (fast tsc) itself if needed.
- Both passes use the same PageGraph-enabled build; pass 2 just adds `--debug-stacks` + a breakpoint,
  so no second browser is required.
- Pass 1 is richer when the binary includes the per-edge `stack trace` engine change, but degrades
  gracefully to `cookie-writes.mjs` offset specs without it.
