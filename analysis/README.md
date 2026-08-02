# analysis/ — cookie deep-dive tooling

Deterministic helpers that turn the crawler's PageGraph output into inputs for an iterative,
debugger-driven cookie audit. They are the "tools" the **`cookie-analyst`** subagent drives (see
`.claude/agents/cookie-analyst.md`, invoked via the `/cookie-dossier` skill).

Plain Node ESM — no build step. Run from the repo root.

> **Never infer what a cookie does from its name.** Names are unreliable/misleading — derive behavior
> only from the graph: read (`.get`) sites, the consumers of the read value (`cookie-reads.mjs`), the
> values written/read, and the flows. The name is an identifier, not evidence of purpose.

## `cookie-reads.mjs`

```
node analysis/cookie-reads.mjs <graphml>                # index: all cookies, compact
node analysis/cookie-reads.mjs <graphml> <cookieName>   # one cookie, full detail
node analysis/cookie-reads.mjs <graphml> --split <dir>  # one detail file per cookie + index
```

For every cookie, extracts **where it was read** (`.get` — `document.cookie` / `cookieStore.get`) and
**what consumed the read value** — any `js call` sink whose args contained the value, which may be a
network request (`fetch`/`XMLHttpRequest.open|send`/`sendBeacon`/…, flagged `isNetworkSink` with a
`destUrl`) **or** an ordinary consumer function (`JsonParse`, `btoa`, …). Built entirely from the
PageGraph instrumentation (`storage read result` values, `read storage call` sites, `js call` args);
no CDP re-derivation. Streams the graphml, so it works on multi-GB graphs where `readFileSync` would
throw.

Output is **grouped by cookie** so a driver reads one deterministic dump instead of many tool calls.
The index carries a `detailBytes` size hint per cookie; when the dump is large, use `--split <dir>`
(writes `<cookie>.json` per cookie + prints the size-sorted index) and read small cookies in batches,
large ones individually, to protect the context window. Encoded/transformed values (e.g. PerimeterX
`_px3`) may not value-match a consumer — the read site + reader script is still the evidence; don't
conclude "no flow".

## `cookie-sites.mjs`

```
node analysis/cookie-sites.mjs <graphml> <cookieName>
```

Parses a `page_graph_*.graphml` and reports where a cookie is **set / deleted / read**, resolving
each acting script to its source URL. Emits ready `--debug-breakpoint` specs (`<escapedUrl>#<offset>`)
for the write sites — the byte offset is the `script position` PageGraph records on `storage set`
edges. Inline-script sites are flagged (no offset spec; their offsets are document-relative).

Output JSON: `{ cookie, pageUrl, writes[], deletes[], reads{sites, readersReturningCookie}, writeSpecs[] }`.

## `cookie-exfiltration.mjs`

```
node analysis/cookie-exfiltration.mjs <graphml> <bodies.ndjson[.gz]> \
     [--cookie <name>] [--min-len N] [--include-responses] [--json]
```

Answers the one question the graph structurally cannot: **did a cookie's value leave in an HTTP
request body?** PageGraph records a request's size but never its content, so a POST to a collector is
indistinguishable from a bodyless ping — every other tool here can only prove a leak that surfaced in
a URL, a header, or a JS argument. This joins the graph's cookie values against the crawler's
`<base>.bodies.ndjson` sidecar (written by default; see `--no-save-bodies`), keyed by `request id`.

Matches raw substrings **and encoded forms** — urlencoded, base64, base64url, unpadded base64, and
JSON-escaped — because a tracker that base64s an identifier is still exfiltrating it. base64 bodies are
also decoded and searched, so a value inside a binary payload is still found. Each hit reports the
encoding, the sink URL and method, a snippet, and the initiating script (resolved from the
`request start` edge; note PageGraph leaves a script node's `url` empty even for external files, so
this falls back to a source excerpt).

Two behaviours worth knowing:

- **Cookie reads are whole-jar.** A `storage read result` edge hands back the entire `a=1; b=2` string
  with no per-cookie key, so the jar is split into pairs before matching. Searching the jar string
  itself would only find bodies that posted the whole jar, and would miss every request that sent a
  single identifier.
- **Outbound only by default.** A value in a *response* body is usually its origin (a script whose
  source hardcodes it), not a leak. `--include-responses` adds them, which is how you spot a partner
  echoing an identifier back.

If nothing is found, check the reported `dropped` count first: bodies skipped by the MIME filter or
the size budget mean the result is not proof of absence. Re-run the crawl with `--save-bodies-full`
and a larger `--bodies-budget-mb` to widen coverage.

## `cookie-headers.mjs`

```
node analysis/cookie-headers.mjs <graphml> [cookieName] [--json] [--min-len N]
```

Finds cookie values inside **request/response HEADERS and URLs** — a channel the other tools
structurally cannot see. `cookie-reads.mjs`/`cookie-flow.mjs` only match a value passed as a `js call`
**argument**, and `.cookie-network.json` only reports the automatic `Cookie:` header. Neither notices a
script copying the value into a **URL query string**, a `Referer`, or a custom header.

It reads the `headers` attribute (JSON `[{name,value}]`) the crawler's rewriter stitches onto request
edges. That blob includes HTTP/2 pseudo-headers, so `:path` yields the full path+query — which is how
URL-parameter leaks are detected. Hits are classified `cookie-header` (expected automatic carriage),
`url` (query string / Referer) or `other-header` (custom/auth); the latter two are reported as
**notable**. Structural pseudo-headers (`:authority`, `:scheme`, `:method`, `host`) are never scanned —
matching them yields false positives, since any cookie whose value embeds a domain would "match" every
request to that host.

**Collision guards** (each fixes a false-positive class that otherwise fabricates an Advertising label —
all are reported in the output's `excluded[]`, so "no hits" for an excluded cookie means *not measurable*,
not *no leak*):
- **`storage set` values contain cookie ATTRIBUTES.** PageGraph records the whole `document.cookie`
  assignment, so the value is `v; path=/; domain=.x.com`. Two unrelated cookies then share the
  `; path=/; domain=…` boilerplate and produce *identical* fake hit lists. Values are truncated at the
  first `;` (a cookie value cannot contain an unencoded one). **The same contamination affected the taint
  seeds in `cookie-reads.mjs` / `cookie-flow.mjs`; both are fixed too.**
- **hostname/URL-shaped values** (`_hjTLDTest` = `.example.org`, `_up_shop` = `shop.myshopify.com`) are
  structural config, not identifiers — high entropy, but they appear in `referer`/`:path` on every request.
- values overlapping the page's own host, and values under `--min-bits` (default 30) total entropy.
- `origin` is never scanned (always exactly `scheme://host`, no payload capacity).

Two matching subtleties that matter:
- values are matched **raw, URL-encoded and double-encoded** (scripts `encodeURIComponent` before appending);
- vendors transmit a **prefix-stripped fragment**, not the whole value — `_ga=GA1.1.47641089.1783130340`
  is sent as `cid=47641089.1783130340`. So separator-delimited **suffixes** are indexed too, requiring
  ≥2 remaining segments and ≥12 chars (which keeps the real identifier but rejects a bare trailing
  10-digit timestamp that would match every cache-buster URL). Each hit records
  `matchType: "full" | "fragment"`.

This is wired into `classify-cookies.mjs` (Stage 1), and its destinations are unioned into the feature
vector's third-party destination set. **It materially changes verdicts**: on themeisle the value of
`_gcl_au`/`FPAU` is copied into `?auid=…` sent to `ad.doubleclick.net` and `www.google.com` — so the
deterministic rules alone now reach **Advertising** with hard cross-domain evidence, where previously
every flow looked first-party (`crossSiteReach: 0`) and only vendor knowledge could have caught it.

## `cookie-writes.mjs`

```
node analysis/cookie-writes.mjs <graphml> [cookieName] [--json]
```

Streaming, **all-cookies** write/delete provenance — the streaming twin of `cookie-sites.mjs` (same
relationship as `edge-stacks.mjs` → `edge-stacks-stream.mjs`). Two reasons it exists:

1. `cookie-sites.mjs` uses `readFileSync`, so it cannot touch multi-GB graphs. On those, JS write
   provenance was simply unavailable and every cookie reported `setChannel: "unknown"`.
2. It reports every cookie in **one** pass. `cookie-sites.mjs` takes a single cookie name, so a driver had
   to invoke it once per cookie — N full parses of the same graph (66 for a directv-sized inventory).

Per cookie: each `storage set` / `delete storage` edge resolved to the writing script's source URL, plus
the `cookie source` channel (`js` / `cookie-store` / `set-cookie-header`). `classify-cookies.mjs` uses
this at any graph size; `cookie-sites.mjs` is retained for its `--debug-breakpoint` specs.

## `stacks-query.mjs`

```
node analysis/stacks-query.mjs <stacks.json> [--grep STR] [--frames N] [--record R] [--frame K] [--json]
```

Condenses a `--debug-stacks` sidecar (which can be multiple MB) so it can be reasoned about without
loading it whole:
- default: per record, the full call chain + the innermost `N` frames' local/block variables
  (truncated); large `closure`/`script` scopes are collapsed.
- `--grep STR`: locate which frame/variable holds a value (e.g. a cookie value fragment) across
  **all** frames — this is how you find where a value originates / gets transformed.
- `--frame K --record R`: deep-dump one frame's full scopes.
- transform hints: values matching `btoa/atob/encrypt/hmac/sha/digest/TextEncoder/…` are tagged
  `⟨xform⟩`. Defensive parse salvages valid records from a truncated file.

## `classify-cookies.mjs` — independent multi-label TCF classifier

```
node analysis/classify-cookies.mjs <graphml> [--rules-only] [--cookie <name>] \
    [--out <dir>] [--declared <file>] [--concurrency <n>] [--model <id>] [--dry-run] [--stdout]
```

Classifies **every cookie in a crawl** into three parallel **multi-label** axes — `iab_purposes`
(the 12 IAB TCF v2.2 purposes), `icc_uk_categories` (Necessary/Functional/Analytics/Advertising),
and `us_state_privacy_categories` — from **observed behavior only**, never the cookie name. Independent
of the VaultJS classification MCP. Each label is `{ label, probability, reasoning }`.

Pipeline (see `lib/`):
1. **Evidence fusion** (`lib/cookie-evidence.mjs`) — fuses `<base>.cookies.json` + `<base>.cookie-network.json`
   with `cookie-reads.mjs`/`cookie-flow.mjs` (`--split`) and, for graphs ≤~350 MB, `cookie-sites.mjs`,
   into one `CookieEvidence` record per cookie. Streaming scripts run as subprocesses, so it scales to
   multi-GB graphs (the readFileSync-based `cookie-sites` enrichment is size-gated off).
2. **Features** (`lib/cookie-features.mjs`) — behavior-only vector: party (eTLD+1), set channel,
   persistence/expiry, attribute flags, value entropy + identifier heuristic, JS reads, exfiltration
   destinations (HTTP `Cookie:` + JS sinks), cross-site reach.
3. **Deterministic rule prior** (`lib/tcf-rules.mjs`) — auditable feature→label mapping. Every label is
   backed by an observed-behavior `signal`. Conservative by design: it does **not** guess advertising
   vs. analytics once a value leaves to a third party (no vendor KB) — it emits the measurement floor +
   both candidates and sets `flags.needsHostKnowledge`.
4. **LLM head** (`lib/llm-head.mjs`) — refines the prior into the final verdict, resolving destination
   **hosts** to vendor purposes from world knowledge and writing the reasoning (grounded in the supplied
   evidence). Anthropic Messages API + forced tool-use for schema-valid output. Needs `ANTHROPIC_API_KEY`
   (override model via `CLASSIFIER_MODEL` or `--model`); without a key the tool runs `--rules-only`.

**Pluggable head (no API key needed).** The head is transport-agnostic — you can classify out-of-band
(an in-session agent, a different provider, a human reviewer) and feed the answers back:

```
# 1. run stages 1-3 and dump the evidence bundles (+ the head instructions)
node analysis/classify-cookies.mjs <graphml> --emit-payloads /tmp/payloads
# 2. classify /tmp/payloads/_payloads.json → a {cookieName: {axes…}} JSON map
# 3. ingest, validated against the taxonomy
node analysis/classify-cookies.mjs <graphml> --verdicts /tmp/verdicts.json --head-tag opus-5
```

Ingested verdicts pass through `lib/verdict-schema.mjs`: unknown labels, out-of-range probabilities and
missing reasoning are **rejected** (never silently accepted — a bad label would corrupt a compliance
verdict), short forms (`P7`, `SP1`, `Purpose 9`) are canonicalized, duplicates merged. A cookie with no
supplied verdict falls back to the rule prior; `source` records which head produced each verdict.

**Blinded evaluation** (`blind-payloads.mjs`) — strip every vendor/site-identifying signal while keeping
the graph-flow structure intact, to test whether flows *alone* are sufficient (and to let a third party
reproduce an audit without being told whose cookie it is):

```
node analysis/classify-cookies.mjs <graphml> --emit-payloads /tmp/p
node analysis/blind-payloads.mjs /tmp/p/_payloads.json --out /tmp/blinded.json --map /tmp/unblind.json
```

Cookie names → `sha256(name)[0..12)`; values → structural description only (segment classes/lengths,
total entropy bits — never raw bytes, since prefixes like `GA1.1.` leak the vendor); hosts → stable
pseudonyms preserving identity and party (`SITE_MAIN` / `SITE_SUB_n` / `EXT_n`); the deterministic prior
is dropped so it can't anchor the evaluator. `--map` writes the un-blinding map for scoring afterwards.

`--rules-only` emits the deterministic prior as the verdict (reproducible, no network — the CI/audit
path). `--dry-run` builds the LLM requests and writes them to `<out>/requests/` without sending (preview
token cost). `--declared <file>` (a `{cookieName: ["Necessary"|"Advertising"|…]}` map of vendor-declared
labels) adds a **divergence** verdict per cookie — `under-declared` flags cookies whose observed
tracking/advertising behavior exceeds the declared label (the litigation-exposure signal).

Output: `<base>.classification/<cookie>.json` per cookie (full verdict + evidence trail + rule prior +
divergence) and `_index.json` (run summary), plus a compact console table.

> **Behavioral honesty:** only Purpose 1 (device storage) is definitionally observable; a persistent
> high-entropy identifier that is read/transmitted is flagged Analytics even under first-party
> CNAME-cloaked (server-side) tagging; the finer ad/analytics/profiling splits depend on the LLM head +
> destination host. Probabilities + per-label reasoning make that uncertainty explicit.

## Pipeline (what the subagent does)

1. Baseline crawl → graphml.
2. `cookie-sites.mjs` → write/read sites + breakpoint specs.
3. Crawl with `--debug-stacks --debug-breakpoint <spec> --debug-max-value 16000 --debug-max-captures 12`
   → stacks.json.
4. `stacks-query.mjs --grep <value fragment>` → find the value's frame.
5. Iterate up the stack via `<url>@<line>:<col>` breakpoints (≤4 passes) until the value's origin /
   transform is identified.
6. Emit `<cookie>.dossier.json` + `<cookie>.md`.

Safety: the harness must **never** use `--debug-native` (native-builtin breakpoints SIGTRAP the
renderer); only JS offset / line:col breakpoints are safe. See the agent definition for the full rules.
