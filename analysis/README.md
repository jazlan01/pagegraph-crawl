# analysis/ — cookie deep-dive tooling

Deterministic helpers that turn the crawler's PageGraph output into inputs for an iterative,
debugger-driven cookie audit. They are the "tools" the **`cookie-analyst`** subagent drives (see
`.claude/agents/cookie-analyst.md`, invoked via the `/cookie-dossier` skill).

Plain Node ESM — no build step. Run from the repo root.

> **Never infer what a cookie does from its name.** Names are unreliable/misleading — derive behavior
> only from the graph: read (`.get`) sites, the consumers of the read value (`cookie-reads.mjs`), the
> values written/read, and the flows. The name is an identifier, not evidence of purpose.

## Everything in here, at a glance

37 scripts and 10 `lib/` modules. Grouped by the job, because the filenames alone do not say which
of several similar tools is the current one.

### The report pipeline — run in this order
Produces `report-data.json` + the client HTML. This is the chain behind `output/audit-2026-08-02/`.

| # | tool | what it adds |
|---|---|---|
| 1 | `extract-cookie-flows.mjs` | every stored item + each edge that touched it, with call stacks |
| 2 | `resolve-script-origins.mjs` | maps script nodes to URL, host, party, and the load chain |
| 3 | `describe-flows.mjs` | turns flows into behaviour (writer, readers, transforms, sends) |
| 4 | `label-from-flows.mjs` | **the report's ICC/TCF labels**, with evidence tiers |
| 5 | `cookie-exfiltration.mjs` | locates stored values inside captured request bodies |
| 6 | `stack-network.mjs` | response headers + request-body schemas per host |
| 7 | `detect-stack.mjs` | technology detection from executed source (`--net` merges headers) |
| 8 | `exposure-signals.mjs` | contents / identifier / association classification per recipient |
| 9 | `decode-cookie-values.mjs` | what each value *contains* (structural decoding, never decryption) |
| 10 | `add-decoded-to-report.mjs` | folds (9) into `report-data.json` + the HTML |
| 11 | `identify-items.mjs` | what each cookie *is* (name lookup, tagged; see “Two kinds of claim”) |
| 12 | `describe-items.mjs` | one plain-English sentence per item — run last |

⚠️ **`label-from-flows.mjs` reads only the JS channel.** It has no reference to
`.cookie-network.json`, so a cookie the browser attaches to outgoing requests — the normal shape of
a `Set-Cookie` ad cookie — reads to it as "never disclosed". That is a known correctness bug, not a
design choice: see `output/audit-2026-08-02/mcp-headtohead.md`.

### Graph readers (per-cookie evidence)

| tool | use | note |
|---|---|---|
| `cookie-reads.mjs` | read sites + the consumers of the read value | |
| `cookie-writes.mjs` | write/delete provenance, ALL cookies, one streaming pass | **use this** |
| `cookie-sites.mjs` | one cookie's write/delete/read sites | *superseded* by `cookie-writes.mjs`; `readFileSync`, so it cannot open multi-GB graphs. Still wired into the skills/agents — rewrite those before deleting |
| `cookie-flow.mjs` | taint propagation: did a consumer actually send the value, and where |
| `cookie-headers.mjs` | cookie values inside request/response headers and URLs |
| `cookie-exfiltration.mjs` | values located inside captured request bodies |
| `cookie-code-trace.mjs` | the actual source lines that touch a cookie |
| `edge-stacks-stream.mjs` | JS call stacks on graph edges | **use this** on large graphs |
| `edge-stacks.mjs` | same, `readFileSync` | *superseded* for multi-GB graphs |
| `stacks-query.mjs` | condense a `--debug-stacks` sidecar for an agent |

### Vendor / infrastructure attribution

| tool | question it answers |
|---|---|
| `build-host-roles.mjs` | compiles the committed Tracker Radar snapshot (`data/tracker-radar-roles.json`) |
| `detect-stack.mjs` | which products executed, from source signatures + `--net` headers |
| `detect-first-party-vendors.mjs` | first-party hostnames operated by a third party (**DNS/CNAME**) |
| `detect-cloaking.mjs` | scripts that **rewrite outbound requests** (patched `fetch`/XHR/beacon) — *a different question from the row above; the two are complementary, not duplicates* |
| `detect-frames.mjs` | did a tracking request come from the main document or an embedded iframe |
| `detect-ad-pathway.mjs` | did this page activate an advertising pathway at all |
| `detect-google-ads.mjs` | is the GA deployment sharing with Google advertising |

### Classification

| tool | note |
|---|---|
| `classify-cookies.mjs` | the independent behaviour-only classifier: rules prior + LLM head. **Not wired into the report** |
| `blind-payloads.mjs` | blinded evidence sets for independent evaluation |
| `merge-mcp-verdicts.mjs` → `mcp-headtohead.mjs` | the benchmark against the VaultJS cookie-classification MCP |
| `merge-mcp-identity.mjs` | folds MCP name-lookup prose into the identity cache (`identify-items.mjs` consumes it) |

### Crawl orchestration & graph maintenance

| tool | note |
|---|---|
| `run-consent-matrix.sh` | crawls every site under three consent states (`gpc-only`, `accept-all`, `reject-all`) and prunes as it goes |
| `plan-probe-targets.mjs` | turns a pass-1 crawl into a `--probe` pass-2 breakpoint plan |
| `prune-graph.py` | stream-prune a graphml (truncates stack traces to 25 frames; ~36–95% smaller). Verified lossless for `timestamp`, `request id`, `key`, `value`, `edge type`, `script position`. This is for making a graph tractable to **analyse** — do not reach for it before archiving, see [Archiving graphs](#archiving-graphs) |
| `archive-graph.sh` | losslessly compress graphs for storage, ~180×, nothing discarded. `--reclaim` deletes an original only after re-verifying its archive |
| `gephi-export.mjs` | pre-styled GEXF storage subgraph — *orphaned; nothing references it* |

### `lib/`

| module | role |
|---|---|
| `graph-source.mjs` | opens a graph plain **or archived** (`.zst`/`.gz`), decompressing in memory. `graphStream`, `readPageUrl` (async), `graphBase`, `graphExists`, `isGraphPath`. Never `existsSync` a `.graphml` path directly — use `graphExists` |
| `graphml-stream.mjs` | the streaming graphml reader — **never `readFileSync` a multi-GB graph** |
| `host-role.mjs` | `roleOf(host)` → `{owner, categories, roles, source}` from the Tracker Radar snapshot |
| `cookie-evidence.mjs` | Stage 1 evidence fusion; **reads the HTTP channel** (`.cookie-network.json`) |
| `cookie-features.mjs` | Stage 2 deterministic feature vector |
| `tcf-rules.mjs` | Stage 3 rule prior |
| `tcf-taxonomy.mjs` | the three label vocabularies + the confidence levels |
| `verdict-schema.mjs` | validates any head's verdict against the taxonomy |
| `llm-head.mjs` | the system prompt + evidence payload builder (single definition, shared by both heads) |
| `llm-head-chat.mjs` | the head client: OpenAI **and** Anthropic over one OpenAI-shaped API |
| `item-identity.mjs` | resolves what an item *is*, kept apart from what it did |

## Two kinds of claim, kept apart

Everything derived from the graph is a statement about **what was recorded**. Cookie *identity*
(“this is Akamai Bot Manager’s cookie”) is a statement about the **name**, matched against an
external corpus. They are never merged: identity lives in its own `ident` field with a `source` tag,
is rendered as “name lookup” rather than “observed”, and never feeds a label. `identify-items.mjs`
enforces this; the reasoning is in its header.

## Confidence is text, never a number

Labels carry one of `low-confidence`, `medium-confidence`, `high-confidence`, `fully-sure` —
enforced by the head's JSON schema. Nothing in this pipeline is calibrated, so a decimal would imply
a precision that does not exist and invite comparison of numbers that were never comparable. The
deterministic rules still carry numeric weights internally; they are mapped once, in
`toConfidence()`, so no rule changed meaning during the switch.

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
4. **LLM head** — refines the prior into the final verdict, resolving destination **hosts** to vendor
   purposes from world knowledge and writing the reasoning (grounded in the supplied evidence). Two
   interchangeable providers, selected with `--provider` (or `CLASSIFIER_PROVIDER`); both import the
   same system prompt and the same evidence builder from `lib/llm-head.mjs`, so switching provider
   changes the model and nothing else:

   | provider | file | transport | schema enforcement |
   |---|---|---|---|
   | `anthropic` (default) | `lib/llm-head.mjs` | Messages API | forced tool-use |
   | `openai` | `lib/llm-head-openai.mjs` | Responses API | strict `json_schema` |

   The OpenAI head defaults to **`gpt-5.6-luna` on the `flex` service tier** — materially cheaper,
   higher latency, and it can return 429 while waiting for capacity (one patient retry is built in).
   Override with `CLASSIFIER_MODEL` / `--model` and `CLASSIFIER_SERVICE_TIER`. The verdict's `source`
   records both, e.g. `llm:gpt-5.6-luna/flex`, so a run is never ambiguous about what produced it.

   Keys are read from the environment: `ANTHROPIC_API_KEY`, or `OPENAI_API_KEY` / `OPENAI_KEY`.
   Nothing loads `.env` automatically — use `node --env-file=.env …` (Node ≥ 20.6) or
   `set -a; source .env; set +a`.

   **Without a key the tool silently runs the deterministic prior.** That fallback is logged
   (`mode: rules-only — no API key found…`) precisely because the output otherwise looks like a
   finished classification; `source` will read `rules`, not `llm:…`. Check it before believing a run.

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

## Consent-state crawling

A finding of the form "the site ignored the visitor's choice" is only interpretable against a
**known** consent state, and only meaningful next to the other states. `run-consent-matrix.sh`
crawls three:

```
analysis/run-consent-matrix.sh output/consent-matrix-<date> [site ...]
```

| state | what it is | what it is for |
|---|---|---|
| `gpc-only` | no extension; Brave still asserts Global Privacy Control | the browser's own signal, no banner interaction — the CCPA/CPRA case |
| `accept-all` | Consent-O-Matic clicking accept (`~/Consent-O-Matic/build`) | upper bound on what the site loads |
| `reject-all` | Consent-O-Matic clicking reject (`~/Consent-O-Matic-reject/build`, upstream's own defaults) | the comparison case |

Each run stamps its own state into `.crawl-status.json` (`consentConfig`), so a directory of graphs
stays self-describing. **Verify before comparing:** a reject run whose consent cookie still shows
targeting granted means the click failed — that run is not a reject state.

> The 2026-08-02 client audit was crawled **accept-all**, and nothing recorded that at the time.
> Any "opt-out was ignored" reading of that data is unsupported; that is what this matrix exists to
> settle.

## The MCP benchmark

`§6` of `pagegraph-vs-cookie-mcp-eval.md` asks for a head-to-head against the VaultJS
cookie-classification MCP. The chain:

```
# 1. call classify_cookies out-of-band (the MCP is reachable from an agent session, not a shell)
# 2. fold the raw batch responses into the two disjoint caches
node analysis/merge-mcp-verdicts.mjs <poll-result>...   # labels  → data/cookie-verdicts-mcp.json
node analysis/merge-mcp-identity.mjs <poll-result>...   # prose   → data/cookie-identity-mcp.json
# 3. run the benchmark
node analysis/mcp-headtohead.mjs output/audit-2026-08-02 --out .../mcp-headtohead.json
```

The two merges are deliberately separate: identity prose must never acquire a label's authority,
and a label must never inherit the name-lookup caveat. Results and method limits (agreement, not
accuracy; `customer_id 0` is a floor on the MCP) are in `output/audit-2026-08-02/mcp-headtohead.md`.

## Archiving graphs

```bash
analysis/archive-graph.sh output analysis/runs     # compress; originals kept
analysis/archive-graph.sh --reclaim output         # delete originals that re-verify
```

Writes `<graph>.graphml.zst` plus a `<graph>.graphml.archive.json` manifest recording exact byte
counts, the source SHA-256, and the restore command.

### The analysis scripts read archives directly — do not decompress first

Every script here takes the **plain `.graphml` path** whether or not the plaintext file still
exists. `lib/graph-source.mjs` resolves it to whatever is on disk and decompresses **in memory**:

```bash
node analysis/cookie-reads.mjs output/.../page_graph_foo.graphml --json   # foo.graphml.zst on disk
```

Nothing is written to a temp file — a 4 MB archive expands to 6.6 GB, so materialising it would
undo the archiving. The decoder is composed onto the existing streaming parsers, so a whole graph
never sits in memory. Delta (7,075,801,690 B, a 4.2 MB archive) streams end-to-end in **29 s**.

Two costs to know:

- **Peak RSS is ~2.5 GB on the largest graphs.** That is the zstd decoder allocating the 2 GB
  window the `--long=31` archives declare, not the graph being buffered.
- **`nvm use` first.** Reading `.zst` needs Node's native zstd (≥ 22.15). `.nvmrc` pins 24; this
  machine's default `node` is still 20 and will fail with an explicit message telling you so.

Note that shell globs no longer match: `*.graphml` finds nothing once a directory is reclaimed.
Use `*.graphml.zst` and strip the suffix, or pass the path explicitly.

### Restoring to plaintext — the obvious command does not work

```bash
zstd -d --long=31 page_graph_....graphml.zst
```

A plain `zstd -d` **fails**: `Frame requires too much memory for decoding`. The archive's window
exceeds zstd's default 128 MiB decode budget, so `--long=31` is required. zstd names the flag in
its error, but the number it suggests differs per file — `--long=31` is the upper bound and always
works.

### Do not prune before archiving

This is the counter-intuitive part, so the numbers, measured on walmart (1,143,132,196 B):

| archived | compressed | cost |
|---|---:|---|
| raw | 6,206,822 | nothing |
| `prune-graph.py --max-frames 25` | 5,998,152 | 646 MB and 45% of every call frame, permanently |
| `--drop-stacks --drop-dom-edges` | 4,717,552 | all 110,905 traces + 54,268 edges destroyed |

Pruning first buys **3.4%** and cannot be undone. The edge `stack trace` attribute is 91.4% of
walmart and 99.2% of delta, but only because the engine stores each edge's stack as its own
`std::string` with no interning — 110,905 stacks on walmart are just **14,013 distinct values**.
A compressor exploits that far better than truncation does.

### Why `--long=31` and not gzip

Stack values average 9,423 B and repeat at a median distance of 12,331 B, so gzip's 32 KB window
holds about three of them and **36.2% of repeats are further apart than it can see**:

| codec | bytes | ratio | wall clock |
|---|---:|---:|---:|
| `gzip -9` | 26,602,721 | 42.97× | 6.8 s |
| `zstd -19` | 7,292,402 | 156.8× | 9.0 s |
| **`zstd -19 --long=31`** | **6,206,822** | **184.2×** | **8.9 s** |
| `xz -9` | 6,681,752 | 171.1× | 9.2 s |

Note this is *not* what the crawler's `-z`/`--compress` flag does — that is gzip, applied at crawl
time, and its output is likewise unreadable by every script here.

## Keys and environment

| var | used by | note |
|---|---|---|
| `OPENAI_API_KEY` / `OPENAI_KEY` | `lib/llm-head-chat.mjs` | default model `gpt-5.6-luna`, `service_tier: flex` |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_KEY` | `lib/llm-head-chat.mjs` | default model `claude-sonnet-5` |
| `CLASSIFIER_MODEL` | both | overrides the model |
| `CLASSIFIER_PROVIDER` | `classify-cookies.mjs` | `openai` \| `anthropic`; `--provider` wins |
| `CLASSIFIER_SERVICE_TIER` | OpenAI only | defaults to `flex` |

Nothing loads `.env` automatically. Use `node --env-file=.env …` (Node ≥ 20.6) or
`set -a; source .env; set +a`. `.env` is git-ignored; `.env.example` documents the shape.

**Without a key the classifier silently runs the deterministic prior.** It logs
`mode: rules-only …` and stamps `source: "rules"` rather than `llm:…` — check that field before
reading a run as an LLM verdict.

