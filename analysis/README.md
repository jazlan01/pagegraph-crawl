# analysis/ — cookie deep-dive tooling

Deterministic helpers that turn the crawler's PageGraph output into inputs for an iterative,
debugger-driven cookie audit. They are the "tools" the **`cookie-analyst`** subagent drives (see
`.claude/agents/cookie-analyst.md`, invoked via the `/cookie-dossier` skill).

Plain Node ESM — no build step. Run from the repo root.

## `cookie-sites.mjs`

```
node analysis/cookie-sites.mjs <graphml> <cookieName>
```

Parses a `page_graph_*.graphml` and reports where a cookie is **set / deleted / read**, resolving
each acting script to its source URL. Emits ready `--debug-breakpoint` specs (`<escapedUrl>#<offset>`)
for the write sites — the byte offset is the `script position` PageGraph records on `storage set`
edges. Inline-script sites are flagged (no offset spec; their offsets are document-relative).

Output JSON: `{ cookie, pageUrl, writes[], deletes[], reads{sites, readersReturningCookie}, writeSpecs[] }`.

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
