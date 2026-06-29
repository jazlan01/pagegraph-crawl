---
name: cookie-dossier
description: Deep-dive how a website sets, reads, updates, and transforms a specific cookie, using the PageGraph crawler's CDP debug harness. Use when the user wants to audit a named cookie's lifecycle/provenance against a custom (PageGraph) Brave build. Invoke as "/cookie-dossier <braveBinary> <cookieName> <url>".
argument-hint: <braveBinary> <cookieName> <url>
---

# cookie-dossier

Run a deep-dive analysis of a single cookie's lifecycle by delegating to the **`cookie-analyst`**
subagent, which drives the crawler (`/Users/jazlan/Desktop/pagegraph-crawl`) and its analysis tools.

## Parse the arguments

From the invocation `arguments`, extract in order:
1. `braveBinary` — path to the PageGraph-enabled Brave binary (required).
2. `cookieName` — the cookie to analyze, e.g. `_px3` (required).
3. `url` — the page to crawl, e.g. `https://www.walmart.com/` (required).

If any are missing, ask the user for the missing value(s) and stop — do not guess a binary path or
URL.

## Delegate to the subagent

Launch the **`cookie-analyst`** agent (via the Agent tool, `subagent_type: "cookie-analyst"`) with a
task prompt that includes the three parsed values, for example:

> Analyze the cookie **`<cookieName>`** on **`<url>`** using the PageGraph binary at
> **`<braveBinary>`**. Follow your full procedure: baseline crawl → `cookie-sites.mjs` to locate
> write/read sites → `--debug-stacks` capture passes at those offsets (condense with
> `stacks-query.mjs`) → iterate up the call stack (≤4 passes) to classify the value's origin and
> transforms → write `<cookieName>.dossier.json` and `<cookieName>.md` into the run dir. Obey the
> hard safety rules (never `--debug-native`; never Read a raw stacks.json; `--debug-max-captures ≤
> 12`). Report the verdict and the two output paths.

## After it returns

Relay the subagent's verdict and the paths to the JSON dossier + Markdown narrative. Offer to open
the Markdown or to run the same analysis on a related cookie.

Notes:
- The subagent needs `built/` present; it runs `npm run build` (fast tsc) itself if needed.
- This requires a PageGraph-enabled Brave build — the harness attaches the CDP Debugger domain.
