---
name: cookie-declaration-report
description: Generate an HTML report comparing what a site DECLARES each cookie does (its own CMP/OneTrust ruleset) against what our independent behavioural classifier OBSERVED it do — flagging cookies declared Strictly Necessary that behave as tracking, and internally contradictory declarations. Use after a crawl has been classified. Invoke as "/cookie-declaration-report <crawl-dir>".
argument-hint: <crawl-dir>
---

# cookie-declaration-report

Produce a self-contained HTML report for one crawl that places the **site's own declared purpose**
for each cookie beside our **independently observed** classification, and surfaces where they part
company. Runs on any crawl dir; developed on the 8-client fixture but keyed only off artifacts every
crawl produces.

**The classifier is independent and stays that way.** It classifies from behaviour and never sees
the declaration. This report is purely a join at the presentation layer — declared vs observed. Do
not feed the declaration (or the MCP) back into the classifier.

## Parse the argument
`<crawl-dir>` — a crawl output directory containing `*.graphml`, `*.cookies.json`, and
`*.bodies.ndjson` (e.g. `output/clients-2026-08-02-fixed/directv`).

## Steps

1. **Fetch the declaration** (the site's own CMP ruleset, re-fetched in full — the crawl-time copy
   is truncated at 64 KB and drops the Advertising groups):
   ```
   node analysis/fetch-declarations.mjs <crawl-dir>
   ```
   Writes `<base>.declaration.json`. OneTrust sites parse; a site with no readable CMP
   (self-hosted, Ensighten, none) yields `cmp: null` and every cookie reads "not declared" — that is
   expected, not a failure. Carries a caveat: the declaration reflects **now**, not crawl time.

2. **Ensure the crawl is classified.** The report needs our observed verdicts in a
   `classify-v2-<site>` dir (the two-pass classifier + `pass3` reconciliation). If absent:
   ```
   node analysis/classify-v2.mjs <crawl-dir>/<graphml> --provider openai --out output/classify-v2-<site>
   node analysis/pass3.mjs output/classify-v2-<site> --crawl-root <parent-of-crawl-dir>
   ```
   Needs `OPENAI_KEY`/`ANTHROPIC_KEY` in the environment (`set -a; source .env; set +a`).

3. **Generate the report:**
   ```
   node analysis/declaration-report.mjs <crawl-dir> --classify output/classify-v2-<site> --out <out.html>
   ```

## What the report says

Per cookie, three columns — **declared** | **observed (ours, with confidence)** | **verdict**:
- **under-declared** — declared benign (Strictly Necessary / Functional), observed tracking. The
  headline compliance finding, with the behavioural evidence cited.
- **contradictory declaration** — the site listed the cookie under mutually-exclusive purposes
  (e.g. Necessary *and* Advertising). Our classifier says which the behaviour supports.
- **over-declared** — declared tracking, not observed this load (stated cautiously: one page load is
  a small window, absence is not proof).
- **consistent** / **not assessable** (our confidence too low — we abstain) / **not declared**.

Headline metric: cookies declared Strictly Necessary that behave as tracking.

## Combined view across sites (per-cookie, per-website, + MCP)
For one report covering every crawled site — a row per cookie per site with three columns side by
side (our **observed** classification | the site's **declared** category | the **MCP** name-corpus
label) plus the declared-vs-observed verdict:
```
node analysis/combined-cookie-report.mjs --crawl-root <crawls-parent> --classify-root output --out <out.html>
```
The MCP column is reference only — name-keyed (identical across sites for a name) and never the
yardstick; the verdict compares only observed vs declared.

## The rule behind it
Mutual exclusivity is *derived*, not hand-picked: `analysis/data/category-rules.json` records each
category's consent basis (exempt vs consent-required) from PECR reg 6 / the ICC UK Cookie Guide /
IAB TCF v2.2. A cookie cannot be both consent-exempt and consent-requiring, so any declaration
asserting one of each is contradictory. `analysis/lib/category-rules.mjs` re-derives the pairs from
those bases and asserts they match the precomputed list.

## Presentation
VaultJS brand palette (Navy ground, Salmon for violations, Sea Green for consistent, Gold for
caution), exact hex from the brand guide; system font stacks; fully self-contained (no external
requests). The brand logo asset is intentionally not embedded — do not recreate it; the palette
carries the identity, matching the existing audit report.

## Honesty guarantees to preserve
- Never assert a divergence off a low-confidence observed label — abstain ("not assessable").
- A site with no parseable declaration renders "not declared", never an error.
- The declaration is the site's; the observed verdict is ours and independent. Keep the two visibly
  separate in every row.
