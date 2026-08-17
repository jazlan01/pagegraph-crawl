#!/usr/bin/env node
// fetch-declarations.mjs — recover a crawl's CMP ruleset URL and re-fetch it IN FULL.
//
//   node analysis/fetch-declarations.mjs <crawl-dir>... [--out-suffix .declaration.json]
//
// Why re-fetch rather than read the captured body: the crawl stored CMP config bodies but capped
// them at 64 KB (--body-max), and OneTrust serialises "Strictly Necessary" first — so the retained
// prefix systematically DROPS the Advertising/Targeting groups. A divergence read off the truncated
// copy would under-count exactly the mis-declarations we care about. The URL is public CDN, no auth.
//
// Caveat, written into the output: a re-fetch reflects the declaration AS OF NOW, not crawl time.
// For a litigation-grade artefact the crawler should capture the full CMP body at crawl time
// (--save-bodies-full for the CMP request). For building and for current-state audits this is fine.
//
// Writes <crawlbase>.declaration.json next to the graph. On any failure (no CMP found, fetch error,
// unparseable) it writes a record with `cmp: null` / `parseFailed` rather than throwing — a site
// with no readable declaration is a normal corpus case, not an error.

import { readdirSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

import { findRulesetUrl, parseDeclaration } from "./lib/cmp-declaration.mjs";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const suffix = flag("--out-suffix", ".declaration.json");
const dirs = argv.filter((a) => !a.startsWith("--"));
if (!dirs.length) {
  process.stderr.write("usage: node analysis/fetch-declarations.mjs <crawl-dir>...\n");
  process.exit(1);
}

const fetchJson = async (url) => {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
};

for (const dir of dirs) {
  const site = dir.replace(/\/$/, "").split("/").pop();
  const graph = existsSync(dir) && readdirSync(dir).find((f) => f.endsWith(".graphml"));
  const bodies = existsSync(dir) && readdirSync(dir).find((f) => f.endsWith(".bodies.ndjson"));
  if (!graph) { process.stderr.write(`${site}: no graphml, skipping\n`); continue; }
  const base = join(dir, graph.replace(/(\.pruned)?\.graphml$/, ""));
  const outPath = base + suffix;

  let record = { site, cmp: null, note: "no CMP ruleset found in this crawl", cookies: {} };
  try {
    const found = bodies ? await findRulesetUrl(join(dir, bodies)) : { cmp: null };
    if (found.cmp && found.url) {
      const json = await fetchJson(found.url);
      record = { site, fetchedAt: new Date().toISOString(),
        caveat: "declaration re-fetched now, not captured at crawl time",
        ...parseDeclaration(found.cmp, json, found.url) };
    }
  } catch (e) {
    record = { site, cmp: null, fetchError: String(e.message ?? e), cookies: {} };
  }

  writeFileSync(outPath, JSON.stringify(record, null, 2));
  const n = Object.keys(record.cookies || {}).length;
  console.log(`${site.padEnd(12)} ${record.cmp ?? "no CMP"}  ${n} declared cookie(s)  -> ${outPath}`);
}
