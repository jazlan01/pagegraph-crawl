#!/usr/bin/env node
// identify-items.mjs — attach WHAT EACH ITEM IS to the report, separately from what it did.
//
//   node analysis/identify-items.mjs <report-dir>
//     e.g. node analysis/identify-items.mjs output/audit-2026-08-02
//
// Reads the identity cache built by `merge-mcp-identity.mjs` (out-of-band MCP calls), applies the
// contradiction guard in `lib/item-identity.mjs`, and writes `ident` onto every item.
//
// Identity is name-derived and therefore a different KIND of claim from everything else in the
// report, so three rules are enforced here rather than left to the renderer:
//
//   1. Cookies only. The CMP corpus is a cookie corpus; asking it about a localStorage key would
//      be a category error dressed up as a lookup. localStorage/sessionStorage stay Tier 2.
//   2. The recording outranks the lookup. If the description names a vendor that this crawl never
//      touched, the description is dropped — see `contradicts()`. A name-only match "may collide
//      with an unrelated same-name cookie" (the MCP's own words), and that collision is exactly
//      what would otherwise put a false vendor in a client report.
//   3. Nothing here touches `icc`/`tcf`. Labels remain behavioural.
//
// Idempotent: re-running replaces `ident`.

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { identify } from "./lib/item-identity.mjs";

const reportDir = process.argv[2];
if (!reportDir || !existsSync(reportDir)) {
  process.stderr.write("usage: node analysis/identify-items.mjs <report-dir>\n");
  process.exit(1);
}
const dataPath = join(reportDir, "report-data.json");
const htmlName = readdirSync(reportDir).find(f => f.endsWith(".html") && f.includes("audit"));
if (!existsSync(dataPath) || !htmlName) {
  process.stderr.write(`need report-data.json and an audit .html in ${reportDir}\n`);
  process.exit(1);
}
const report = JSON.parse(readFileSync(dataPath, "utf8"));

const CACHE = new URL("./data/cookie-identity-mcp.json", import.meta.url).pathname;
const cache = existsSync(CACHE) ? JSON.parse(readFileSync(CACHE, "utf8")) : { records: {} };

// ---------- why there is no automated contradiction check here ----------
// The plan called for dropping any name-derived identity that named a vendor this crawl never
// touched. That requires a STRUCTURED vendor field, and the MCP returns none — the vendor exists
// only inside the prose. Reading it back out was tried against the Tracker Radar owner list and
// failed in both directions, so it was removed rather than tuned:
//
//   * False extraction. "respect your privacy choices on FUTURE visits" matched the owner
//     "Future" (the publisher); "help OPTIMIZE website performance" matched "Optimize". Owner
//     names that are ordinary English words make the vocabulary unusable, and a stoplist to
//     patch it would be exactly the arbitrary judgement this pipeline avoids.
//   * False rejection. `_abck` is correctly described as Akamai Bot Manager, but Akamai's edge is
//     served first-party, so its host never appears as an observed third party — the guard threw
//     away a correct identity. Same for Amplitude's `AMP_*`, written by first-party bundle code.
//     Absence of a vendor host is not evidence against the claim; it is the normal case.
//
// So identity is carried WITHOUT a vendor assertion of our own, and the honest control is
// disclosure: every line is tagged as a name lookup and the corpus caveat travels with it. The
// guard in `lib/item-identity.mjs` remains, unused here, for a future source that does return a
// structured vendor.

// ---------- attach ----------
const counts = { mcp: 0, observed: 0, rejected: 0, nonCookie: 0, noRecord: 0 };
const rejections = [];
for (const site of report.sites) {
  for (const it of site.items) {
    delete it.ident;
    if (it.b !== "c") { it.ident = identify(it, null, site); counts.nonCookie++; continue; }

    const rec = cache.records?.[it.n];
    if (!rec) { it.ident = identify(it, null, site); counts.noRecord++; continue; }

    // No company assertion of our own: see the note above. `identify()` therefore keeps the
    // description as context and resolves the company from the observed writer, which is a
    // statement about the recording rather than about the name.
    const id = identify(it, { ...rec, company: null }, site);
    if (id.rejected) {
      counts.rejected++;
      rejections.push({ site: site.dir, cookie: it.n, claimed: id.rejected.claim });
    } else if (id.source === "observed") counts.observed++;
    else counts.mcp++;
    it.ident = id;
  }
}

report.identityAdded = new Date().toISOString().slice(0, 10);
report.totals.identityKnown = counts.mcp;
report.totals.identityObserved = counts.observed + counts.noRecord + counts.nonCookie + counts.rejected;
report.identitySource = {
  name: cache.source ?? null,
  caveat: cache.caveat ?? null,
  model: Object.values(cache.records ?? {})[0]?.model ?? null,
};
writeFileSync(dataPath, JSON.stringify(report));

const htmlPath = join(reportDir, htmlName);
const html = readFileSync(htmlPath, "utf8");
const start = html.indexOf("const DATA = ");
if (start === -1) { process.stderr.write("could not find `const DATA = ` in the HTML\n"); process.exit(1); }
const eol = html.indexOf("\n", start);
writeFileSync(htmlPath,
  html.slice(0, start) + "const DATA = " + JSON.stringify(report) + ";" + html.slice(eol));

console.log(`identity: ${counts.mcp} from the knowledge base · ` +
  `${counts.noRecord} cookies with no record · ${counts.nonCookie} non-cookie (Tier 2 by design) · ` +
  `${counts.rejected} rejected as contradicting the recording`);
if (rejections.length) {
  console.log("\nrejected (the lookup named a vendor this crawl never touched):");
  for (const r of rejections.slice(0, 15)) {
    console.log(`  ${r.site}/${r.cookie}: claimed ${r.claimed}`);
  }
}
