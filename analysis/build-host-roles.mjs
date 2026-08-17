#!/usr/bin/env node
// build-host-roles.mjs — compile a compact host→role snapshot from DuckDuckGo Tracker Radar.
//
// Tracker Radar stores one JSON file per (region, registrable-domain) under domains/<REGION>/.
// Each carries an `owner` and a `categories` array from DDG's published taxonomy. This unions
// a domain's categories across every region it appears in and writes a single compact lookup,
// so the labeller can resolve a host offline and deterministically with no per-file I/O.
//
// The snapshot is committed. Regenerate it only to refresh against a newer Tracker Radar; the
// labeller never touches the network. Records the Tracker Radar commit it was built from.
//
// Usage: node analysis/build-host-roles.mjs <tracker-radar-checkout> [--out <file>] [--rev <sha>]

import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const root = process.argv[2];
if (!root || !existsSync(join(root, "domains"))) {
  process.stderr.write("usage: build-host-roles.mjs <tracker-radar-checkout> [--out <file>] [--rev <sha>]\n");
  process.exit(1);
}
const flag = (n, d) => { const i = process.argv.indexOf(n); return i !== -1 ? process.argv[i + 1] : d; };
const outFile = flag("--out", new URL("./data/tracker-radar-roles.json", import.meta.url).pathname);
const rev = flag("--rev", null);

// DDG's category vocabulary → our role. Grounded in Tracker Radar's own taxonomy, not invented
// per-host. A category we do not map contributes no role (but is still preserved verbatim).
const CATEGORY_ROLE = {
  // advertising
  "Advertising": "advertising",
  "Ad Motivated Tracking": "advertising",
  "Ad Fraud": "advertising",
  "Action Pixels": "advertising",
  "Retargeting": "advertising",
  "Third-Party Analytics Marketing": "advertising",
  // analytics / measurement
  "Analytics": "analytics",
  "Audience Measurement": "analytics",
  "Session Replay": "analytics",
  "Tag Manager": "analytics",
  // security / anti-fraud
  "Fraud Prevention": "security",
  "Malware/Spyware": "security",
  // functional / operational
  "Federated Login": "functional",
  "SSO": "functional",
  "Embedded Content": "functional",
  "CDN": "functional",
  "Online Payment": "functional",
  "Consent Management Platform": "functional",
  "Non-Tracking": "functional",
  // social
  "Social - Comment": "social",
  "Social - Share": "social",
  "Social Network": "social",
  "Badge": "social",
};

const regions = readdirSync(join(root, "domains")).filter(r => {
  try { return readdirSync(join(root, "domains", r)).length >= 0; } catch { return false; }
});

const acc = new Map(); // domain -> { owner, categories:Set, regions:Set }
let files = 0, parseErr = 0;
for (const region of regions) {
  const dir = join(root, "domains", region);
  let names; try { names = readdirSync(dir); } catch { continue; }
  for (const name of names) {
    if (!name.endsWith(".json")) continue;
    const domain = name.slice(0, -5);
    let j;
    try { j = JSON.parse(readFileSync(join(dir, name), "utf8")); files++; }
    catch { parseErr++; continue; }
    const rec = acc.get(domain) || { owner: null, categories: new Set(), regions: new Set() };
    if (!rec.owner && j.owner) rec.owner = j.owner.displayName || j.owner.name || null;
    for (const c of j.categories || []) rec.categories.add(c);
    rec.regions.add(region);
    acc.set(domain, rec);
  }
}

const rolesFor = cats => {
  const roles = new Set();
  for (const c of cats) { const r = CATEGORY_ROLE[c]; if (r) roles.add(r); }
  return [...roles];
};

const out = {};
let withCats = 0;
for (const [domain, rec] of acc) {
  const categories = [...rec.categories].sort();
  const roles = rolesFor(categories);
  if (categories.length) withCats++;
  out[domain] = {
    owner: rec.owner || null,
    categories,
    roles,               // may be empty: a known domain with only unmapped categories
    regions: [...rec.regions].sort(),
  };
}

const snapshot = {
  source: "duckduckgo/tracker-radar",
  trackerRadarRev: rev,
  builtRegions: regions.sort(),
  domainCount: Object.keys(out).length,
  domainsWithCategories: withCats,
  domains: out,
};
writeFileSync(outFile, JSON.stringify(snapshot));
process.stderr.write(
  `built ${outFile}\n  ${files} files (${parseErr} parse errors) across ${regions.length} regions\n` +
  `  ${snapshot.domainCount} domains, ${withCats} with categories\n`);
