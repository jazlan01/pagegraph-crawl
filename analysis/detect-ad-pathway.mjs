#!/usr/bin/env node
// detect-ad-pathway.mjs — did this page activate an advertising pathway at all?
//
// Generalises the Google-signals idea to every vendor. Many measurement platforms are dual-use:
// Tracker Radar categorises them as BOTH advertising and analytics (Optimizely, Qualtrics,
// Tealium, GTM, Contentsquare…). Labelling their identifiers "advertising" purely because the
// vendor *can* do advertising is the same error the blanket `_ga` label was.
//
// The site-level signal is whether the page contacted any host that is advertising and NOT
// analytics — a pure ad/RTB endpoint (doubleclick, adsrvr, adnxs, rubiconproject, openx,
// pubmatic, amazon-adsystem …). If a page never touches an ad endpoint, a dual-use vendor on it
// is being used for measurement; if it does, the ad pathway is demonstrably live.
//
// Roles come from the committed Tracker Radar snapshot (lib/host-role.mjs), so no vendor name is
// hard-coded here. Reads only the bodies sidecar — no graph re-stream.
//
// Usage: node analysis/detect-ad-pathway.mjs <flowdir> --bodies <ndjson> [--out <file>]

import { createReadStream, writeFileSync, existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { roleOf } from "./lib/host-role.mjs";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const DIR = argv.find((a, i) => !a.startsWith("--") && argv[i - 1] !== "--bodies" && argv[i - 1] !== "--out");
const bodiesPath = flag("--bodies", null);
const outPath = flag("--out", DIR ? join(DIR, "_ad-pathway.json") : null);
if (!DIR) { process.stderr.write("usage: detect-ad-pathway.mjs <flowdir> --bodies <ndjson> [--out <file>]\n"); process.exit(1); }

const adOnly = new Map();   // registrable domain -> { owner, categories, sampleHost }
const dualSeen = new Map();

// The page's own registrable domain is excluded: a site contacting itself is not an ad pathway,
// even when Tracker Radar categorises that domain as advertising (large retailers and publishers
// are trackers on OTHER sites, which is what the dataset records). Same first-party exclusion the
// labeller applies to role resolution.
const MULTI_SUFFIX = new Set(["co.uk", "com.au", "co.jp", "co.nz", "com.br", "co.in", "org.uk", "gov.uk"]);
const registrable = host => {
  const p = String(host).toLowerCase().replace(/\.$/, "").split(".");
  if (p.length <= 2) return p.join(".");
  const last2 = p.slice(-2).join(".");
  return MULTI_SUFFIX.has(last2) ? p.slice(-3).join(".") : last2;
};
let pageReg = null;

if (bodiesPath && existsSync(bodiesPath)) {
  const rl = createInterface({ input: createReadStream(bodiesPath, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let r; try { r = JSON.parse(line); } catch { continue; }
    if (r.kind !== "request" || !r.url) continue;
    let host; try { host = new URL(r.url).hostname; } catch { continue; }
    // first document request is the navigation itself → the page's own domain
    if (!pageReg && r.resourceType === "document") pageReg = registrable(host);
    if (pageReg && registrable(host) === pageReg) continue;
    const role = roleOf(host);
    if (!role || !(role.roles || []).length) continue;
    const isAd = role.roles.includes("advertising");
    const isAna = role.roles.includes("analytics");
    // A pure ad endpoint: advertising, and not also a measurement product.
    if (isAd && !isAna && !adOnly.has(role.matchedDomain))
      adOnly.set(role.matchedDomain, { owner: role.owner || null, categories: role.categories || [], sampleHost: host });
    if (isAd && isAna && !dualSeen.has(role.matchedDomain))
      dualSeen.set(role.matchedDomain, { owner: role.owner || null, categories: role.categories || [] });
  }
}

const evidence = [...adOnly.entries()].map(([d, v]) => ({
  signal: "ad-only endpoint contacted", domain: d, owner: v.owner,
  detail: `${v.sampleHost} [${v.categories.join(", ")}]`,
}));

const report = {
  flowdir: DIR,
  adPathway: adOnly.size > 0,
  adOnlyHosts: [...adOnly.keys()],
  dualUseHosts: [...dualSeen.keys()],
  evidence,
};
if (outPath) writeFileSync(outPath, JSON.stringify(report, null, 2));

const site = DIR.replace(/\/$/, "").split("/").pop();
console.log(`${site}: ad pathway = ${report.adPathway ? "ACTIVE" : "none observed"}`);
if (report.adOnlyHosts.length) console.log(`    ad-only endpoints: ${report.adOnlyHosts.join(", ")}`);
if (report.dualUseHosts.length) console.log(`    dual-use vendors:  ${report.dualUseHosts.join(", ")}`);
