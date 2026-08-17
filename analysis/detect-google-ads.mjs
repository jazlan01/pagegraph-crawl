#!/usr/bin/env node
// detect-google-ads.mjs — decide, per crawl, whether the Google Analytics deployment is sharing
// with Google's advertising systems, from OBSERVED client-side behaviour.
//
// A `_ga` cookie is the GA client id; by itself it is analytics. GA4 becomes advertising when the
// property's "Google signals / share data with Google" toggle is on. The observable client-side
// tell is that GA4 mirrors its collect hit to the DoubleClick advertising domain, plus the Google
// Ads conversion cookies / tags. This produces a site-level signal (the toggle is per-property):
//
//   1. GA4 collect mirrored to stats.g.doubleclick.net/g/collect (same tid=G-…), or a
//      google.com/ads/ga-audiences remarketing pixel, or td.doubleclick.net  — Google signals on;
//   2. Google Ads conversion cookies (_gcl_au / _gcl_* / _gac_*) present, or a GA-family value
//      observed reaching googleadservices.com / *.doubleclick.net;
//   3. gtag configured an AW- (Google Ads) or DC- (Floodlight) tag id  (from detect-stack).
//
// IMPORTANT: absence of these does NOT prove analytics-only. GA data sent to Google can be linked
// to the user's Google account and used for ad personalisation server-side (Google Takeout
// evidences this). A logged-out, single-load crawl cannot observe that — no Google-account cookies
// are sent — so we report only what fired client-side. The caller renders that limit as a caveat,
// not as an advertising label.
//
// Usage: node analysis/detect-google-ads.mjs <flowdir> --bodies <ndjson> --stack <stack.json> [--out <file>]

import { createReadStream, readFileSync, writeFileSync, existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const DIR = argv.find(a => !a.startsWith("--") && argv[argv.indexOf(a) - 1] !== "--bodies" && argv[argv.indexOf(a) - 1] !== "--stack" && argv[argv.indexOf(a) - 1] !== "--out");
const bodiesPath = flag("--bodies", null);
const stackPath = flag("--stack", null);
const outPath = flag("--out", DIR ? join(DIR, "_google-ads.json") : null);
if (!DIR) { process.stderr.write("usage: detect-google-ads.mjs <flowdir> --bodies <ndjson> --stack <stack.json> [--out <file>]\n"); process.exit(1); }

const evidence = [];
const add = (signal, detail) => { if (!evidence.some(e => e.signal === signal && e.detail === detail)) evidence.push({ signal, detail }); };

// --- signal 1 & 2b: request URLs from the bodies sidecar ---
const MIRROR = /(^|\/\/)stats\.g\.doubleclick\.net\/g\/collect/;
const GA_AUD = /\/\/[^/]*google\.[a-z.]+\/ads\/ga-audiences/;
const TD_DC = /(^|\/\/)td\.doubleclick\.net\//;
const ADS_HOST = /(^|\/\/)(www\.)?(googleadservices\.com|googleads\.g\.doubleclick\.net|\d+\.fls\.doubleclick\.net)/;
if (bodiesPath && existsSync(bodiesPath)) {
  const rl = createInterface({ input: createReadStream(bodiesPath, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let r; try { r = JSON.parse(line); } catch { continue; }
    if (r.kind !== "request" || !r.url) continue;
    const u = r.url;
    if (MIRROR.test(u)) { const tid = (u.match(/[?&]tid=(G-[A-Z0-9]+)/) || [])[1]; add("ga-doubleclick-mirror", `stats.g.doubleclick.net/g/collect${tid ? " tid=" + tid : ""}`); }
    else if (GA_AUD.test(u)) add("ga-audiences", u.split("?")[0]);
    else if (TD_DC.test(u)) add("td.doubleclick.net", u.split("?")[0]);
    if (ADS_HOST.test(u)) { try { add("google-ads-endpoint", new URL(u).hostname); } catch { /* */ } }
  }
}

// --- signal 3: AW-/DC- tag ids configured in gtag (executed source, via detect-stack) ---
if (stackPath && existsSync(stackPath)) {
  const stk = JSON.parse(readFileSync(stackPath, "utf8"));
  for (const d of stk.detections || []) {
    for (const id of d.accountIds || []) {
      const m = id.match(/\b(AW-\d+|DC-\d+)\b/);
      if (m) add("gtag-ads-tag", `${m[1]} (${d.name})`);
    }
  }
}

// --- signal 2a: GA-family cookies present, and any reaching an ad host (from behaviour) ---
const GA_FAMILY = /^(_ga($|_)|_gid$|_gat|_gcl_|_gac_|__gads$|__gpi$)/;
const GADS_COOKIE = /^(_gcl_|_gac_)/;
const behPath = join(DIR, "_behaviour.json");
let gaFamilyItems = [];
if (existsSync(behPath)) {
  const beh = JSON.parse(readFileSync(behPath, "utf8"));
  gaFamilyItems = beh.items.filter(it => GA_FAMILY.test(it.item)).map(it => it.item);
  for (const it of beh.items) {
    if (GADS_COOKIE.test(it.item)) add("google-ads-cookie", it.item);
    if (GA_FAMILY.test(it.item)) {
      const dests = it.offsiteDestinations || [];
      if (dests.some(d => /doubleclick\.net|googleadservices\.com/.test(d)))
        add("ga-value-to-ads-host", `${it.item} → ${dests.filter(d => /doubleclick|googleadservices/.test(d)).join(", ")}`);
    }
  }
}

const gaAdvertising = evidence.length > 0;
const report = { flowdir: DIR, gaAdvertising, gaFamilyItems, evidence };
if (outPath) writeFileSync(outPath, JSON.stringify(report, null, 2));

const site = DIR.replace(/\/$/, "").split("/").pop();
console.log(`${site}: GA advertising = ${gaAdvertising ? "YES" : "no client-side signal"}  (GA-family cookies: ${gaFamilyItems.join(", ") || "none"})`);
for (const e of evidence) console.log(`    · ${e.signal}: ${e.detail}`);
