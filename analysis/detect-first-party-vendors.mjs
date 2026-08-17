#!/usr/bin/env node
// detect-first-party-vendors.mjs — first-party hostnames that are operated by a third-party
// vendor, and (separately) genuine DNS CNAME cloaking.
//
// These are two DIFFERENT things and were previously conflated:
//
//   CNAME CLOAKING is a DNS mechanism, and only that: a first-party hostname whose CNAME record
//   resolves to a THIRD PARTY's domain. The browser treats the request as first-party, so the
//   vendor's server can issue first-party cookies over HTTP and the request evades hostname
//   blocklists. Confirming it requires DNS showing the alias leaving the first party for a
//   non-CDN third party. A CNAME to Akamai/CloudFront is the site using a CDN — not cloaking,
//   and it MASKS whoever runs the origin, so it can neither confirm nor deny.
//
//   VENDOR-OPERATED FIRST-PARTY HOST is the broader arrangement: a first-party hostname whose
//   origin is run by a vendor, by any mechanism — a CNAME, or simply an A record pointing at the
//   vendor's cloud (Google server-side tagging is A-record, no CNAME at all). Detected from
//   observed behaviour: the vendor's own code executing from the host, its request-body schema,
//   or the server's own infrastructure header.
//
// What is NOT evidence of either: "the host sets a first-party cookie". Any third-party script
// in the page can set a first-party cookie with document.cookie — Google Analytics and the Meta
// pixel both do it routinely. It says nothing about who operates the hostname. Server-issued
// cookies (from Set-Cookie response headers) are still reported, as a CONSEQUENCE of the
// arrangement rather than as proof of it.
//
// Usage: node analysis/detect-first-party-vendors.mjs <net.json> <stack.json> [--json out] [--no-dns]

import { readFileSync, writeFileSync } from "node:fs";
import { promises as dns } from "node:dns";
import { roleOf } from "./lib/host-role.mjs";

const netPath = process.argv[2], stackPath = process.argv[3];
if (!netPath || !stackPath) {
  console.error("usage: detect-first-party-vendors.mjs <net.json> <stack.json> [--json out] [--no-dns]");
  process.exit(1);
}
const flag = (n, d) => { const i = process.argv.indexOf(n); return i !== -1 ? process.argv[i + 1] : d; };
const jsonOut = flag("--json", null);
const doDns = !process.argv.includes("--no-dns");

const net = JSON.parse(readFileSync(netPath, "utf8"));
const stack = JSON.parse(readFileSync(stackPath, "utf8"));
const pageUrl = stack.pageUrl || "";

const MULTI_SUFFIX = new Set(["co.uk", "com.au", "co.jp", "co.nz", "com.br", "co.in", "org.uk", "gov.uk"]);
const registrable = host => {
  if (!host) return null;
  const p = String(host).toLowerCase().replace(/\.$/, "").split(".");
  if (p.length <= 2) return p.join(".");
  const last2 = p.slice(-2).join(".");
  return MULTI_SUFFIX.has(last2) ? p.slice(-3).join(".") : last2;
};
const pageReg = (() => { try { return registrable(new URL(pageUrl).hostname); } catch { return null; } })();

// Delivery networks. A CNAME terminating here identifies the CDN, not the origin operator.
const CDN_SUFFIX = /(^|\.)(edgekey\.net|edgesuite\.net|akamaiedge\.net|akamai\.net|akadns\.net|akamaized\.net|cloudfront\.net|fastly\.net|fastlylb\.net|azureedge\.net|cloudflare\.net|cdn77\.org|impervadns\.net|footprint\.net|llnwd\.net)$/i;

// Vendor categories that make a first-party-hosted vendor privacy-relevant (not CDN/security).
const DATA_CATS = new Set(["advertising", "analytics", "customer data", "personalisation",
  "session replay", "tag manager", "CDP", "survey", "experimentation", "call tracking"]);
// Server/via fingerprints the host itself emits, revealing a vendor cloud behind a first-party name.
const INFRA_VENDOR = [[/Google Frontend/i, "Google (server-side tagging / GA)", true]];

const infraStr = h => Object.entries(h.infraHeaders || {}).map(([k, v]) => `${k}: ${v[0]}`).join(" | ");

// Reverse-DNS operator for a host's A records: the registrable domain of the PTR name
// (googleusercontent.com, akamaitechnologies.com, cloudfront.net…). Comparing this against the
// CANONICAL domain's operator is the indirect DNS signal: if a first-party subdomain is hosted by
// a different operator than the site's own www, something else is running it. Raw IP or /16
// comparison does NOT work — a CDN allocates different edge IPs per property, so two hosts on the
// same CDN look "different" by address while having the same operator.
async function hostOperator(host) {
  let ips = [];
  try { ips = await dns.resolve4(host); } catch { /* */ }
  if (!ips.length) { try { ips = await dns.resolve6(host); } catch { /* */ } }
  if (!ips.length) return { ips: [], operator: null, ptr: null };
  let ptr = null;
  for (const ip of ips.slice(0, 2)) { try { const r = await dns.reverse(ip); if (r && r[0]) { ptr = r[0]; break; } } catch { /* */ } }
  return { ips, ptr, operator: ptr ? registrable(ptr) : null };
}

async function cnameChain(host) {
  if (!doDns) return [];
  const chain = []; let cur = host, hops = 0;
  while (hops++ < 8) {
    let recs; try { recs = await dns.resolveCname(cur); } catch { break; }
    if (!recs || !recs.length) break;
    const next = recs[0].replace(/\.$/, "");
    if (next === cur) break;
    chain.push(next); cur = next;
  }
  return chain;
}

// executed-source + body-shape vendor identity per first-party host (from detect-stack)
const stackByHost = new Map();
for (const d of stack.detections || []) {
  if (!DATA_CATS.has(d.category)) continue;
  for (const sf of d.servedFrom || []) {
    if (registrable(sf) !== pageReg || sf === pageReg || sf === "www." + pageReg) continue;
    if (!stackByHost.has(sf)) stackByHost.set(sf, []);
    stackByHost.get(sf).push({ vendor: `${d.name} (${d.category})`, how: `executed source (${d.detectedBy})` });
  }
}
const bodyByHost = new Map();
for (const e of stack.endpointSignatures || []) {
  try {
    const hh = new URL("https://" + e.endpoint).hostname;
    if (registrable(hh) === pageReg && hh !== pageReg && hh !== "www." + pageReg) {
      if (!bodyByHost.has(hh)) bodyByHost.set(hh, []);
      bodyByHost.get(hh).push({ vendor: e.name, how: "request-body shape", evidence: e.endpoint });
    }
  } catch { /* */ }
}

// Canonical baseline: how the site's own primary hostname is hosted.
const canonicalHost = (() => { try { return new URL(pageUrl).hostname; } catch { return null; } })();
const canonical = canonicalHost && doDns ? await hostOperator(canonicalHost) : { ips: [], operator: null, ptr: null };

const findings = [];
let firstPartyHostsExamined = 0;
for (const h of net.hosts || []) {
  const host = h.host;
  if (!pageReg || registrable(host) !== pageReg) continue;
  if (host === pageReg || host === "www." + pageReg) continue;
  firstPartyHostsExamined++;

  const chain = await cnameChain(host);
  const target = chain.length ? chain[chain.length - 1] : null;
  const targetReg = target ? registrable(target) : null;
  const leavesParty = !!targetReg && targetReg !== pageReg;
  const viaCdn = !!target && CDN_SUFFIX.test(target);
  // LITERAL CNAME cloaking: the alias leaves the first party for a third party that is not a CDN
  // AND that Tracker Radar actually categorises as a tracker. A CNAME to an uncategorised domain
  // (typically a CDN or media host not in my suffix list — e.g. cloud-cdn.co) is not evidence of
  // cloaking; calling it that would be the same over-claim as inferring from a suggestive name.
  const targetRole = leavesParty && !viaCdn ? roleOf(target) : null;
  const targetIsTracker = !!targetRole && (targetRole.roles || []).length > 0;
  const cnameCloaked = leavesParty && !viaCdn && targetIsTracker;
  const cnameOffPartyUncategorised = leavesParty && !viaCdn && !targetIsTracker;
  const cnameTargetRole = targetRole;

  // indirect DNS evidence: hosted by a different operator than the canonical domain
  const self = doDns ? await hostOperator(host) : { ips: [], operator: null, ptr: null };
  const operatorDiffers = !!(self.operator && canonical.operator && self.operator !== canonical.operator);

  // vendor-operated evidence (behaviour / server-declared), independent of DNS
  const signals = [];
  for (const v of stackByHost.get(host) || []) signals.push({ how: v.how, vendor: v.vendor, evidence: "vendor script served from this host" });
  for (const v of bodyByHost.get(host) || []) signals.push({ how: v.how, vendor: v.vendor, evidence: v.evidence });
  const infra = infraStr(h);
  const hasCollection = (h.serverSetCookies || []).length > 0 || /XMLHttpRequest|Fetch|Beacon/.test((h.resourceTypes || []).join(","));
  for (const [re, v, needsColl] of INFRA_VENDOR) if (re.test(infra) && (!needsColl || hasCollection)) signals.push({ how: "server-declared infrastructure", vendor: v, evidence: infra.slice(0, 90) });

  if (operatorDiffers) signals.push({ how: "DNS hosting divergence",
    vendor: `hosted by ${self.operator} (canonical ${canonicalHost} is on ${canonical.operator})`,
    evidence: `${host} → ${self.ips.slice(0,2).join(", ")} [${self.ptr || "no PTR"}]` });

  if (!signals.length && !cnameCloaked) continue;

  findings.push({
    host,
    // the two classes, kept apart
    cnameCloaked,
    vendorOperated: signals.length > 0,
    verdict: cnameCloaked ? "CNAME cloaking (DNS alias to a third party)"
      : "vendor-operated first-party host (no CNAME cloaking observed)",
    vendors: [...new Set(signals.map(s => s.vendor))],
    signals,
    cnameChain: chain,
    cnameTarget: target,
    cnameLeavesFirstParty: leavesParty,
    cnameViaCdn: viaCdn,
    cnameOffPartyUncategorised,
    hostingOperator: self.operator, canonicalOperator: canonical.operator,
    hostingOperatorDiffers: operatorDiffers, hostingPtr: self.ptr, hostingIps: self.ips.slice(0, 3),
    cnameTargetVendor: cnameTargetRole ? { owner: cnameTargetRole.owner, categories: cnameTargetRole.categories } : null,
    // consequence, not proof: cookies the SERVER issued on a first-party hostname
    serverIssuedCookies: (h.serverSetCookies || []).slice(0, 8),
    resourceTypes: h.resourceTypes || [],
  });
}

const report = {
  pageUrl, pageRegistrableDomain: pageReg, dnsChecked: doDns,
  firstPartyHostsExamined,
  cnameCloakedCount: findings.filter(f => f.cnameCloaked).length,
  vendorOperatedCount: findings.filter(f => !f.cnameCloaked && f.vendorOperated).length,
  findings,
};
if (jsonOut) writeFileSync(jsonOut, JSON.stringify(report, null, 2));

console.log(`${pageUrl || netPath}`);
console.log(`  ${report.cnameCloakedCount} CNAME-cloaked, ${report.vendorOperatedCount} vendor-operated first-party host(s), of ${firstPartyHostsExamined} examined\n`);
for (const f of findings) {
  console.log(`  ${f.host}   [${f.verdict}]`);
  if (f.vendors.length) console.log(`      vendor: ${f.vendors.join("; ")}`);
  if (f.cnameChain.length) console.log(`      CNAME: → ${f.cnameChain.join(" → ")}${f.cnameViaCdn ? "  (CDN — origin operator masked, not cloaking)" : ""}`);
  else console.log(`      CNAME: none (A record) — no DNS cloaking`);
  if (f.hostingOperatorDiffers) console.log(`      hosting: ${f.hostingOperator} — canonical is ${f.canonicalOperator} (different operator)`);
  if (f.serverIssuedCookies.length) console.log(`      server-issued cookies (consequence): ${f.serverIssuedCookies.join(", ")}`);
  for (const s of f.signals) console.log(`      · ${s.how}: ${s.vendor}`);
}
