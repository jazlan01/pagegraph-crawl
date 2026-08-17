#!/usr/bin/env node
// blind-payloads.mjs — produce a BLINDED evidence set for independent evaluation.
//
//   node analysis/blind-payloads.mjs <payloads.json> [--out <file>] [--map <file>]
//
// Takes the output of `classify-cookies.mjs --emit-payloads` and strips every
// signal that could identify the cookie's VENDOR or the site, while preserving
// the complete graph-flow structure:
//   - cookie name        -> sha256(name)[0..12)
//   - cookie value       -> structural description only (segment classes/lengths,
//                           total entropy bits) — never the raw bytes, because
//                           value prefixes like "GA1.1." leak the vendor
//   - hosts / script URLs-> stable pseudonyms that preserve identity and the
//                           first/third-party relationship (SITE_MAIN, SITE_SUB_n,
//                           EXT_n) so "who set it / who read it" survives intact
//   - deterministic prior-> dropped (it would anchor the evaluator)
//
// Purpose: test whether the observed set/use flows ALONE are sufficient to assign
// TCF purposes, with no name- or vendor-recognition available. Also lets a third
// party reproduce an audit without being told which vendor is under review.

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const inPath = argv.find((a) => !a.startsWith("--") && a.endsWith(".json"));
if (!inPath) {
  process.stderr.write("usage: node analysis/blind-payloads.mjs <payloads.json> [--out <file>] [--map <file>]\n");
  process.exit(1);
}
const outPath = flag("--out", "/dev/stdout");
const mapPath = flag("--map", null);

const src = JSON.parse(readFileSync(inPath, "utf8"));
const hashName = (n) => createHash("sha256").update(n).digest("hex").slice(0, 12);

// ---- host pseudonymisation ---------------------------------------------------
const pageRegDomain = src.pageRegDomain;
const pageHost = (() => { try { return new URL(src.pageUrl).hostname; } catch { return null; } })();
const hostMap = new Map();
let subN = 0, extN = 0;
const pseudoHost = (host) => {
  if (!host) return null;
  if (hostMap.has(host)) return hostMap.get(host);
  let alias;
  if (host === pageHost) alias = "SITE_MAIN";
  else if (pageRegDomain && (host === pageRegDomain || host.endsWith("." + pageRegDomain))) alias = `SITE_SUB_${++subN}`;
  else alias = `EXT_${++extN}`;
  hostMap.set(host, alias);
  return alias;
};

// ---- value structure description --------------------------------------------
// Describe shape without revealing content. Segments split on common separators.
const classOf = (seg) => {
  if (/^\d+$/.test(seg)) return "digits";
  if (/^[a-f0-9]+$/i.test(seg) && seg.length >= 8) return "hex";
  if (/^[A-Za-z]+$/.test(seg)) return "alpha";
  if (/^[A-Za-z0-9]+$/.test(seg)) return "alnum";
  if (/^[A-Za-z0-9+/=_%-]+$/.test(seg)) return "b64ish";
  return "mixed";
};
const describeValue = (preview, bits) => {
  if (preview == null) return null;
  // the payload preview may be truncated with an "…(N chars)" marker
  const m = String(preview).match(/^(.*?)…\((\d+) chars\)$/);
  const body = m ? m[1] : String(preview);
  const trueLen = m ? Number(m[2]) : body.length;
  const segs = body.split(/[.$|:;,\-_]/).filter((s) => s.length > 0);
  return {
    length: trueLen,
    truncatedSample: !!m,
    totalEntropyBits: bits ?? null,
    segmentCount: segs.length,
    segments: segs.slice(0, 10).map((s) => `${classOf(s)}(${s.length})`),
    separatorsPresent: [...new Set((body.match(/[.$|:;,\-_%]/g) || []))],
    // a 10-digit segment is almost always a unix timestamp: worth flagging as it
    // indicates creation-time state, but it is not vendor-identifying.
    containsLikelyUnixTimestamp: segs.some((s) => /^\d{10}$/.test(s)),
  };
};

// ---- blind one cookie --------------------------------------------------------
const blindOne = (name, c) => ({
  cookieId: hashName(name),
  cookieDomainScope: c.domain === pageRegDomain || String(c.domain).endsWith(pageRegDomain) ? "same-site-as-page" : "different-site-from-page",
  party: c.party,
  valueStructure: describeValue(c.valuePreview, c.valueTotalEntropyBits ?? null),
  valueEntropyBitsPerChar: c.valueEntropyBitsPerChar,
  looksLikeIdentifier: c.looksLikeIdentifier,
  attributes: c.attributes,
  setChannel: c.setChannel,
  setBy: {
    viaSetCookieHeaderFrom: (c.httpSetters || []).map((s) => ({ host: pseudoHost(s.host), party: s.party })),
    viaScriptFrom: (c.jsWriteHosts || []).map((w) => ({ host: pseudoHost(w.host), party: w.party, source: w.source })),
  },
  usedAfterSet: {
    readByScript: c.readByJs,
    readerHosts: (c.readerHosts || []).map(pseudoHost),
    carriedOnRequestsTo: (c.httpTransmittedTo || []).map((t) => ({ host: pseudoHost(t.host), party: t.party, method: t.method })),
    requestCount: (c.httpTransmittedTo || []).length,
    valuePassedToJsSinks: c.consumerMethods || {},
    valueSentToNetworkByScript: c.jsExfilFired,
    scriptNetworkDestinations: (c.jsExfilDestinations || []).map((d) => ({ host: pseudoHost(d.host), party: d.party, method: d.method })),
  },
  crossesRegistrableDomainBoundary: (c.thirdPartyDestinations || []).length > 0,
  observedTransforms: c.transforms || [],
});

const cookies = {};
const nameMap = {};
for (const [name, c] of Object.entries(src.cookies)) {
  const b = blindOne(name, c);
  cookies[b.cookieId] = b;
  nameMap[b.cookieId] = name;
}

const out = {
  note: "BLINDED evidence from a PageGraph provenance graph of one real page load. Cookie names are SHA-256 hashed and values reduced to structure; hosts are pseudonymised (SITE_MAIN = the page's own host, SITE_SUB_n = another subdomain of the SAME registrable domain as the page, EXT_n = a different registrable domain). Classify from the observed set/use flows only.",
  siteContext: { pageHostAlias: "SITE_MAIN", distinctSameSiteSubdomains: subN, distinctExternalDomains: extN },
  cookies,
};
writeFileSync(outPath, JSON.stringify(out, null, 2));
if (mapPath) writeFileSync(mapPath, JSON.stringify({ nameMap, hostMap: Object.fromEntries(hostMap) }, null, 2));
process.stderr.write(`blinded ${Object.keys(cookies).length} cookie(s) → ${outPath}${mapPath ? ` (unblinding map → ${mapPath})` : ""}\n`);
