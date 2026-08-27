#!/usr/bin/env node
// decode-cookie-values.mjs — say what a cookie value actually CONTAINS.
//
// The pipeline records where a value travels but treats the value itself as an opaque blob.
// Much of it is not opaque: a large share of tracker cookies are structured, and the structure
// carries the privacy substance — a first-seen timestamp (which implies retention), a client IP,
// a screen fingerprint, a partner-sync ledger, or a consent decision. "This cookie carries a
// persistent id minted at 11:26:47 and the visitor's IP" is a finding; "opaque string" is not.
//
// STRICTLY DETERMINISTIC AND NON-CRYPTOGRAPHIC. Everything here is structural parsing: delimiter
// splits, URL-decoding, base64 with content sniffing, JSON, UUID version/timestamp fields, epoch
// scanning, and the published consent-string formats. No attempt is made — and none should be
// added — to recover plaintext from an encrypted or obfuscated value (PerimeterX `_px3`, Akamai,
// Cloudflare, AWS WAF, F5). Those are reported honestly as "opaque — contents not determinable",
// which is itself the correct compliance answer.
//
// Every decoded value carries a per-part verdict, so a half-decoded value (a hash joined to a
// cleartext id) reads as exactly that rather than as fully understood.
//
// Usage: node analysis/decode-cookie-values.mjs <crawl-dir> [--out <file>]

import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

// All structural parsing lives in lib/value-parts.mjs (extracted verbatim from here), so the same
// part machinery can also match individual value parts against outbound request bytes.
import {
  IPV4_ONLY, EMAIL_RE, tryUrlDecode, tryJson, epochs,
  decodeTcf, decodeOptanon, classifyPart, DELIMS,
} from "./lib/value-parts.mjs";

const dir = process.argv[2];
const flag = (n, d) => { const i = process.argv.indexOf(n); return i !== -1 ? process.argv[i + 1] : d; };
const outPath = flag("--out", null);
if (!dir) { process.stderr.write("usage: decode-cookie-values.mjs <crawl-dir> [--out <file>]\n"); process.exit(1); }

const jarFile = readdirSync(dir).find(f => f.endsWith(".cookies.json"));
if (!jarFile) { process.stderr.write("no .cookies.json in " + dir + "\n"); process.exit(1); }
const raw = JSON.parse(readFileSync(join(dir, jarFile), "utf8"));
const cookies = Array.isArray(raw) ? raw : (raw.cookies || []);

function decodeValue(name, value, cookie) {
  const out = { name, domain: cookie.domain, parts: [], fields: {}, flags: [] };
  const v = String(value ?? "");
  if (!v) { out.parts = [{ verdict: "empty", kind: "empty" }]; return out; }

  // 1. consent formats first — published, fully specified
  if (/OptanonConsent/i.test(name)) {
    out.format = "OneTrust OptanonConsent";
    out.fields = decodeOptanon(v);
    out.parts = [{ verdict: "decoded", kind: "key=value (URL-encoded)" }];
    if (out.fields.gpcContradiction) out.flags.push("GPC signal recorded but not applied");
    if (out.fields.consentId) out.flags.push("persistent consentId stored inside the consent cookie");
    return out;
  }
  if (/euconsent-v2$/i.test(name)) {
    out.format = "IAB TCF v2 consent string";
    const core = decodeTcf(v.split(".")[0]);
    out.fields = core || {};
    out.parts = [{ verdict: core ? "decoded" : "opaque", kind: "TCF core segment (bit-packed)" }];
    if (core && !core.purposesConsent.length) out.flags.push("no TCF purposes consented");
    return out;
  }
  if (/OTGPPConsent|gpp/i.test(name)) {
    out.format = "IAB GPP string";
    const head = v.split("~")[0];
    out.fields = { sections: v.split("~").length - 1, header: head.slice(0, 24) };
    out.parts = [{ verdict: "partial", kind: "GPP (header parsed; section bodies bit-packed)" }];
    return out;
  }

  // 2. structural: split on the delimiter that yields the most classifiable parts
  const urlDec = tryUrlDecode(v);
  const base = urlDec || v;
  if (tryJson(base)) { out.format = "JSON"; out.parts = [classifyPart(base)]; }
  else if (/^[\w.[\]%-]+=/.test(base) && base.includes("&")) {
    out.format = "key=value pairs";
    const kv = {};
    for (const pair of base.split("&").slice(0, 30)) { const i = pair.indexOf("="); if (i > 0) kv[pair.slice(0, i)] = pair.slice(i + 1).slice(0, 120); }
    out.fields = kv;
    out.parts = [{ verdict: "decoded", kind: "key=value" }];
  } else {
    let best = null;
    for (const d of DELIMS) {
      const segs = base.split(d);
      if (segs.length < 2 || segs.length > 12) continue;
      const cls = segs.map(classifyPart);
      const score = cls.filter(c => c.verdict === "decoded").length;
      if (!best || score > best.score) best = { d, segs, cls, score };
    }
    if (best && best.score > 0) { out.format = `delimited by "${best.d}"`; out.parts = best.cls; }
    else out.parts = [classifyPart(base)];
  }

  // 3. cross-cutting flags
  if (out.parts.some(p => p.kind === "IP address")
      || Object.values(out.fields || {}).some(v => typeof v === "string" && IPV4_ONLY.test(v.trim())))
    out.flags.push("carries an IP address in cleartext");
  if (EMAIL_RE.test(base)) out.flags.push("contains an email-shaped value");
  const allEpochs = out.parts.flatMap(p => p.epochs || []).concat(p0(out.fields));
  if (allEpochs.length) {
    out.timestamps = allEpochs.slice(0, 4);
    // retention stated INSIDE the value can outlast the cookie's own expiry
    const exp = cookie.expires && cookie.expires > 0 ? cookie.expires * 1000 : null;
    const far = allEpochs.map(e => Date.parse(e.iso)).filter(n => isFinite(n)).sort((a, b) => b - a)[0];
    if (exp && far && far > exp + 864e5) out.flags.push(`value states a date (${new Date(far).toISOString().slice(0, 10)}) beyond the cookie's own expiry (${new Date(exp).toISOString().slice(0, 10)})`);
  }
  const minted = out.parts.find(p => p.mintedAt);
  if (minted) out.flags.push(`identifier encodes its creation time (${minted.mintedAt})`);
  return out;
}
function p0(fields) { try { return epochs(JSON.stringify(fields || {})); } catch { return []; } }

// ---------- run ----------
const decoded = cookies.map(c => decodeValue(c.name, c.value, c));
// identifier replication: the same value under more than one cookie name
const byValue = new Map();
for (const c of cookies) { if (!c.value || c.value.length < 12) continue;
  if (!byValue.has(c.value)) byValue.set(c.value, []); byValue.get(c.value).push(c.name); }
const replicated = [...byValue.entries()].filter(([, names]) => new Set(names).size > 1)
  .map(([v, names]) => ({ value: v.slice(0, 40) + (v.length > 40 ? "…" : ""), names: [...new Set(names)] }));

const tally = { decoded: 0, partial: 0, opaque: 0, plain: 0, empty: 0 };
for (const d of decoded) { const v = d.parts.some(p => p.verdict === "decoded") ? "decoded"
  : d.parts.some(p => p.verdict === "partial") ? "partial"
  : d.parts.every(p => p.verdict === "opaque") ? "opaque"
  : d.parts.some(p => p.verdict === "empty") ? "empty" : "plain";
  d.overall = v; tally[v]++; }

const report = { crawlDir: dir, cookieCount: cookies.length, tally, replicatedIdentifiers: replicated, cookies: decoded };
if (outPath) writeFileSync(outPath, JSON.stringify(report, null, 2));

const site = dir.replace(/\/$/, "").split("/").pop();
console.log(`${site}: ${cookies.length} cookies — decoded ${tally.decoded}, partial ${tally.partial}, opaque ${tally.opaque}, literal ${tally.plain}`);
for (const d of decoded) if (d.flags.length) console.log(`   ${d.name}: ${d.flags.join(" · ")}`);
if (replicated.length) console.log(`   identifier reused across names: ${replicated.map(r => r.names.join("=")).slice(0, 4).join("  |  ")}`);
