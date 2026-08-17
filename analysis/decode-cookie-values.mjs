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

const dir = process.argv[2];
const flag = (n, d) => { const i = process.argv.indexOf(n); return i !== -1 ? process.argv[i + 1] : d; };
const outPath = flag("--out", null);
if (!dir) { process.stderr.write("usage: decode-cookie-values.mjs <crawl-dir> [--out <file>]\n"); process.exit(1); }

const jarFile = readdirSync(dir).find(f => f.endsWith(".cookies.json"));
if (!jarFile) { process.stderr.write("no .cookies.json in " + dir + "\n"); process.exit(1); }
const raw = JSON.parse(readFileSync(join(dir, jarFile), "utf8"));
const cookies = Array.isArray(raw) ? raw : (raw.cookies || []);

// ---------- primitives ----------
const NOW = Date.now();
const PLAUSIBLE_MIN = Date.parse("2000-01-01"), PLAUSIBLE_MAX = NOW + 20 * 365 * 864e5;
const isHex = s => /^[0-9a-f]+$/i.test(s);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// An IP is only claimed when a WHOLE value or a whole delimited part IS the address. Searching
// for the pattern anywhere inside a value produces false positives: Cloudflare's __cf_bm encodes
// a version marker "1.0.1.1" that matches an IPv4 regex perfectly and is not an IP at all.
const IPV4_ONLY = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

const tryUrlDecode = s => { try { const d = decodeURIComponent(s); return d !== s ? d : null; } catch { return null; } };
const tryJson = s => { try { const o = JSON.parse(s); return (o && typeof o === "object") ? o : null; } catch { return null; } };
const printableRatio = buf => { let p = 0; for (const b of buf) if (b >= 32 && b < 127) p++; return buf.length ? p / buf.length : 0; };
const tryBase64 = s => {
  if (!/^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(s)) return null;
  try {
    const buf = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    if (!buf.length) return null;
    const text = buf.toString("utf8");
    const j = tryJson(text);
    if (j) return { kind: "base64(JSON)", json: j };
    const gzip = buf[0] === 0x1f && buf[1] === 0x8b, zlib = buf[0] === 0x78;
    if (gzip || zlib) return { kind: `base64(${gzip ? "gzip" : "zlib"}) — compressed, not decompressed here` };
    const pr = printableRatio(buf);
    if (pr > 0.85) return { kind: "base64(text)", text: text.slice(0, 160) };
    return { kind: "base64(binary)", printableRatio: +pr.toFixed(2), bytes: buf.length };
  } catch { return null; }
};
// A UUID with its dashes stripped is still a UUID, and trackers write them that way (Microsoft
// UET's `_uetsid`/`_uetvid` are dashless v1s). Requiring dashes filed those as opaque, hiding a
// mint timestamp the value states outright.
//
// The dashless form is only claimed for **v1 with a plausible embedded clock**, and the asymmetry
// is deliberate. Bare 32-hex is also what an MD5 or a random id looks like: a random string carries
// the v4 version+variant nibbles about 1 in 64 times, which is far too often to assert "this is a
// UUID" — and a v4 has no timestamp, so the claim would add nothing anyway. A v1 must additionally
// decode to a date inside the plausible window, which random hex essentially never does. Strong
// evidence for the one version whose structure is worth reporting; silence for the rest.
const DASHLESS_HEX32 = /^[0-9a-f]{32}$/i;
const withDashes = h =>
  `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
const uuidInfo = u => {
  if (!UUID_RE.test(u)) {
    if (!DASHLESS_HEX32.test(u)) return null;
    const candidate = withDashes(u);
    // Only a v1 whose clock decodes plausibly clears the bar; uuidInfo re-derives that below,
    // so probe it here and bail on anything else.
    const probe = uuidInfo(candidate);
    if (!probe || probe.uuidVersion !== 1 || probe.mintedAt === undefined) return null;
    return { ...probe, dashless: true };
  }
  const p = u.split("-"), ver = parseInt(p[2][0], 16);
  const info = { uuidVersion: ver };
  if (ver === 1) {
    try {
      const ticks = BigInt("0x" + p[2].slice(1) + p[1] + p[0]);
      const ms = Number(ticks / 10000n) - 12219292800000;
      if (ms > PLAUSIBLE_MIN && ms < PLAUSIBLE_MAX) {
        info.mintedAt = new Date(ms).toISOString();
        info.note = "UUID v1 embeds its creation time — the identifier states when the visitor was first seen";
      }
    } catch { /* not decodable */ }
  }
  return info;
};
// epoch seconds/ms appearing anywhere in the value
const epochs = s => {
  const out = [];
  for (const m of String(s).matchAll(/\b(\d{10}|\d{13})\b/g)) {
    const n = Number(m[1]);
    const ms = m[1].length === 13 ? n : n * 1000;
    if (ms > PLAUSIBLE_MIN && ms < PLAUSIBLE_MAX) out.push({ raw: m[1], iso: new Date(ms).toISOString() });
    if (out.length >= 6) break;
  }
  return out;
};

// ---------- consent strings (published formats) ----------
function decodeTcf(core) {
  try {
    const b64 = core.replace(/-/g, "+").replace(/_/g, "/");
    const buf = Buffer.from(b64 + "=".repeat((4 - b64.length % 4) % 4), "base64");
    let bit = 0;
    const rd = n => { let v = 0; for (let i = 0; i < n; i++) { const byte = buf[bit >> 3]; if (byte === undefined) return v; v = (v * 2) + ((byte >> (7 - (bit & 7))) & 1); bit++; } return v; };
    const version = rd(6), created = rd(36), updated = rd(36);
    const cmpId = rd(12), cmpVersion = rd(12); rd(6);
    const lang = String.fromCharCode(65 + rd(6)) + String.fromCharCode(65 + rd(6));
    const vendorListVersion = rd(12), tcfPolicyVersion = rd(6); rd(1); rd(1);
    const specialFeatureOptIns = []; for (let i = 1; i <= 12; i++) if (rd(1)) specialFeatureOptIns.push(i);
    const purposesConsent = []; for (let i = 1; i <= 24; i++) if (rd(1)) purposesConsent.push(i);
    const purposesLegitimateInterest = []; for (let i = 1; i <= 24; i++) if (rd(1)) purposesLegitimateInterest.push(i);
    return { version, created: new Date(created * 100).toISOString(), lastUpdated: new Date(updated * 100).toISOString(),
      cmpId, cmpVersion, language: lang, vendorListVersion, tcfPolicyVersion,
      specialFeatureOptIns, purposesConsent, purposesLegitimateInterest };
  } catch { return null; }
}
function decodeOptanon(value) {
  const q = tryUrlDecode(value) || value;
  const pick = re => (q.match(re) || [])[1] || null;
  const groups = pick(/groups=([^&]*)/);
  const parsed = groups ? groups.split(",").filter(Boolean).map(g => { const [id, v] = g.split(":"); return { group: id, consented: v === "1" }; }) : [];
  const isGpc = pick(/isGpcEnabled=(\d)/), browserGpc = pick(/browserGpcFlag=(\d)/);
  const out = {
    consentId: pick(/consentId=([0-9a-f-]{36})/),
    datestamp: pick(/datestamp=([^&]*)/),
    groups: parsed,
    consentedGroups: parsed.filter(g => g.consented).length,
    deniedGroups: parsed.filter(g => !g.consented).length,
    isGpcEnabled: isGpc, browserGpcFlag: browserGpc,
  };
  // The CMP recorded that the browser sent Global Privacy Control, yet stored the signal as off.
  if (browserGpc === "1" && isGpc === "0") {
    out.gpcContradiction = "the browser sent Global Privacy Control (browserGpcFlag=1) but the CMP recorded isGpcEnabled=0";
  }
  return out;
}

// ---------- part classification ----------
function classifyPart(part) {
  const p = String(part);
  const dec = tryUrlDecode(p);
  const s = dec || p;
  const j = tryJson(s);
  if (j) return { verdict: "decoded", kind: "JSON", json: j, epochs: epochs(s) };
  const u = uuidInfo(s);
  if (u) return { verdict: "decoded", kind: "UUID", ...u };
  if (IPV4_ONLY.test(s.trim())) return { verdict: "decoded", kind: "IP address", value: s.trim(), sensitive: "client IP in cleartext" };
  if (/^\d{10}$|^\d{13}$/.test(s)) { const e = epochs(s); if (e.length) return { verdict: "decoded", kind: "timestamp", ...e[0] }; }
  if (isHex(s) && (s.length === 32 || s.length === 40 || s.length === 64)) {
    return { verdict: "opaque", kind: `${s.length * 4}-bit hex digest`, note: "digest or random id — contents not determinable without the original input" };
  }
  const b = tryBase64(s);
  if (b) return { verdict: b.kind.includes("binary") || b.kind.includes("compressed") ? "opaque" : "decoded", ...b, epochs: b.json ? epochs(JSON.stringify(b.json)) : [] };
  const e = epochs(s);
  if (e.length) return { verdict: "partial", kind: "text with embedded timestamp(s)", text: s.slice(0, 80), epochs: e };
  if (/^[A-Za-z0-9._~-]{40,}$/.test(s)) return { verdict: "opaque", kind: "high-entropy token", note: "contents not determinable" };
  return { verdict: "plain", kind: "literal", text: s.slice(0, 80) };
}

const DELIMS = [":", "|", "~", "!", "."];
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
