// value-parts.mjs — deterministic decomposition of a cookie VALUE into named, classified parts.
//
// Extracted verbatim from decode-cookie-values.mjs so the same structural parsing that powers the
// value report can also answer a different question: WHICH PART of a value left the page. A cookie
// like OptanonConsent is mostly benign consent state plus one persistent identifier (`consentId`);
// telling those parts apart — and matching them individually against outbound request bytes — is
// what lets the pipeline distinguish "consent state propagated" from "identifier exfiltrated".
//
// STRICTLY DETERMINISTIC AND NON-CRYPTOGRAPHIC (same contract as decode-cookie-values.mjs): no
// attempt is made to recover plaintext from encrypted/obfuscated values; those classify as opaque.

// ---------- primitives ----------
const NOW = Date.now();
const PLAUSIBLE_MIN = Date.parse("2000-01-01"), PLAUSIBLE_MAX = NOW + 20 * 365 * 864e5;
export const isHex = s => /^[0-9a-f]+$/i.test(s);
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// An IP is only claimed when a WHOLE value or a whole delimited part IS the address. Searching
// for the pattern anywhere inside a value produces false positives: Cloudflare's __cf_bm encodes
// a version marker "1.0.1.1" that matches an IPv4 regex perfectly and is not an IP at all.
export const IPV4_ONLY = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
export const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

export const tryUrlDecode = s => { try { const d = decodeURIComponent(s); return d !== s ? d : null; } catch { return null; } };
export const tryJson = s => { try { const o = JSON.parse(s); return (o && typeof o === "object") ? o : null; } catch { return null; } };
const printableRatio = buf => { let p = 0; for (const b of buf) if (b >= 32 && b < 127) p++; return buf.length ? p / buf.length : 0; };
export const tryBase64 = s => {
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
export const uuidInfo = u => {
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
export const epochs = s => {
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
export function decodeTcf(core) {
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
export function decodeOptanon(value) {
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
export function classifyPart(part) {
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

export const DELIMS = [":", "|", "~", "!", "."];

// ---------- named decomposition (new — feeds outbound-value matching) ----------
//
// namedParts(name, value) -> [{ key, text, kind, isIdentifier, volatile }]
//
// `key` names the part (`consentId`, or `part[2]` for positional splits), `text` is the RAW bytes
// of the part exactly as they sit inside the stored value (so a substring search against request
// bytes works), `kind` is classifyPart's structural kind, and the two booleans drive matching:
//   isIdentifier — identifier-grade: stable, high-entropy, user-linkable. These are the parts whose
//     appearance in an outbound request means the request can identify the visitor.
//   volatile — a timestamp-like part that legitimately differs between snapshots of the same
//     cookie. Volatile parts are stable-identifier matching's complement: an outbound copy of an
//     EARLIER snapshot of the value keeps its identifier parts verbatim while its volatile parts
//     drift, which is exactly why matching must be per-part rather than whole-value.

const IDENTIFIER_KINDS = new Set(["UUID", "IP address", "high-entropy token"]);
const identifierGrade = (cls, text) => {
  if (IDENTIFIER_KINDS.has(cls.kind)) return true;
  if (/hex digest$/.test(cls.kind || "")) return true;           // 128/160/256-bit hex
  if (EMAIL_RE.test(text) && text.length <= 254) return true;    // email-shaped part
  return false;
};
const volatileGrade = (cls, key) => {
  if (cls.kind === "timestamp" || cls.kind === "text with embedded timestamp(s)") return true;
  if (key && /(^|[_-])(date|time|ts|stamp|expires?)([_-]|$)|datestamp|timestamp/i.test(key)) return true;
  return false;
};

const mkPart = (key, text) => {
  const cls = classifyPart(text);
  return {
    key,
    text,
    kind: cls.kind,
    isIdentifier: identifierGrade(cls, text),
    volatile: volatileGrade(cls, key),
  };
};

export function namedParts(name, value) {
  const v = String(value ?? "");
  if (!v) return [];

  // k=v pairs (OptanonConsent and friends): keys come for free, and the part text is the RAW
  // (still-encoded) right-hand side so it substring-matches request bytes as stored.
  if (/^[\w.[\]%-]+=/.test(v) && v.includes("&")) {
    const parts = [];
    for (const pair of v.split("&").slice(0, 40)) {
      const i = pair.indexOf("=");
      if (i <= 0) continue;
      const key = pair.slice(0, i), text = pair.slice(i + 1);
      if (!text) continue;
      parts.push(mkPart(key, text));
    }
    if (parts.length) return parts;
  }

  // positional: split on the delimiter that yields the most classifiable parts (same heuristic
  // as decode-cookie-values.mjs decodeValue).
  let best = null;
  for (const d of DELIMS) {
    const segs = v.split(d);
    if (segs.length < 2 || segs.length > 12) continue;
    const cls = segs.map(classifyPart);
    const score = cls.filter(c => c.verdict === "decoded").length;
    if (!best || score > best.score) best = { d, segs, cls, score };
  }
  if (best && best.score > 0) {
    return best.segs.map((seg, i) => mkPart(`part[${i}]`, seg)).filter(p => p.text !== "");
  }

  // single-part value: the whole value is one part.
  return [mkPart("value", v)];
}

// Identifier parts long enough to be collision-safe substring needles. 16 chars of an
// identifier-grade token essentially never appears in unrelated request bytes by chance;
// shorter parts (an 8-char id) would match too much to be evidence.
export function identifierNeedles(parts, minLen = 16) {
  const seen = new Set();
  const out = [];
  for (const p of parts) {
    if (!p.isIdentifier || p.text.length < minLen) continue;
    if (seen.has(p.text)) continue;
    seen.add(p.text);
    out.push(p);
  }
  return out;
}
