#!/usr/bin/env node
// cookie-headers.mjs — find cookie values inside REQUEST/RESPONSE HEADERS and URLs.
//
//   node analysis/cookie-headers.mjs <graphml> [cookieName] [--json] [--min-len N]
//
// Closes a real gap in the other analysis tools: `cookie-reads.mjs` / `cookie-flow.mjs`
// only see a value when it is passed as a `js call` ARGUMENT, and `.cookie-network.json`
// only reports the automatic `Cookie:` header. Neither notices a value that a script
// copied into a URL query string, a `Referer`, or a custom `X-*` header — a very common
// exfiltration path (e.g. `?cid=<clientId>`, `&uid=<id>`).
//
// The crawler's rewriter stitches a `headers` attribute (JSON `[{name,value}]`) onto
// request/response edges. That blob also carries HTTP/2 pseudo-headers, so `:path`
// gives the full path+query — which is how URL-parameter leaks are detected here.
//
// Hits are classified:
//   channel "cookie-header"  — value in `Cookie:`/`Set-Cookie:` (EXPECTED automatic carriage)
//   channel "url"            — value in `:path` or a `*-url`/`referer` header (URL LEAK)
//   channel "other-header"   — value in any other header (custom/auth header LEAK)
// Only the latter two are new evidence; they are reported as `notable`.
//
// Values are matched raw, URL-encoded, and double-encoded, since scripts routinely
// encodeURIComponent a value before appending it to a query string.

import { readFileSync, existsSync } from "node:fs";
import { graphBase, graphStream, readPageUrl } from "./lib/graph-source.mjs";

const argv = process.argv.slice(2);
const flagVal = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const asJson = argv.includes("--json");
const MIN_LEN = parseInt(flagVal("--min-len", "8"), 10);
// Length alone is NOT a sufficient guard against collisions. A low-entropy value
// ("1", "true", "national", "en-US") is long enough to pass MIN_LEN yet occurs
// naturally in page HTML and query strings, so it "matches" everywhere and
// fabricates exfiltration evidence — which then drives a false Advertising label.
// Require enough total entropy for the value to be plausibly identifying.
const MIN_BITS = parseInt(flagVal("--min-bits", "30"), 10);
const skip = new Set(["--min-len", flagVal("--min-len", "8"), "--min-bits", flagVal("--min-bits", "30")]);
const positional = argv.filter((a) => !a.startsWith("--") && !skip.has(a));
const graphmlPath = positional[0];
const onlyCookie = positional[1] || null;
if (!graphmlPath) {
  process.stderr.write("usage: node analysis/cookie-headers.mjs <graphml> [cookieName] [--json] [--min-len N]\n");
  process.exit(1);
}

const unescapeXml = (s) => s == null ? null : s
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
  .replace(/&#39;/g, "'").replace(/&amp;/g, "&");

async function* streamElements(path) {
  const stream = graphStream(path);
  let buf = "";
  const openRe = /<(node|edge|key)\b/g;
  for await (const chunk of stream) {
    buf += chunk;
    let consumedTo = 0;
    openRe.lastIndex = 0;
    let m;
    while ((m = openRe.exec(buf)) !== null) {
      const tag = m[1];
      const start = m.index;
      const closeTag = `</${tag}>`;
      let end = buf.indexOf(closeTag, openRe.lastIndex);
      let after;
      if (end !== -1) after = end + closeTag.length;
      else {
        const selfClose = buf.indexOf("/>", openRe.lastIndex);
        const nextOpen = buf.indexOf("<", openRe.lastIndex);
        if (selfClose !== -1 && (nextOpen === -1 || selfClose < nextOpen)) { after = selfClose + 2; end = -2; }
        else break;
      }
      const raw = buf.slice(start, after);
      const headEnd = raw.indexOf(">");
      yield { tag, head: raw.slice(0, headEnd), body: end === -2 ? "" : raw.slice(headEnd + 1, raw.length - closeTag.length) };
      consumedTo = after;
      openRe.lastIndex = after;
    }
    buf = buf.slice(consumedTo);
  }
}

const keysByFor = { edge: {}, node: {} };
const attrId = (head) => {
  const f = head.match(/for="(edge|node)"/);
  const nm = head.match(/attr\.name="([^"]*)"/);
  const id = head.match(/id="(d\d+)"/);
  if (f && nm && id) keysByFor[f[1]][nm[1]] = id[1];
};
const mk = (kind) => (body, name) => {
  const kid = keysByFor[kind][name];
  if (!kid || body == null) return null;
  const m = body.match(new RegExp(`key="${kid}">([\\s\\S]*?)</data>`));
  return m ? unescapeXml(m[1]) : null;
};
const eAttr = mk("edge");
const nAttr = mk("node");
const idOf = (head) => (head.match(/id="(n\d+)"/) || [])[1];
const endpoints = (head) => [(head.match(/source="(n\d+)"/) || [])[1], (head.match(/target="(n\d+)"/) || [])[1]];
const unwrap = (v) => {
  if (v == null) return v;
  if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') {
    try { const p = JSON.parse(v); if (typeof p === "string") return p; } catch { return v.slice(1, -1); }
  }
  return v;
};
// A `storage set` edge records the WHOLE `document.cookie` assignment, attributes
// included: `document.cookie = "n=v; path=/; domain=.x.com"` yields the value
// `v; path=/; domain=.x.com`. Using that verbatim is a correctness bug: the shared
// `; path=/; domain=…` boilerplate matches `referer`/`:path` on every request, so two
// unrelated cookies fabricate identical exfiltration evidence. A cookie value cannot
// contain an unencoded ";" (it is the delimiter), so truncating there is always safe.
const cookieValueOnly = (v) => (v == null ? v : String(v).split(";")[0].trim());

const parseJar = (s) => {
  const out = [];
  if (!s) return out;
  for (const pair of s.split(";")) {
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (name) out.push([name, value]);
  }
  return out;
};

// ---------------------------------------------------------------------------
// Seed cookie values. `.cookies.json` is authoritative (includes httpOnly cookies
// the graph's JS-visible jar reads never expose); the graph's own jar edges add
// values that existed only transiently during the crawl.
// ---------------------------------------------------------------------------
const pageUrl = await readPageUrl(graphmlPath);
const base = graphBase(graphmlPath);
const cookieValues = new Map(); // name -> Set(value)
const addVal = (name, v) => {
  if (!name || !v || v.length < MIN_LEN) return;
  let s = cookieValues.get(name);
  if (!s) cookieValues.set(name, (s = new Set()));
  s.add(v);
};
if (existsSync(`${base}.cookies.json`)) {
  try {
    for (const c of JSON.parse(readFileSync(`${base}.cookies.json`, "utf8"))) addVal(c.name, c.value);
  } catch { /* fall back to graph-only values */ }
}

let cookieJarId = null;
const resourceUrl = new Map();
const resourceHost = new Map();
const pending = []; // edges with headers, held until node maps are complete

for await (const el of streamElements(graphmlPath)) {
  if (el.tag === "key") { attrId(el.head); continue; }
  if (el.tag === "node") {
    const id = idOf(el.head);
    const type = nAttr(el.body, "node type");
    if (type === "cookie jar") cookieJarId = id;
    else if (type === "resource") { resourceUrl.set(id, nAttr(el.body, "url")); resourceHost.set(id, nAttr(el.body, "host")); }
    continue;
  }
  const et = eAttr(el.body, "edge type");
  if (!et) continue;
  const [s, t] = endpoints(el.head);
  if (et === "storage read result" && s === cookieJarId) {
    for (const [n, v] of parseJar(unwrap(eAttr(el.body, "value")))) addVal(n, v);
  } else if (et === "storage set" && t === cookieJarId) {
    addVal(eAttr(el.body, "key"), cookieValueOnly(unwrap(eAttr(el.body, "value"))));
  }
  const headers = eAttr(el.body, "headers");
  if (headers) {
    pending.push({ et, s, t, headers, requestId: eAttr(el.body, "request id") });
  }
}

// ---------------------------------------------------------------------------
// Scan the collected header blobs for cookie values.
// ---------------------------------------------------------------------------
const encodings = (v) => {
  const out = new Set([v]);
  try { out.add(encodeURIComponent(v)); } catch { /* ignore */ }
  try { out.add(encodeURIComponent(encodeURIComponent(v))); } catch { /* ignore */ }
  return [...out];
};

// Vendors routinely transmit a PREFIX-STRIPPED fragment of the cookie rather than
// the whole value: `_ga=GA1.1.47641089.1783130340` is sent as `cid=47641089.1783130340`.
// Full-value matching alone therefore produces false negatives. So also index
// separator-delimited SUFFIXES of the value, but require >=2 remaining segments and
// >=12 chars — that keeps the real identifier fragment while rejecting a bare
// 10-digit trailing timestamp, which would otherwise match every cache-buster URL.
const fragmentsOf = (v) => {
  const segs = v.split(/[.|:_-]/).filter(Boolean);
  const out = [];
  for (let i = 1; i < segs.length - 1; i++) {
    const frag = segs.slice(i).join(".");
    if (frag.length >= 12) out.push(frag);
  }
  return out;
};

// variant -> { names:Set, matchType }
const valueIndex = new Map();
const indexVariant = (variant, name, matchType) => {
  if (!variant || variant.length < MIN_LEN) return;
  let e = valueIndex.get(variant);
  if (!e) valueIndex.set(variant, (e = { names: new Set(), matchType }));
  e.names.add(name);
  if (matchType === "full") e.matchType = "full"; // full match wins over fragment
};
// Shannon entropy x length = total bits. Values below MIN_BITS cannot plausibly
// identify a user and DO collide with ordinary page text, so they are never indexed.
const totalBits = (s) => {
  if (!s) return 0;
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const c of freq.values()) { const p = c / s.length; h -= p * Math.log2(p); }
  return h * s.length;
};

// Some cookies store a HOSTNAME or URL as their value — Hotjar's `_hjTLDTest` writes
// the domain to probe cookie scope; Shopify's `_up_shop` stores the shop host. Those
// strings have plenty of entropy but appear structurally in `referer`/`:path` on every
// request, so matching them fabricates exfiltration. Excluded by SHAPE, not entropy.
const looksLikeHostOrUrl = (v) => /^https?:\/\//i.test(v) || /^\.?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\.?$/i.test(v);

// The page's own origin/host, so a match that is merely part of the page URL is not
// treated as the cookie's identity leaking.
const pageHostStr = (() => { try { return new URL(pageUrl).hostname; } catch { return null; } })();

const excluded = [];
for (const [name, vals] of cookieValues) {
  if (onlyCookie && name !== onlyCookie) continue;
  for (const v of vals) {
    if (looksLikeHostOrUrl(v)) {
      excluded.push({ cookie: name, reason: "value is a hostname/URL (structural, collides with referer/:path)", value: v.slice(0, 60) });
      continue;
    }
    if (pageHostStr && (pageHostStr.includes(v) || v.includes(pageHostStr))) {
      excluded.push({ cookie: name, reason: "value overlaps the page's own host", value: v.slice(0, 60) });
      continue;
    }
    if (totalBits(v) < MIN_BITS) {
      excluded.push({ cookie: name, reason: `only ${Math.round(totalBits(v))} bits of entropy — not identifying, collides with page text`, value: v.slice(0, 60) });
      continue; // e.g. "1", "true", "en-US"
    }
    for (const enc of encodings(v)) indexVariant(enc, name, "full");
    for (const frag of fragmentsOf(v)) {
      if (totalBits(frag) < MIN_BITS) continue;
      for (const enc of encodings(frag)) indexVariant(enc, name, "fragment");
    }
  }
}
const variants = [...valueIndex.keys()];

// HTTP/2 pseudo-headers that carry request STRUCTURE, not payload. Matching against
// them produces false positives (`:authority` is just a hostname, so any cookie whose
// value embeds a domain "matches" every request to that host). Never scanned.
// `origin` is always exactly scheme://host with no payload capacity, so it can never
// legitimately carry a cookie value — matching it only ever produces collisions.
const STRUCTURAL_HEADERS = new Set([":authority", ":scheme", ":method", "host", "origin"]);

const classifyHeader = (name) => {
  const n = String(name).toLowerCase();
  if (STRUCTURAL_HEADERS.has(n)) return "skip";
  if (n === "cookie" || n === "set-cookie") return "cookie-header";
  if (n === ":path" || n === "referer" || n === "referrer" || /(^|-)url$/.test(n)) return "url";
  return "other-header";
};

// Reconstruct the request URL from the header blob itself (`:authority` + `:path`),
// which is more reliable than resolving the edge's resource node.
const urlFromHeaders = (arr) => {
  let authority = null, path = null;
  for (const h of arr) {
    const n = String(h?.name).toLowerCase();
    if (n === ":authority") authority = h.value;
    else if (n === ":path") path = h.value;
  }
  if (!authority) return { host: null, url: null };
  return { host: authority, url: path ? `https://${authority}${path}` : `https://${authority}` };
};

const results = new Map(); // cookie -> { cookieHeaderRequests, notable:[], urlHits, otherHeaderHits }
const recOf = (name) => {
  let r = results.get(name);
  if (!r) results.set(name, (r = { cookieHeaderRequests: 0, urlHits: 0, otherHeaderHits: 0, notable: [] }));
  return r;
};
const seenNotable = new Set();

for (const p of pending) {
  let arr;
  try { arr = JSON.parse(p.headers); } catch { continue; }
  if (!Array.isArray(arr)) continue;
  const isResponse = p.et === "request complete" || p.et === "request error";
  // the resource endpoint carries the URL; for request edges it's the target
  const resNode = isResponse ? p.s : p.t;
  const fromHdr = urlFromHeaders(arr);
  const url = fromHdr.url || resourceUrl.get(resNode) || resourceUrl.get(p.s) || resourceUrl.get(p.t) || null;
  const host = fromHdr.host || resourceHost.get(resNode) || resourceHost.get(p.s) || resourceHost.get(p.t) || null;
  for (const h of arr) {
    const hval = h && typeof h.value === "string" ? h.value : null;
    if (!hval || hval.length < MIN_LEN) continue;
    const channel = classifyHeader(h.name);
    if (channel === "skip") continue;
    for (const variant of variants) {
      if (!hval.includes(variant)) continue;
      const { names: hitNames, matchType } = valueIndex.get(variant);
      for (const name of hitNames) {
        const r = recOf(name);
        if (channel === "cookie-header") { r.cookieHeaderRequests++; continue; }
        if (channel === "url") r.urlHits++; else r.otherHeaderHits++;
        const idx = hval.indexOf(variant);
        const sig = `${name}|${channel}|${h.name}|${host}|${idx}`;
        if (seenNotable.has(sig)) continue;
        seenNotable.add(sig);
        r.notable.push({
          channel,
          header: h.name,
          direction: isResponse ? "response" : "request",
          host,
          url: url ? String(url).slice(0, 300) : null,
          requestId: p.requestId,
          matchType, // "full" = whole cookie value; "fragment" = prefix-stripped identifier
          snippet: hval.slice(Math.max(0, idx - 40), idx + variant.length + 40),
        });
      }
    }
  }
}

const names = [...results.keys()].sort();
const out = {
  pageUrl,
  headerBlobsScanned: pending.length,
  cookiesWithValues: cookieValues.size,
  // Reported, never silent: these cookies were EXCLUDED from matching because their
  // value carries too little entropy to be identifying. Absence of hits for them is
  // "not measurable", not "no exfiltration".
  excluded,
  minBits: MIN_BITS,
  cookies: Object.fromEntries(names.map((n) => [n, results.get(n)])),
};

if (asJson || onlyCookie) {
  process.stdout.write(JSON.stringify(onlyCookie ? (out.cookies[onlyCookie] ?? { cookieHeaderRequests: 0, urlHits: 0, otherHeaderHits: 0, notable: [] }) : out, null, 2) + "\n");
} else {
  process.stdout.write(`page: ${pageUrl}\nheader blobs scanned: ${pending.length}; cookies with values: ${cookieValues.size}\n\n`);
  if (names.length === 0) process.stdout.write("no cookie values found in any header.\n");
  for (const n of names) {
    const r = results.get(n);
    const tag = r.notable.length ? "  ** NOTABLE **" : "";
    process.stdout.write(`${n}: Cookie-header carriage=${r.cookieHeaderRequests}, urlHits=${r.urlHits}, otherHeaderHits=${r.otherHeaderHits}${tag}\n`);
    for (const h of r.notable.slice(0, 6)) {
      process.stdout.write(`    [${h.channel}] ${h.direction} ${h.header} -> ${h.host}\n        ${h.snippet.replace(/\n/g, " ")}\n`);
    }
  }
}
