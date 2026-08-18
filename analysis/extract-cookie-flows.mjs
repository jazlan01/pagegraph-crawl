#!/usr/bin/env node
// extract-cookie-flows.mjs — pull the COMPLETE flow for every stored item in ONE go.
//
//   node analysis/extract-cookie-flows.mjs <graphml> --out <dir> [--min-bits 30]
//
// Covers all three client-side storage buckets, not just cookies: the cookie jar,
// localStorage and sessionStorage. Trackers increasingly prefer localStorage precisely
// because cookie-only audits do not look at it, and the graph records all three
// identically (a `storage` node with a `storage bucket` edge to each). Treating cookies
// as the whole picture answers the wrong question.
//
// One useful asymmetry: `document.cookie` reads return the WHOLE jar, so the read edge
// alone cannot say WHICH cookie the script wanted. localStorage reads name their key, so
// they are exact. The jar case is recoverable anyway: the script that reads the jar
// almost always parses it for a specific name on the spot —
// `match(/_ga=([^;]+)/)`, `split(';').find(c => c.startsWith('_gcl_au='))` — and the
// edge carries the byte offset of the read while the script node carries the full
// source. Reading the code AT that offset recovers the intended cookie, which turns a
// jar-wide read back into per-cookie evidence. See `readIntent` in each flow file.
//
// Replaces the per-cookie tools for bulk work. Two motivations:
//
// 1. COST. `cookie-code-trace.mjs` re-streams the whole graph per cookie. On a
//    66-cookie, 1.5 GB crawl that is 66 full passes (~100 GB of I/O) and it is why
//    a parallel run saturated the machine. This does two passes total, whatever the
//    cookie count, and writes results to disk for offline reading.
//
// 2. COMPLETENESS. Every other tool here first decides which edge types "matter"
//    (`storage set`, `js call`, …) and discards the rest. On themeisle that filter
//    throws away 24,030 of 28,302 edges — including 766 stack traces and 8,082
//    `set attribute` edges. `img.src = "https://tracker/?id=<cookie>"` is an
//    exfiltration, and it is recorded as `set attribute`, NOT as a `js call`, so the
//    old filter could not see that channel at all. Here there is NO type filter:
//    every edge of every type is searched for the cookie's value.
//
// Pass 1  nodes (all types, all attrs) + cookie values from the jar
// Pass 2  every edge of every type; keep those carrying a value, plus the structural
//         edges (jar ops / execute / request) needed to attribute them
//
// Output: <dir>/_scripts.json, <dir>/_src/<node>.js (full source, once each),
//         <dir>/_summary.json, <dir>/flows/<cookie>.json (every edge touching it).

import { mkdirSync, writeFileSync } from "node:fs";
import { graphStream, isGraphPath, readPageUrl } from "./lib/graph-source.mjs";
import { join } from "node:path";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const graphmlPath = argv.find(a => !a.startsWith("--") && isGraphPath(a));
const OUT = flag("--out", null);
const MIN_BITS = parseInt(flag("--min-bits", "30"), 10);
if (!graphmlPath || !OUT) {
  process.stderr.write("usage: node analysis/extract-cookie-flows.mjs <graphml> --out <dir> [--min-bits 30]\n");
  process.exit(1);
}

const un = s => s == null ? null : s
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
  .replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, "&");

async function* stream(path, want) {
  const st = graphStream(path);
  let buf = "";
  const open = new RegExp(`<(${want.join("|")})\\b`, "g");
  for await (const chunk of st) {
    buf += chunk;
    let consumed = 0; open.lastIndex = 0; let m;
    while ((m = open.exec(buf)) !== null) {
      const tag = m[1], start = m.index, close = `</${tag}>`;
      let end = buf.indexOf(close, open.lastIndex), after;
      if (end !== -1) after = end + close.length;
      else {
        const sc = buf.indexOf("/>", open.lastIndex), no = buf.indexOf("<", open.lastIndex);
        if (sc !== -1 && (no === -1 || sc < no)) { after = sc + 2; end = -2; }
        else break;
      }
      const raw = buf.slice(start, after), he = raw.indexOf(">");
      yield { tag, head: raw.slice(0, he), body: end === -2 ? "" : raw.slice(he + 1, raw.length - close.length) };
      consumed = after; open.lastIndex = after;
    }
    // Bound the carry buffer. Elements we are not interested in never match, so
    // `consumed` can stay at 0 while megabytes of them stream past — the buffer then
    // grows until it exceeds V8's maximum string length and the process dies. Keep only
    // from the earliest unconsumed opening tag (an element may legitimately span chunks
    // and be large); if there is no opening tag at all, keep just enough to catch a tag
    // split across the boundary.
    buf = buf.slice(consumed);
    if (buf.length > 1 << 20) {
      open.lastIndex = 0;
      const nxt = open.exec(buf);
      buf = nxt ? buf.slice(nxt.index) : buf.slice(-64);
    }
  }
}

const K = { edge: {}, node: {} };
const key = h => { const f = h.match(/for="(edge|node)"/), n = h.match(/attr\.name="([^"]*)"/), i = h.match(/id="(d\d+)"/); if (f && n && i) K[f[1]][n[1]] = i[1]; };
const A = kind => (body, name) => {
  const id = K[kind][name]; if (!id || body == null) return null;
  const m = body.match(new RegExp(`key="${id}">([\\s\\S]*?)</data>`));
  return m ? un(m[1]) : null;
};
const eA = A("edge"), nA = A("node");
// every attribute present on an element, so nothing is silently dropped
const allAttrs = (kind, body) => {
  const o = {};
  for (const name of Object.keys(K[kind])) { const v = A(kind)(body, name); if (v != null) o[name] = v; }
  return o;
};
const idOf = h => (h.match(/id="(n\d+)"/) || [])[1];
const eid = h => (h.match(/id="(e\d+)"/) || [])[1];
const ends = h => [(h.match(/source="(n\d+)"/) || [])[1], (h.match(/target="(n\d+)"/) || [])[1]];
const unwrap = v => {
  if (v == null) return v;
  if (v.length >= 2 && v[0] === '"' && v.at(-1) === '"') {
    try { const p = JSON.parse(v); if (typeof p === "string") return p; } catch { return v.slice(1, -1); }
  }
  return v;
};
const valOnly = v => v == null ? v : String(v).split(";")[0].trim();
const parseJar = s => { const o = []; if (!s) return o;
  for (const p of s.split(";")) { const e = p.indexOf("="); if (e === -1) continue;
    const n = p.slice(0, e).trim(), v = p.slice(e + 1).trim(); if (n) o.push([n, v]); } return o; };
const bits = s => { if (!s) return 0; const f = new Map();
  for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let h = 0; for (const c of f.values()) { const p = c / s.length; h -= p * Math.log2(p); } return h * s.length; };
const isHostish = v => /^https?:\/\//i.test(v) || /^\.?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\.?$/i.test(v);

// ===================== PASS 1: nodes + cookie values =====================
const t0 = Date.now();
const pageUrl = await readPageUrl(graphmlPath);
let jar = null;
const bucketOf = new Map();  // storage node id -> "cookie" | "localStorage" | "sessionStorage"
const nodes = new Map();     // id -> attrs (source stripped out, kept separately)
const srcOf = new Map();     // id -> full source text
const byV8 = new Map();      // V8 scriptId -> node id
const cookieVals = new Map();// cookie -> Set(values)

process.stderr.write(`[1/2] nodes + cookie values … `);
for await (const el of stream(graphmlPath, ["key", "node"])) {
  if (el.tag === "key") { key(el.head); continue; }
  const id = idOf(el.head);
  const a = allAttrs("node", el.body);
  if (a.source) { srcOf.set(id, a.source); a.source = `<${a.source.length} chars -> _src/${id}.js>`; }
  const nt = a["node type"];
  if (nt === "cookie jar") { jar = id; bucketOf.set(id, "cookie"); }
  else if (nt === "local storage") bucketOf.set(id, "localStorage");
  else if (nt === "session storage") bucketOf.set(id, "sessionStorage");
  if (a["script id"]) byV8.set(String(a["script id"]), id);
  nodes.set(id, a);
}
process.stderr.write(`${nodes.size} nodes, ${srcOf.size} with source, buckets: ${[...bucketOf.values()].join("/") || "none"}\n`);

// ---- what was this jar read actually looking for? -------------------------------
// `document.cookie` hands back everything, so the edge cannot name a cookie. The code
// at the read site can: scripts parse the jar for a name immediately after reading it.
// Scan a window of source around the read offset for any known storage key mentioned
// in a cookie-ish context, and note the parsing idiom used.
const NAME_CTX = (name) => {
  const e = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // `name=` in a string/regex, or the name quoted as a literal
  return new RegExp(`${e}\\s*=|["'\`]${e}["'\`]`);
};
const PARSE_IDIOMS = [
  { id: "regex match on the jar", re: /\.match\s*\(/ },
  { id: "split(';')", re: /\.split\s*\(\s*["'`]\s*;/ },
  { id: "indexOf(name)", re: /\.indexOf\s*\(/ },
  { id: "startsWith(name)", re: /\.startsWith\s*\(/ },
  { id: "RegExp built from a name", re: /new\s+RegExp\s*\(/ },
  { id: "URLSearchParams", re: /URLSearchParams/ },
];
// Minified tag code reads the jar through a generic accessor —
// `var Cp=function(){return op(a)?a.document.cookie:""}` — which names no cookie at all.
// The name it is after lives in the CALLER. So walk the whole stack: resolve each frame
// to its script source via the V8 script id, and look for a known key in the code around
// that frame. The frame that names it tells you which function wanted which cookie.
const frameOffset = (src, line, col) => {
  if (src == null) return null;
  const lines = src.split("\n");
  if (line == null || line < 0 || line >= lines.length) return null;
  let off = 0;
  for (let i = 0; i < line; i++) off += lines[i].length + 1;
  return off + Math.max(0, Math.min(col || 0, lines[line].length));
};
const readIntentFromStack = (rawStack, knownKeys, win = 400, maxFrames = 12) => {
  if (!rawStack) return null;
  let parsed; try { parsed = JSON.parse(rawStack); } catch { return null; }
  const frames = [];
  const walk = (st, depth) => {
    if (!st || depth > 6) return;
    for (const f of st.callFrames || []) frames.push(f);
    if (st.parent) walk(st.parent, depth + 1);
  };
  walk(parsed, 0);
  const found = new Map();  // key -> {frame, fn, code}
  const chain = [];
  for (const [i, f] of frames.slice(0, maxFrames).entries()) {
    const sn = byV8.get(String(f.scriptId));
    chain.push(f.functionName || "(anonymous)");
    const src = sn != null ? srcOf.get(sn) : null;
    if (!src) continue;
    const off = frameOffset(src, f.lineNumber, f.columnNumber);
    if (off == null) continue;
    const window = src.slice(Math.max(0, off - win), Math.min(src.length, off + win));
    for (const k of knownKeys) {
      if (k.length < 3 || found.has(k)) continue;
      if (NAME_CTX(k).test(window)) {
        found.set(k, { frame: i, fn: f.functionName || "(anonymous)",
          idioms: PARSE_IDIOMS.filter(p => p.re.test(window)).map(p => p.id),
          code: window.length > 500 ? window.slice(0, 500) + "…" : window });
      }
    }
  }
  return { callChain: chain, looksFor: [...found.keys()],
    evidence: Object.fromEntries(found), framesInspected: Math.min(frames.length, maxFrames) };
};

// ===================== PASS 2: cookie values only (nothing buffered) =========
// Deliberately does NOT retain edges. A 2.2 GB graph holds on the order of a
// million edges; keeping every attribute object in memory exhausts the heap. The
// value set is tiny, so this pass is cheap, and pass 3 re-reads the file keeping
// only the edges that actually match.
process.stderr.write(`[2/3] stored values (all buckets) … `);
let edgeCount = 0;
// items are keyed "<bucket>\u0000<key>" so a cookie and a localStorage entry sharing a
// name stay distinct
const itemKey = (bucket, k) => `${bucket}\u0000${k}`;
const addVal = (bucket, k, v) => {
  if (!k || !v) return;
  const id = itemKey(bucket, k);
  if (!cookieVals.has(id)) cookieVals.set(id, new Set());
  cookieVals.get(id).add(v);
};
for await (const el of stream(graphmlPath, ["edge"])) {
  edgeCount++;
  const et = eA(el.body, "edge type");
  if (et !== "storage set" && et !== "storage read result") continue;
  const [s, t] = ends(el.head);
  const wb = bucketOf.get(t), rb = bucketOf.get(s);
  if (et === "storage set" && wb) {
    const k = eA(el.body, "key");
    // only the cookie jar packs attributes into the value; localStorage stores it raw
    const raw = unwrap(eA(el.body, "value"));
    addVal(wb, k, wb === "cookie" ? valOnly(raw) : raw);
  } else if (et === "storage read result" && rb) {
    if (rb === "cookie") {
      for (const [n, v] of parseJar(unwrap(eA(el.body, "value")))) addVal("cookie", n, v);
    } else {
      // localStorage / sessionStorage reads name the exact key — exact attribution
      addVal(rb, eA(el.body, "key"), unwrap(eA(el.body, "value")));
    }
  }
}
process.stderr.write(`${edgeCount} edges, ${cookieVals.size} stored items\n`);

// index of the strings we search edges for: each stored value, plus prefix-stripped
// fragments of it (vendors ship `cid=<id>.<ts>` rather than the whole cookie value)
const idx = new Map(); // search string -> Set(item id)
const excluded = [];
for (const [name, set] of cookieVals) {
  for (const v of set) {
    if (isHostish(v)) { excluded.push({ item: name.split("\u0000")[1], bucket: name.split("\u0000")[0], reason: "hostname/URL-shaped", value: v.slice(0, 60) }); continue; }
    if (bits(v) < MIN_BITS) { excluded.push({ item: name.split("\u0000")[1], bucket: name.split("\u0000")[0], reason: `${Math.round(bits(v))} bits — not identifying`, value: v.slice(0, 60) }); continue; }
    // A stored value can be enormous — some sites park a JSON blob or a chunk of code in
    // storage. Embedding that verbatim in the alternation blows the regex compiler's
    // limit. A long random string is uniquely identifying well before its full length, so
    // match on a bounded slice instead and note that it is a prefix match.
    const MAX_LEN = 160;
    const probe = v.length > MAX_LEN ? v.slice(0, MAX_LEN) : v;
    const needles = new Set([probe]);
    // Fragment generation has to stay tightly bounded. Emitting every separator-delimited
    // suffix of every value produced ~25,000 search strings on one crawl, which then had
    // to be compiled into ~200 regexes and run against every edge — the search never
    // finished. In practice vendors strip a fixed one- or two-segment prefix
    // (`GA1.1.<id>.<ts>` is sent as `<id>.<ts>`), so two suffixes cover the real cases.
    const segs = v.split(/[.|:_-]/).filter(Boolean);
    if (segs.length >= 3) {
      for (const i of [1, 2]) {
        if (i >= segs.length - 1) continue;
        const f = segs.slice(i).join(".");
        if (f.length >= 12 && bits(f) >= MIN_BITS) needles.add(f.length > MAX_LEN ? f.slice(0, MAX_LEN) : f);
      }
    }
    for (const n of needles) {
      // only add an encoded form when encoding actually changes the string
      const enc = encodeURIComponent(n);
      for (const form of (enc === n ? [n] : [n, enc])) {
        if (form.length < 8) continue;
        if (!idx.has(form)) idx.set(form, new Set());
        idx.get(form).add(name);
      }
    }
  }
}

// Item names, needed to recover which cookie a whole-jar read was after.
const cookieNames = [...new Set([...cookieVals.keys()]
  .filter(k => k.startsWith("cookie\u0000")).map(k => k.split("\u0000")[1]))];
const unattributedJarReads = [];

// Retaining every matching edge exhausts the heap on a large crawl: a whole-jar read
// matches EVERY cookie, so one such edge is retained once per cookie, each copy carrying
// a multi-kilobyte stack trace. It is also pointless — how many times a behaviour
// repeated is not evidence about the item. Keep a few EXAMPLES per distinct behaviour
// signature instead, and record that more occurred without storing them.
const MAX_EXAMPLES = 3;
// The acting function is part of the behaviour: the same script reading the jar from two
// different functions is two different things, so it belongs in the signature or capping
// would collapse them. It is also kept as a small field because the raw stack is dropped.
const topFrameFn = (rawStack) => {
  if (!rawStack) return null;
  try { const o = JSON.parse(rawStack); return o?.callFrames?.[0]?.functionName || null; } catch { return null; }
};
// A compact call stack: enough to name the code that acted, small enough to keep. The raw
// DevTools stack is multi-KB and cannot be retained per edge, but the frame list is the
// evidence a reviewer needs to check an attribution, so it must survive.
const MAX_FRAMES = 8;
const frameList = (rawStack) => {
  if (!rawStack) return null;
  try {
    const o = JSON.parse(rawStack);
    const out = [];
    let s = o;
    while (s && out.length < MAX_FRAMES) {
      for (const f of s.callFrames || []) {
        if (out.length >= MAX_FRAMES) break;
        out.push({ fn: f.functionName || "(anonymous)", url: f.url || "", line: f.lineNumber, col: f.columnNumber });
      }
      s = s.parent;
    }
    return out.length ? out : null;
  } catch { return null; }
};
const sigOf = (e) => [e.a["edge type"], e.s, e.t, e.a.key || "", (e.a["attr name"] || ""), e.actingFn || ""].join("|");
const pushCapped = (arr, seen, e, extra, sigExtra) => {
  // sigExtra distinguishes behaviours the edge attributes alone cannot: several reads can
  // share a top frame (a generic jar accessor) while the function that actually names the
  // cookie differs, and those are different behaviours.
  const sig = sigOf(e) + (sigExtra ? "|" + sigExtra : "");
  const n = (seen.get(sig) || 0) + 1;
  seen.set(sig, n);
  if (n <= MAX_EXAMPLES) arr.push(extra ? { ...e, ...extra } : e);
};
const flows = new Map();  // item id -> {carries:[], ops:[], scripts:Set}
const of = c => { if (!flows.has(c)) flows.set(c, { carries: [], ops: [], scripts: new Set(),
  seenCarry: new Map(), seenOp: new Map() }); return flows.get(c); };

let searchStrings = [...idx.keys()];
let searchDegraded = null;
const MAX_PATTERNS = 4000;
if (searchStrings.length > MAX_PATTERNS) {
  // Keep the full values (the reliable signal) and drop derived fragments rather than
  // run a search that cannot finish. Reported, never silent.
  const fullValues = new Set();
  for (const set of cookieVals.values()) for (const v of set) {
    const p = v.length > 160 ? v.slice(0, 160) : v;
    fullValues.add(p); const e = encodeURIComponent(p); if (e !== p) fullValues.add(e);
  }
  const kept = searchStrings.filter(x => fullValues.has(x));
  searchDegraded = { from: searchStrings.length, to: kept.length,
    note: "too many patterns to search exhaustively; prefix-stripped fragments were dropped, so a vendor sending only a fragment of a value may be missed on this graph" };
  searchStrings = kept;
}
const byTypeCount = new Map();

// ===================== PASS 3: match against EVERY edge of EVERY type ========
// Only matching edges are retained, so memory stays proportional to the evidence
// rather than to the graph.
// Matching is the hot loop: millions of edges times hundreds of search strings.
// Testing each one with .includes() measured at ~400 s for a 400 MB graph, which
// extrapolates to hours on the 2 GB crawls. A single alternation regex hands the whole
// search to V8's engine, which scans each edge body once; a cheap literal-prefix test
// rejects the overwhelming majority of edges before the regex is entered.
// GLOBAL: one request can carry several cookies at once (a `/collect` URL commonly
// bundles a client id and an ad id). Stopping at the first match credits the edge to
// whichever needle happened to be found first — array order in the old code, leftmost
// position in a non-global regex — and silently drops the other cookie's evidence.
// Collect every distinct match instead.
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// Even bounded, hundreds of 160-char literals in one alternation can exceed the
// compiler's limit, so split into several regexes and run each.
const CHUNK = 120;
const searchRes = [];
for (let i = 0; i < searchStrings.length; i += CHUNK) {
  const part = searchStrings.slice(i, i + CHUNK).map(esc).join("|");
  try { searchRes.push(new RegExp(part, "g")); }
  catch (err) {
    // last resort: fall back to individual patterns for this chunk
    for (const one of searchStrings.slice(i, i + CHUNK)) {
      try { searchRes.push(new RegExp(esc(one), "g")); } catch { /* unusable */ }
    }
  }
}
const searchRe = searchRes.length ? searchRes[0] : null;
const matchAll = body => {
  const out = new Set();
  for (const re of searchRes) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(body)) !== null) {
      out.add(m[0]);
      if (m.index === re.lastIndex) re.lastIndex++; // guard zero-width
    }
  }
  return [...out];
};
// shortest distinctive prefix shared by no other purpose — used as a cheap reject
const prefixes = [...new Set(searchStrings.map(n => n.slice(0, 6)))];

// The stack trace must be excluded from the search. It is provenance metadata, not data
// flow, and it embeds script URLs — so when a vendor puts an identifier in its own script
// URL (PerimeterX does), every DOM operation that script performs appears to "carry" the
// value. On one crawl that manufactured ~2,200 phantom carriers for a single cookie,
// across create node / add event listener / cross DOM edges it never touched.
const stackKeyId = K.edge["stack trace"];
const stripStack = (body) => {
  if (!stackKeyId) return body;
  const i = body.indexOf(`key="${stackKeyId}">`);
  if (i === -1) return body;
  const j = body.indexOf("</data>", i);
  return j === -1 ? body.slice(0, i) : body.slice(0, i) + body.slice(j + 7);
};

process.stderr.write(`[3/3] searching all edges for ${searchStrings.length} value strings … `);
for await (const el of stream(graphmlPath, ["edge"])) {
  const [s, t] = ends(el.head);
  const isJarOp = bucketOf.has(t) || bucketOf.has(s);
  let hits = [];
  let searchBody = null;
  if (!isJarOp) {
    if (!searchRes.length) continue;
    // The needles are DECODED storage values, but the element body is raw XML, where a
    // quote is written `&quot;`. Any JSON-shaped value therefore could never match — on
    // walmart that silently hid 13 of 74 items, and cut one item's observed carriers from
    // 526 to 0. Decode the body before searching. The prefix gate must be applied to the
    // decoded text too, or it rejects the edge before the search ever runs.
    searchBody = un(stripStack(el.body));
    let maybe = false;
    for (const p of prefixes) { if (searchBody.includes(p)) { maybe = true; break; } }
    if (!maybe) continue;
    hits = matchAll(searchBody);
    if (!hits.length) continue;
  }
  const a = allAttrs("edge", el.body);
  // the raw stack is large and only needed to derive read intent; drop it after use
  const rawStack = a["stack trace"];
  const actingFn = topFrameFn(rawStack);
  const frames = frameList(rawStack);
  if (rawStack) a["stack trace"] = `<${rawStack.length} chars; top ${MAX_FRAMES} frames preserved as frames>`;
  const e = { id: eid(el.head), s, t, a, actingFn, frames };
  const et = a["edge type"] || "(none)";
  if (isJarOp) {
    const wb = bucketOf.get(t), rb = bucketOf.get(s);
    if (et === "read storage call" && wb === "cookie") {
      // whole-jar read: recover the intended cookie from the code at the read site
      const intent = readIntentFromStack(rawStack, cookieNames);
      const named = intent && intent.looksFor.length ? intent.looksFor : null;
      for (const n of (named || [])) {
        const id2 = itemKey("cookie", n);
        if (!cookieVals.has(id2)) continue;
        pushCapped(of(id2).ops, of(id2).seenOp, e, { readIntent: intent },
          intent?.evidence?.[n]?.fn || "");
        if (s) of(id2).scripts.add(s);
      }
      if (!named) unattributedJarReads.push({ ...e, readIntent: intent });
    } else if (wb && a.key) {
      const id2 = itemKey(wb, a.key);
      if (cookieVals.has(id2)) { pushCapped(of(id2).ops, of(id2).seenOp, e); if (s) of(id2).scripts.add(s); }
    } else if (rb === "cookie" && et === "storage read result") {
      for (const [n] of parseJar(unwrap(a.value))) {
        const id2 = itemKey("cookie", n);
        if (cookieVals.has(id2)) { pushCapped(of(id2).ops, of(id2).seenOp, e); if (t) of(id2).scripts.add(t); }
      }
    } else if (rb && a.key) {
      const id2 = itemKey(rb, a.key);
      if (cookieVals.has(id2)) { pushCapped(of(id2).ops, of(id2).seenOp, e); if (t) of(id2).scripts.add(t); }
    }
    if (!hits.length) hits = matchAll(un(el.body));   // decoded, for the same reason as above
    if (!hits.length) continue;
  }
  // credit EVERY cookie whose value appears on this edge
  const credited = new Set();
  for (const h of hits) for (const c of idx.get(h) || []) {
    if (credited.has(c)) continue;
    credited.add(c);
    pushCapped(of(c).carries, of(c).seenCarry, e, { matched: h.slice(0, 60) });
    if (s) of(c).scripts.add(s);
    if (t) of(c).scripts.add(t);
  }
  if (credited.size) byTypeCount.set(et, (byTypeCount.get(et) || 0) + 1);
}
process.stderr.write(`done\n`);

// ===================== write =====================
mkdirSync(join(OUT, "flows"), { recursive: true });
mkdirSync(join(OUT, "_src"), { recursive: true });
for (const [id, src] of srcOf) writeFileSync(join(OUT, "_src", `${id}.js`), src);
writeFileSync(join(OUT, "_scripts.json"), JSON.stringify(
  Object.fromEntries([...nodes].filter(([, a]) => a["node type"] === "script")), null, 1));

const index = [];
for (const [itemId, f] of flows) {
  const [bucket, cookie] = itemId.split("\u0000");
  const safe = `${bucket === "cookie" ? "" : bucket + "__"}${cookie}`.replace(/[^\w.-]/g, "_");
  const involved = {};
  for (const n of f.scripts) if (nodes.has(n)) involved[n] = nodes.get(n);
  const doc = {
    item: cookie, bucket, cookie, pageUrl, graph: graphmlPath,
    values: [...(cookieVals.get(itemId) || [])],
    distinctBehaviours: f.seenOp.size + f.seenCarry.size,
    operations: f.ops,          // set / read / delete on the jar, full attrs incl. stack trace
    carriedOn: f.carries,       // EVERY edge of EVERY type carrying the value
    carriedOnTypes: f.carries.reduce((o, e) => { const t = e.a["edge type"] || "(none)"; o[t] = (o[t] || 0) + 1; return o; }, {}),
    involvedNodes: involved,
  };
  writeFileSync(join(OUT, "flows", `${safe}.json`), JSON.stringify(doc, null, 1));
  index.push({ item: cookie, bucket, file: `flows/${safe}.json`, ops: f.ops.length,
    carried: f.carries.length, types: doc.carriedOnTypes, values: doc.values.length });
}
index.sort((a, b) => b.carried - a.carried);
writeFileSync(join(OUT, "_summary.json"), JSON.stringify({
  pageUrl, graph: graphmlPath, nodes: nodes.size, edges: edgeCount,
  scriptsWithSource: srcOf.size, items: index.length,
  byBucket: index.reduce((o, e) => { o[e.bucket] = (o[e.bucket] || 0) + 1; return o; }, {}),
  excludedFromValueSearch: excluded,
  searchDegraded,
  jarReadsAttributedByCode: [...flows.values()].reduce((n, f) => n + f.ops.filter(o => o.readIntent).length, 0),
  jarReadsStillUnattributed: unattributedJarReads.length,
  carrierEdgeTypes: Object.fromEntries(byTypeCount),
  elapsedMs: Date.now() - t0, index,
}, null, 1));

process.stderr.write(`wrote ${index.length} storage-item flows -> ${OUT}  (${((Date.now() - t0) / 1000).toFixed(0)}s)\n`);
console.log(JSON.stringify({ items: index.length,
  byBucket: index.reduce((o, e) => { o[e.bucket] = (o[e.bucket] || 0) + 1; return o; }, {}),
  edges: edgeCount, scriptsWithSource: srcOf.size,
  carrierEdgeTypes: Object.fromEntries(byTypeCount), out: OUT }, null, 1));
