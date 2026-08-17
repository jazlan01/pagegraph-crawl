#!/usr/bin/env node
// cookie-code-sites.mjs — the exact SOURCE that touches each cookie, for the report's "where to fix
// it" layer. Streams the graph and emits, per requested cookie, the code that WROTE it and the code
// that SENT its value to the network; and, page-wide, the distinct document.cookie READ sites (with
// their call stack) for the LLM read-resolver to attribute.
//
//   node analysis/cookie-code-sites.mjs <graphml> <cookie,cookie,...> <out.json>
//
// Memory-safe on multi-GB graphs: three streaming passes, retaining script source ONLY for scripts
// that write/send a requested cookie or appear at a read site (or its stack). The single-cookie
// cookie-code-trace holds every script's source and OOMs on chegg's 6.4 GB; this does not.
import { writeFileSync } from "node:fs";
import { stream, makeKeys, idOf, ends, readPageUrl, unwrap, valueOnly, codeWindow, fromLineCol, decodeStack } from "./lib/graph-parse.mjs";

const [graphmlPath, cookieList, outPath] = process.argv.slice(2);
const wanted = new Set(cookieList.split(",").map((s) => s.trim()).filter(Boolean));
const log = (m) => process.stderr.write(m + "\n");

const CTX_BEFORE = 90, CTX_AFTER = 170;
// Read sites need a WIDER, DEEPER view than write/send sites: the cookie name a getter reads is often
// a string literal several frames up the stack (getCookie('_ga')), so capture more frames and bigger
// windows so the resolver can see the literal.
const READ_CTX_BEFORE = 150, READ_CTX_AFTER = 230, STACK_FRAMES = 3, READ_STACK_FRAMES = 7, STACK_CTX = 140;
const fmt = (w) => w ? { line: w.line, col: w.col, before: w.before.replace(/\n/g, "↵"), after: w.after.replace(/\n/g, "↵") } : { line: null, col: null, before: null, after: null };

// A value is rarely shipped verbatim; a stable sub-segment often is. Fragment for send-matching.
const fragsOf = (value) => {
  const out = new Set();
  const v = valueOnly(unwrap(value));
  if (v && v.length >= 8) {
    out.add(v);
    const segs = v.split(/[.|:_\-]/).filter(Boolean);
    for (let i = 1; i < segs.length - 1; i++) { const f = segs.slice(i).join("."); if (f.length >= 12) out.add(f); }
  }
  return out;
};
const NET = /(?:^|\.)fetch\b|XMLHttpRequest\.(?:open|send|setRequestHeader)\b|sendBeacon\b|(?:^|\.)WebSocket\b|EventSource\b|HTML(?:Image|Script|Link|Media|IFrame)Element\.src\b/i;
const destFromArgs = (args) => { if (!args) return null; try { const a = JSON.parse(args); for (const x of Array.isArray(a) ? a : []) if (typeof x === "string" && /^(https?:)?\/\/|^\//.test(x)) return x; } catch { /* not json */ } return null; };

const pageUrl = readPageUrl(graphmlPath);

// ---- pass 1: node maps, storage edges, value fragments, distinct read sites -
log(`  pass 1: ${graphmlPath}`);
const { key, nA, eA } = makeKeys();
const scriptMeta = new Map();  // node -> {url}
const byV8 = new Map();        // v8 scriptId -> node
const resUrl = new Map(), execSrc = new Map(), elemReq = new Map(), webApi = new Map();
const storageEdges = [];       // {et, s, cookie, posn, stack}
const fragCookie = new Map();   // value fragment -> cookie
const readSites = new Map();    // "script|offset" -> {script, offset, stack}
const needSrc = new Set();
let jar = null;                 // the cookie-jar node — reads target it (vs localStorage/sessionStorage)

for await (const el of stream(graphmlPath)) {
  if (el.tag === "key") { key(el.head); continue; }
  if (el.tag === "node") {
    const id = idOf(el.head), t = nA(el.body, "node type");
    if (t === "cookie jar") jar = id;
    else if (t === "script") { scriptMeta.set(id, { url: nA(el.body, "url") }); const v8 = nA(el.body, "script id"); if (v8) byV8.set(String(v8), id); }
    else if (t === "resource") resUrl.set(id, nA(el.body, "url"));
    else if (t === "web API" || t === "JS builtin") webApi.set(id, nA(el.body, "method") || nA(el.body, "id"));
    continue;
  }
  const et = eA(el.body, "edge type");
  if (!et) continue;
  const [s, t] = ends(el.head);
  if (et === "execute") { if (t) execSrc.set(t, s); continue; }
  if (et === "request start" || et === "request complete") { const u = t && resUrl.get(t); if (s && u && !elemReq.has(s)) elemReq.set(s, u); continue; }

  if (et === "read storage call") {
    // The same edge type covers localStorage/sessionStorage too; keep the target so we can prune to
    // cookie-jar reads after the stream (the jar node may appear after some read edges).
    const off = eA(el.body, "script position");
    const k = `${s}|${off}`;
    if (!readSites.has(k)) readSites.set(k, { script: s, offset: off, target: t, stack: eA(el.body, "stack trace") });
    continue;
  }
  if (et === "storage set" || et === "delete storage") {
    const ck = eA(el.body, "key");
    if (!ck || !wanted.has(ck)) continue;
    const value = eA(el.body, "value");
    storageEdges.push({ et, s, cookie: ck, posn: eA(el.body, "script position"), stack: eA(el.body, "stack trace"), csrc: eA(el.body, "cookie source") });
    if (s) needSrc.add(s);
    if (et === "storage set") for (const f of fragsOf(value)) if (!fragCookie.has(f)) fragCookie.set(f, ck);
  }
}
// Prune read sites to cookie-jar reads only (drop localStorage/sessionStorage), now that jar is known.
if (jar) for (const [k, rs] of readSites) if (rs.target && rs.target !== jar) readSites.delete(k);
// Read-site scripts + their stack-frame scripts (a getter's caller lives elsewhere) need source.
for (const rs of readSites.values()) { if (rs.script) needSrc.add(rs.script); for (const f of decodeStack(rs.stack).slice(0, READ_STACK_FRAMES)) { const n = byV8.get(String(f.scriptId)); if (n) needSrc.add(n); } }
const frags = [...fragCookie.keys()].filter((f) => f.length >= 8);
log(`  ${storageEdges.length} storage edge(s), ${readSites.size} distinct cookie read site(s), ${frags.length} value fragment(s)`);

// ---- pass 2: js-call edges carrying a cookie value = the SEND site ----------
const consumers = [];
if (frags.length) { log(`  pass 2: scanning js calls for value sends`);
  for await (const el of stream(graphmlPath)) {
    if (el.tag === "key") { key(el.head); continue; }
    if (el.tag !== "edge") continue;
    if (eA(el.body, "edge type") !== "js call") continue;
    const args = eA(el.body, "args");
    if (!args) continue;
    const hitCookies = new Set();
    for (const f of frags) if (args.includes(f)) hitCookies.add(fragCookie.get(f));
    if (!hitCookies.size) continue;
    const [s, t] = ends(el.head);
    const method = webApi.get(t) || "(unknown)";
    const posn = eA(el.body, "script position"), stack = eA(el.body, "stack trace"), destUrl = destFromArgs(args), isNetworkSink = NET.test(method);
    for (const cookie of hitCookies) consumers.push({ s, cookie, method, destUrl, isNetworkSink, posn, stack });
    if (s) needSrc.add(s);
  }
}
log(`  ${consumers.length} value-send call(s)`);

// ---- pass 3: source ONLY for referenced scripts -----------------------------
log(`  pass 3: pulling source for ${needSrc.size} script(s)`);
const srcById = new Map();
const { key: key3, nA: nA3 } = makeKeys();
if (needSrc.size) for await (const el of stream(graphmlPath)) {
  if (el.tag === "key") { key3(el.head); continue; }
  if (el.tag !== "node") continue;
  const id = idOf(el.head);
  if (!needSrc.has(id)) continue;
  if (nA3(el.body, "node type") !== "script") continue;
  srcById.set(id, nA3(el.body, "source"));
}

const scriptUrlOf = (sn) => scriptMeta.get(sn)?.url || (elemReq.get(execSrc.get(sn))) || `${pageUrl} (inline)`;
const siteAt = (sn, posn) => {
  const src = srcById.get(sn), off = posn != null ? Number(posn) : null;
  return { scriptUrl: scriptUrlOf(sn), inline: !scriptMeta.get(sn)?.url, hasSource: src != null, ...fmt(codeWindow(src, off, CTX_BEFORE, CTX_AFTER)) };
};
const frameSite = (f) => {
  const sn = byV8.get(String(f.scriptId)), src = sn != null ? srcById.get(sn) : null;
  const off = src != null ? fromLineCol(src, f.lineNumber ?? 0, f.columnNumber ?? 0) : null;
  return { fn: f.functionName || "(anonymous)", async: !!f.async, scriptUrl: sn != null ? scriptUrlOf(sn) : (f.url || null), hasSource: src != null, ...fmt(codeWindow(src, off, STACK_CTX, STACK_CTX)) };
};

const cookies = {};
for (const ck of wanted) cookies[ck] = { writes: [], deletes: [], sends: [] };
const WHAT = { "storage set": "writes", "delete storage": "deletes" };
for (const e of storageEdges) cookies[e.cookie][WHAT[e.et]].push({ ...siteAt(e.s, e.posn), channel: e.csrc || null, stack: decodeStack(e.stack).slice(0, STACK_FRAMES).map((f) => ({ fn: f.functionName || "(anonymous)", url: f.url || null, line: f.lineNumber, col: f.columnNumber })) });
for (const c of consumers) cookies[c.cookie].sends.push({ ...siteAt(c.s, c.posn), method: c.method, destUrl: c.destUrl, isNetworkSink: c.isNetworkSink, stack: decodeStack(c.stack).slice(0, STACK_FRAMES).map((f) => ({ fn: f.functionName || "(anonymous)", url: f.url || null, line: f.lineNumber, col: f.columnNumber })) });

const readSiteAt = (sn, posn) => {
  const src = srcById.get(sn), off = posn != null ? Number(posn) : null;
  return { scriptUrl: scriptUrlOf(sn), inline: !scriptMeta.get(sn)?.url, hasSource: src != null, ...fmt(codeWindow(src, off, READ_CTX_BEFORE, READ_CTX_AFTER)) };
};
const readSitesOut = [...readSites.entries()].map(([k, rs]) => ({
  key: k, ...readSiteAt(rs.script, rs.offset),
  stack: decodeStack(rs.stack).slice(0, READ_STACK_FRAMES).map(frameSite),
}));

writeFileSync(outPath, JSON.stringify({ pageUrl, cookies, readSites: readSitesOut }, null, 2));
log(`  wrote ${outPath}`);
