#!/usr/bin/env node
// cookie-code-trace.mjs — read the ACTUAL CODE that touches a cookie.
//
//   node analysis/cookie-code-trace.mjs <graphml> <cookieName> [--ctx N] [--json] [--all-frames]
//
// Every other tool here classifies a cookie from metadata about it: which host it
// went to, how long it lives, how much entropy the value carries. Those are all
// PROXIES. This one reads the source.
//
// PageGraph records, and nothing else in this repo was using:
//   node  `source`          — the full JavaScript text of each script it executed
//   node  `script id`       — the V8 scriptId, which joins a stack frame to that text
//   edge  `script position` — the BYTE OFFSET into that text where the operation happened
//   edge  `stack trace`     — the full call stack at the moment of the operation,
//                             each frame carrying {functionName, scriptId, lineNumber, columnNumber}
//
// So for a cookie we can show, with no inference at all:
//   1. the exact line of code that WROTE it, in context
//   2. the exact line(s) that READ it back
//   3. the call stack above each of those, with the source at every frame
//   4. the code that CONSTRUCTED the outbound request carrying the value, in context
//
// That is the difference between "this value reached host X" and "this function
// harvested the value and put it in a query string on line N of this file".

import { stream, makeKeys, readPageUrl, idOf, ends, unwrap, valueOnly, parseJar, codeWindow, fromLineCol, decodeStack } from "./lib/graph-parse.mjs";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const asJson = argv.includes("--json");
const allFrames = argv.includes("--all-frames");
const CTX = parseInt(flag("--ctx", "320"), 10); // chars of context either side of an offset
const skip = new Set(["--ctx", flag("--ctx", "320")]);
const pos = argv.filter(a => !a.startsWith("--") && !skip.has(a));
const graphmlPath = pos[0], cookieName = pos[1];
if (!graphmlPath || !cookieName) {
  process.stderr.write("usage: node analysis/cookie-code-trace.mjs <graphml> <cookieName> [--ctx N] [--json] [--all-frames]\n");
  process.exit(1);
}

// Shared streaming + parsing primitives now live in lib/graph-parse.mjs. One key table per run.
const { key, nA, eA } = makeKeys();

// ---------------------------------------------------------------------------
const pageUrl = await readPageUrl(graphmlPath);
let jar = null;
const scripts = new Map();      // node id -> {url, src, v8, type}
const byV8 = new Map();         // V8 scriptId -> node id
const resUrl = new Map();       // resource node -> url
const execSrc = new Map();      // script node -> element node
const elemReq = new Map();      // element node -> requested url
const webApi = new Map();       // call node -> method
const pend = [];                // edges held until node maps complete

for await (const el of stream(graphmlPath)) {
  if (el.tag === "key") { key(el.head); continue; }
  if (el.tag === "node") {
    const id = idOf(el.head), t = nA(el.body, "node type");
    if (t === "cookie jar") jar = id;
    else if (t === "script") {
      const v8 = nA(el.body, "script id");
      scripts.set(id, { url: nA(el.body, "url"), src: nA(el.body, "source"), v8, type: nA(el.body, "script type") });
      if (v8) byV8.set(String(v8), id);
    } else if (t === "resource") resUrl.set(id, nA(el.body, "url"));
    else if (t === "web API" || t === "JS builtin") webApi.set(id, nA(el.body, "method") || nA(el.body, "id"));
    continue;
  }
  const et = eA(el.body, "edge type");
  if (!et) continue;
  const [s, t] = ends(el.head);
  if (et === "execute") { if (t) execSrc.set(t, s); continue; }
  if (et === "request start" || et === "request complete") {
    const u = t && resUrl.get(t);
    if (s && u && !elemReq.has(s)) elemReq.set(s, u);
    continue;
  }
  if (["storage set", "delete storage", "read storage call", "storage read result", "js call", "js result"].includes(et)) {
    pend.push({ et, s, t,
      key: eA(el.body, "key"), value: eA(el.body, "value"), args: eA(el.body, "args"),
      posn: eA(el.body, "script position"), stack: eA(el.body, "stack trace"),
      csrc: eA(el.body, "cookie source"), ts: eA(el.body, "timestamp") });
  }
}

const scriptUrl = sn => {
  const s = scripts.get(sn); if (s?.url) return s.url;
  const e = execSrc.get(sn); const u = e && elemReq.get(e);
  return u || `${pageUrl} (inline)`;
};

// byte offset -> {line, col, offset, before, after} — symmetric window via the shared helper.
// (fromLineCol + decodeStack are imported from lib/graph-parse.mjs.)
const at = (src, off, ctx = CTX) => codeWindow(src, off, ctx);
const frameCode = f => {
  const sn = byV8.get(String(f.scriptId));
  if (sn == null) return null;
  const s = scripts.get(sn);
  if (!s?.src) return { scriptNode: sn, url: s?.url || scriptUrl(sn), noSource: true };
  const off = fromLineCol(s.src, f.lineNumber ?? 0, f.columnNumber ?? 0);
  return { scriptNode: sn, url: s.url || scriptUrl(sn), ...at(s.src, off, Math.round(CTX * 0.6)) };
};

// ---------------------------------------------------------------------------
// collect what happened to THIS cookie
// ---------------------------------------------------------------------------
const writes = [], deletes = [], reads = [], consumers = [];
const cookieValues = new Set();

for (const p of pend) {
  if (p.et === "storage set" && p.t === jar && p.key === cookieName) {
    const v = valueOnly(unwrap(p.value)); if (v) cookieValues.add(v);
    writes.push(p);
  } else if (p.et === "delete storage" && p.t === jar && p.key === cookieName) deletes.push(p);
  else if (p.et === "storage read result" && p.s === jar) {
    for (const [n, v] of parseJar(unwrap(p.value))) if (n === cookieName && v) cookieValues.add(v);
  }
}
// read sites whose paired result contained our cookie: approximate by recording all
// read-call sites on the jar, then marking those whose reader script also saw the value
for (const p of pend) {
  if (p.et === "read storage call" && p.t === jar) reads.push(p);
}
// js calls whose args contain the value = the code that CONSUMED it
const vals = [...cookieValues].filter(v => v.length >= 8);
const frags = new Set();
for (const v of vals) {
  frags.add(v);
  const segs = v.split(/[.|:_-]/).filter(Boolean);
  for (let i = 1; i < segs.length - 1; i++) { const f = segs.slice(i).join("."); if (f.length >= 12) frags.add(f); }
}
// Follow the value THROUGH transforms, not just to its first consumer.
//
// A cookie value is very often not shipped verbatim: it is base64-encoded, hashed,
// JSON-wrapped or concatenated first, and only the RESULT of that transform reaches
// the network. Matching a single generation of the value therefore stops one hop
// short of the evidence that matters, and reports "no network sink" for a cookie
// that is in fact exfiltrated. PageGraph pairs each `js call` (script -> call node,
// carrying args) with a `js result` (call node -> script, carrying the return value),
// so chaining call.args -> result.value walks the real data-flow chain.
const ROUNDS = parseInt(flag("--rounds", "4"), 10);
const resultOf = new Map();          // call node -> return value
for (const p of pend) if (p.et === "js result" && p.s) resultOf.set(p.s, unwrap(p.value));

// seed -> provenance chain describing how we got to that string
const taint = new Map();
for (const f of frags) taint.set(f, { round: 0, via: [] });
const seenCall = new Set();

for (let round = 0; round < ROUNDS; round++) {
  const seeds = [...taint.keys()];
  let grew = false;
  for (const p of pend) {
    if (p.et !== "js call" || !p.args) continue;
    let hit = null;
    for (const f of seeds) { if (f.length >= 8 && p.args.includes(f)) { hit = f; break; } }
    if (!hit) continue;
    const sig = `${p.s}|${p.t}|${p.posn}|${hit}`;
    if (!seenCall.has(sig)) {
      seenCall.add(sig);
      const prov = taint.get(hit);
      consumers.push({ ...p, matched: hit, exact: vals.includes(hit),
        round: prov.round, via: prov.via });
    }
    // propagate the transform's OUTPUT as a new tainted value
    const out = resultOf.get(p.t);
    if (out && out.length >= 8 && out.length <= 4096 && !taint.has(out)) {
      const method = webApi.get(p.t) || "(unknown)";
      taint.set(out, { round: (taint.get(hit).round || 0) + 1,
                       via: [...taint.get(hit).via, method] });
      grew = true;
    }
  }
  if (!grew) break;
}

// ---------------------------------------------------------------------------
const NET = /(?:^|\.)fetch\b|XMLHttpRequest\.(?:open|send|setRequestHeader)\b|sendBeacon\b|(?:^|\.)WebSocket\b|EventSource\b|HTML(?:Image|Script|Link|Media|IFrame)Element\.src\b/i;

const site = (p, label) => {
  const sn = p.s;
  const s = scripts.get(sn);
  const off = p.posn != null ? Number(p.posn) : null;
  return {
    what: label,
    scriptNode: sn,
    scriptUrl: scriptUrl(sn),
    inline: !s?.url,
    hasSource: !!s?.src,
    sourceLength: s?.src ? s.src.length : 0,
    channel: p.csrc || null,
    timestamp: p.ts || null,
    value: p.value ? valueOnly(unwrap(p.value)) : null,
    code: s?.src ? at(s.src, off) : null,
    offset: off,
    stack: decodeStack(p.stack).map(f => ({
      fn: f.functionName || "(anonymous)", async: f.async,
      url: f.url || null, line: f.lineNumber, col: f.columnNumber,
      code: frameCode(f),
    })),
  };
};

const out = {
  cookie: cookieName, pageUrl, graph: graphmlPath,
  scriptsWithSource: [...scripts.values()].filter(s => s.src).length,
  totalScripts: scripts.size,
  observedValues: [...cookieValues],
  writes: writes.map(p => site(p, "WROTE the cookie")),
  deletes: deletes.map(p => site(p, "DELETED the cookie")),
  consumers: consumers.map(p => {
    const b = site(p, "CONSUMED the value");
    const method = webApi.get(p.t) || "(unknown)";
    let dest = null;
    try { const a = JSON.parse(p.args); for (const x of Array.isArray(a) ? a : []) if (typeof x === "string" && /^(https?:)?\/\/|^\//.test(x)) { dest = x; break; } } catch { /* not json */ }
    return { ...b, method, isNetworkSink: NET.test(method), destUrl: dest,
      matchedFragment: p.matched, exactValue: p.exact,
      transformRound: p.round || 0,
      transformChain: (p.via && p.via.length) ? p.via : null,
      argsPreview: p.args ? p.args.slice(0, 400) : null };
  }),
  readSiteCount: reads.length,
};

// ---------------------------------------------------------------------------
if (asJson) {
  // Flush BEFORE exiting: process.exit() drops un-flushed stdout, truncating large JSON at ~64KB.
  await new Promise((r) => process.stdout.write(JSON.stringify(out, null, 2) + "\n", r));
  process.exit(0);
}

const rule = (c = "─") => c.repeat(78);
const codeBlock = (code, indent = "    ") => {
  if (!code) return `${indent}(source not recorded for this script)`;
  const b = code.before.replace(/\n/g, "\n" + indent);
  const a = code.after.replace(/\n/g, "\n" + indent);
  return `${indent}line ${code.line}, col ${code.col} (offset ${code.offset})\n` +
         `${indent}${"·".repeat(60)}\n${indent}${b}[7m▮[0m${a}\n${indent}${"·".repeat(60)}`;
};

console.log(rule("═"));
console.log(`COOKIE  ${cookieName}`);
console.log(`PAGE    ${pageUrl}`);
console.log(`SOURCE  ${out.scriptsWithSource} of ${out.totalScripts} script nodes carry full source text`);
console.log(`VALUES  ${out.observedValues.map(v => JSON.stringify(v.slice(0, 70))).join("  ")}`);
console.log(rule("═"));

const dump = (arr, title) => {
  if (!arr.length) { console.log(`\n${title}: none observed\n`); return; }
  for (const [i, w] of arr.entries()) {
    console.log(`\n${rule()}`);
    console.log(`${title} #${i + 1} — ${w.what}`);
    console.log(`  script : ${w.scriptUrl}${w.inline ? "  [inline]" : ""}`);
    if (w.channel) console.log(`  channel: ${w.channel}`);
    if (w.value) console.log(`  value  : ${JSON.stringify(w.value.slice(0, 90))}`);
    if (w.method) console.log(`  method : ${w.method}${w.isNetworkSink ? "   ** NETWORK SINK **" : ""}`);
    if (w.destUrl) console.log(`  dest   : ${w.destUrl.slice(0, 160)}`);
    if (w.matchedFragment) console.log(`  matched: ${JSON.stringify(String(w.matchedFragment).slice(0,60))} ${w.exactValue ? "(whole value)" : "(derived/fragment)"}`);
    if (w.transformChain) console.log(`  chain  : cookie value -> ${w.transformChain.join(" -> ")} -> here   (hop ${w.transformRound})`);
    console.log(`\n  ▼ THE CODE AT THE OPERATION`);
    console.log(codeBlock(w.code));
    if (w.stack.length) {
      console.log(`\n  ▼ CALL STACK (${w.stack.length} frames, innermost first)`);
      const frames = allFrames ? w.stack : w.stack.slice(0, 6);
      for (const [j, f] of frames.entries()) {
        console.log(`\n   [${j}] ${f.fn}${f.async ? "   (async parent)" : ""}`);
        console.log(`       ${f.code?.url || f.url || "(unknown script)"}  ${f.line}:${f.col}`);
        if (f.code && !f.code.noSource) console.log(codeBlock(f.code, "       "));
      }
      if (!allFrames && w.stack.length > 6) console.log(`\n   … ${w.stack.length - 6} more frames (--all-frames)`);
    } else {
      console.log(`\n  (no stack trace recorded on this edge)`);
    }
  }
};

dump(out.writes, "WRITE");
dump(out.deletes, "DELETE");
const netFirst = out.consumers.slice().sort((a, b) => (b.isNetworkSink ? 1 : 0) - (a.isNetworkSink ? 1 : 0));
dump(netFirst, "CONSUMER");
console.log(`\n${rule("═")}`);
console.log(`${out.writes.length} write(s) · ${out.deletes.length} delete(s) · ${out.consumers.length} consumer(s) ` +
            `(${out.consumers.filter(c => c.isNetworkSink).length} network sinks) · ${out.readSiteCount} jar read sites`);
