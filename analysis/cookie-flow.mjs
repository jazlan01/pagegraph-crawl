#!/usr/bin/env node
// cookie-flow.mjs — taint-propagation over a PageGraph .graphml: for every cookie,
// follow its value from the read (`storage read result`) FORWARD through JS
// consumers and their return values, to determine whether the value (or a
// transform of it) EVENTUALLY reaches a network request.
//
// PageGraph records, per JS invocation, a `js call` edge (script -> call node,
// with `args`) and a paired `js result` edge (call node -> script, with the
// return `value`). Chaining call.args -> result.value across invocations is a
// data-flow (taint) trace: a value read from a cookie that is passed to
// `TextEncoder.encode` produces a new value (the encoded bytes) that may then be
// passed to `fetch`/`XHR.send`/`sendBeacon` — a network request fired eventually.
//
//   node analysis/cookie-flow.mjs <graphml> [cookieName] [--split <dir>] [--rounds N]
//
// Streaming + bounded rounds so it works on multi-GB graphs. Each round is one
// full stream of the edges; a value only ever grows the taint set, so a small
// fixed round cap (default 4) captures realistic transform chains
// (cookie -> encode -> hash -> fetch) without unbounded work.

import { mkdirSync, writeFileSync } from "node:fs";
import { graphStream, readPageUrl } from "./lib/graph-source.mjs";
import { join } from "node:path";

const argv = process.argv.slice(2);
const flag = (name, def) => {
  const i = argv.indexOf(name);
  return i !== -1 ? argv[i + 1] : def;
};
const splitDir = flag("--split", null);
const maxRounds = parseInt(flag("--rounds", "4"), 10);
const skip = new Set(["--split", splitDir, "--rounds", flag("--rounds", "4")].filter(Boolean));
const positional = argv.filter((a) => !a.startsWith("--") && !skip.has(a));
const graphmlPath = positional[0];
const onlyCookie = positional[1] || null;
if (!graphmlPath) {
  process.stderr.write("usage: node analysis/cookie-flow.mjs <graphml> [cookieName] [--split <dir>] [--rounds N]\n");
  process.exit(1);
}

const MIN_SEED = 8;        // ignore values shorter than this (would match everywhere)
const MAX_SEED = 4096;     // don't propagate absurdly large return values as new seeds
const SNIP = 200;

const unescapeXml = (s) => s == null ? null : s
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
  .replace(/&#39;/g, "'").replace(/&amp;/g, "&");

const isNetworkSink = (method) =>
  /(?:^|\.)fetch\b|XMLHttpRequest\.(?:open|send|setRequestHeader)\b|sendBeacon\b|(?:^|\.)WebSocket\b|EventSource\b|HTML(?:Image|Script|Link|Media|IFrame)Element\.src\b|Navigator\.sendBeacon\b/i.test(method || "");

const destUrlFromArgs = (argsRaw) => {
  try {
    const arr = JSON.parse(argsRaw);
    for (const a of Array.isArray(arr) ? arr : []) {
      if (typeof a === "string" && /^(https?:)?\/\/|^\//.test(a)) return a;
    }
  } catch { /* not json */ }
  return null;
};

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
const endpoints = (head) => [ (head.match(/source="(n\d+)"/) || [])[1], (head.match(/target="(n\d+)"/) || [])[1] ];
const unwrap = (v) => {
  if (v == null) return v;
  if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') {
    try { const p = JSON.parse(v); if (typeof p === "string") return p; } catch { return v.slice(1, -1); }
  }
  return v;
};
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
// PASS 1 — node maps, cookie seed values, script-url resolution, request edges.
// ---------------------------------------------------------------------------
const pageUrl = await readPageUrl(graphmlPath);
let cookieJarId = null;
const webApiMethod = new Map();   // call node id -> method
const resourceUrl = new Map();    // resource node id -> url
const executeSrc = new Map();     // script node id -> element node id
const elementReqUrl = new Map();  // element/script node id -> requested url
const scriptRequests = new Map(); // script node id -> Set(url)  (request start FROM a script)
const cookies = new Map();        // name -> { values:Set, readers:Set }
const cookieOf = (n) => { let c = cookies.get(n); if (!c) cookies.set(n, c = { values: new Set(), readers: new Set() }); return c; };

for await (const el of streamElements(graphmlPath)) {
  if (el.tag === "key") { attrId(el.head); continue; }
  if (el.tag === "node") {
    const id = idOf(el.head);
    const type = nAttr(el.body, "node type");
    if (type === "cookie jar") cookieJarId = id;
    else if (type === "web API" || type === "JS builtin") webApiMethod.set(id, nAttr(el.body, "method") || nAttr(el.body, "id"));
    else if (type === "resource") resourceUrl.set(id, nAttr(el.body, "url"));
    continue;
  }
  const et = eAttr(el.body, "edge type");
  if (!et) continue;
  const [s, t] = endpoints(el.head);
  if (et === "execute") { if (t) executeSrc.set(t, s); }
  else if (et === "request start" || et === "request complete") {
    const url = t && resourceUrl.get(t);
    if (s && url) {
      if (!elementReqUrl.has(s)) elementReqUrl.set(s, url);
      let set = scriptRequests.get(s); if (!set) scriptRequests.set(s, set = new Set()); set.add(url);
    }
  } else if (et === "storage read result" && s === cookieJarId) {
    for (const [name, val] of parseJar(unwrap(eAttr(el.body, "value")))) {
      const c = cookieOf(name); if (val) c.values.add(val); if (t) c.readers.add(t);
    }
  } else if (et === "storage set" && t === cookieJarId) {
    const key = eAttr(el.body, "key");
    // Strip cookie ATTRIBUTES: a `storage set` records the whole `document.cookie`
    // assignment (`v; path=/; domain=.x.com`). Tainting with that boilerplate makes
    // unrelated cookies match it everywhere and invents network hits. A value cannot
    // contain an unencoded ";", so truncating at the first one is always correct.
    const value = unwrap(eAttr(el.body, "value"))?.split(";")[0].trim();
    if (key && value) cookieOf(key).values.add(value);
  }
}
const scriptUrlCache = new Map();
const scriptUrl = (sn) => {
  if (scriptUrlCache.has(sn)) return scriptUrlCache.get(sn);
  const elem = executeSrc.get(sn);
  const url = (elem && elementReqUrl.get(elem)) || pageUrl || null;
  scriptUrlCache.set(sn, url);
  return url;
};

// seed taint: value string -> Set(cookieName)
const taint = new Map();
const seedOrigins = (val, names) => {
  if (!val || val.length < MIN_SEED) return;
  let set = taint.get(val); if (!set) taint.set(val, set = new Set());
  for (const n of names) set.add(n);
};
for (const [name, c] of cookies) for (const v of c.values) seedOrigins(v, [name]);

// ---------------------------------------------------------------------------
// PASS 2 — rounds of taint propagation over js call / js result edges.
// Per cookie: consumers (every tainted call) + networkHits (tainted call whose
// method is a network sink, i.e. a request actually fired carrying the value).
// ---------------------------------------------------------------------------
const consumersByCookie = new Map();   // name -> Map(key -> record)   (dedup)
const netHitsByCookie = new Map();     // name -> Map(key -> record)
const rec = (map, name, key, val) => { let m = map.get(name); if (!m) map.set(name, m = new Map()); if (!m.has(key)) m.set(key, val); };

for (let round = 0; round < maxRounds; round++) {
  const before = taint.size;
  const seeds = [...taint.keys()];
  const pendingCall = new Map(); // call node id -> { args, method, script }
  for await (const el of streamElements(graphmlPath)) {
    if (el.tag !== "edge") continue;
    const et = eAttr(el.body, "edge type");
    if (et !== "js call" && et !== "js result") continue;
    const [s, t] = endpoints(el.head);
    if (et === "js call") {
      // s = script, t = call node
      const args = eAttr(el.body, "args");
      pendingCall.set(t, { args, method: webApiMethod.get(t) || "(unknown)", script: s });
      continue;
    }
    // js result: s = call node, t = script; value = return
    const call = pendingCall.get(s);
    pendingCall.delete(s);
    const value = eAttr(el.body, "value");
    const args = call ? call.args : null;
    const method = call ? call.method : (webApiMethod.get(s) || "(unknown)");
    const via = call ? call.script : t;
    if (!args) { // still may propagate nothing
      continue;
    }
    // which seeds appear in this call's args? Track WHICH seed matched per cookie
    // name: when two cookies' values sit in the same call args, a shared "first
    // seed found" would attribute cookie A's bytes to cookie B's record.
    let originNames = null;
    const seedByName = new Map(); // name -> the matched seed carrying that name
    for (const seed of seeds) {
      if (args.length >= seed.length && args.includes(seed)) {
        const names = taint.get(seed);
        if (!originNames) originNames = new Set();
        for (const n of names) {
          originNames.add(n);
          if (!seedByName.has(n)) seedByName.set(n, seed);
        }
      }
    }
    if (originNames) {
      const net = isNetworkSink(method);
      const dest = net ? destUrlFromArgs(args) : null;
      const viaUrl = via ? scriptUrl(via) : null;
      const key = `${method}|${viaUrl}|${dest || ""}`;
      for (const name of originNames) {
        const seed = seedByName.get(name);
        const idx = Math.max(0, args.indexOf(seed));
        const snip = args.slice(Math.max(0, idx - 30), idx + SNIP);
        rec(consumersByCookie, name, key, { method, viaScriptUrl: viaUrl, isNetworkSink: net, destUrl: dest, argSnippet: snip, round });
        // argSnippet/matchedValue on the NETWORK hit too — this record is what
        // cookie-evidence keeps, and the outbound bytes are the evidence.
        if (net) rec(netHitsByCookie, name, `${method}|${dest || viaUrl}`, { method, destUrl: dest, viaScriptUrl: viaUrl, round, argSnippet: snip, matchedValue: seed.slice(0, 500) });
      }
      // propagate: the return value becomes a new tainted value carrying same origins
      if (value != null) {
        const v = unwrap(value);
        if (v && v.length >= MIN_SEED && v.length <= MAX_SEED) seedOrigins(v, originNames);
      }
    }
  }
  if (taint.size === before) break; // fixpoint
}

// ---------------------------------------------------------------------------
// Assemble.
// ---------------------------------------------------------------------------
const detailFor = (name) => {
  const c = cookies.get(name);
  const cons = [...(consumersByCookie.get(name) || new Map()).values()];
  const hits = [...(netHitsByCookie.get(name) || new Map()).values()];
  const readers = [...c.readers].map((sn) => scriptUrl(sn));
  // requests fired by any script that consumed the value (corroboration)
  return {
    cookie: name,
    values: [...c.values],
    readerScripts: [...new Set(readers)],
    consumerCount: cons.length,
    consumers: cons,
    firedNetworkRequest: hits.length > 0,
    networkHits: hits,
  };
};
const indexEntry = (name) => {
  const d = detailFor(name);
  const methods = {};
  for (const con of d.consumers) methods[con.method] = (methods[con.method] || 0) + 1;
  return {
    cookie: name,
    consumerCount: d.consumerCount,
    consumerMethods: methods,
    firedNetworkRequest: d.firedNetworkRequest,
    networkDestinations: [...new Set(d.networkHits.map((h) => h.destUrl || h.viaScriptUrl).filter(Boolean))],
  };
};

const names = [...cookies.keys()].sort();
if (splitDir) {
  mkdirSync(splitDir, { recursive: true });
  const index = [];
  for (const name of names) {
    const safe = name.replace(/[^\w.-]/g, "_");
    writeFileSync(join(splitDir, `${safe}.flow.json`), JSON.stringify(detailFor(name), null, 2));
    index.push(indexEntry(name));
  }
  process.stdout.write(JSON.stringify({ pageUrl, cookieCount: names.length, index }, null, 2) + "\n");
} else if (onlyCookie) {
  if (!cookies.has(onlyCookie)) { process.stderr.write(`cookie not found: ${onlyCookie}\n`); process.exit(2); }
  process.stdout.write(JSON.stringify(detailFor(onlyCookie), null, 2) + "\n");
} else {
  process.stdout.write(JSON.stringify({ pageUrl, cookieCount: names.length, index: names.map(indexEntry) }, null, 2) + "\n");
}
