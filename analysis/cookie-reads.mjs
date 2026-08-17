#!/usr/bin/env node
// cookie-reads.mjs — from a PageGraph .graphml, extract for every cookie WHERE it
// was read (`.get` — document.cookie / cookieStore.get) and WHAT consumed the read
// value (any `js call` sink whose args contained the value — a network request OR
// an ordinary consumer function like JsonParse/btoa). Relies entirely on the
// PageGraph instrumentation; no CDP re-derivation.
//
//   node analysis/cookie-reads.mjs <graphml>                 # index: all cookies, compact
//   node analysis/cookie-reads.mjs <graphml> <cookieName>    # one cookie, full detail
//   node analysis/cookie-reads.mjs <graphml> --split <dir>   # write one detail file per
//                                                            # cookie into <dir> + print index
//
// Streaming + two-pass so it works on multi-GB graphs (readFileSync throws past
// V8's ~1GB max string length). Memory is bounded to the small node classes
// (cookie jar / script / web API / resource) and actual matches — never the DOM.
//
// NOTE for analysis: never infer what a cookie DOES from its name — names are
// misleading. Use the read sites + consumers this reports as the evidence.

import { createReadStream, openSync, readSync, closeSync } from "node:fs";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// The page url lives in <desc><url> near the top; read just the file head to get
// it (the whole graph can be multi-GB).
const readPageUrl = (path) => {
  const fd = openSync(path, "r");
  try {
    const b = Buffer.alloc(262144);
    const n = readSync(fd, b, 0, b.length, 0);
    const m = b.toString("utf8", 0, n).match(/<url>([^<]*)<\/url>/);
    return m ? m[1] : null;
  } finally {
    closeSync(fd);
  }
};

const argv = process.argv.slice(2);
const splitIdx = argv.indexOf("--split");
const splitDir = splitIdx !== -1 ? argv[splitIdx + 1] : null;
// positional args = everything that isn't a flag or a flag's value.
const splitValIdx = splitIdx !== -1 ? splitIdx + 1 : -1;
const positional = argv.filter(
  (a, i) => !a.startsWith("--") && i !== splitValIdx,
);
const graphmlPath = positional[0] || null;
const onlyCookie = positional[1] || null;

if (!graphmlPath) {
  process.stderr.write(
    "usage: node analysis/cookie-reads.mjs <graphml> [cookieName] [--split <dir>]\n",
  );
  process.exit(1);
}

const PREVIEW = 60; // value preview length in the index
const ARG_SNIPPET = 240; // consumer arg snippet length in detail mode

const unescapeXml = (s) =>
  s == null
    ? null
    : s
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&amp;/g, "&");

// Network-sink web API methods (everything else that consumes a value is a plain
// consumer function, which is still reported — just not flagged network).
const isNetworkSink = (method) =>
  /(?:^|\.)fetch\b|XMLHttpRequest\.(?:open|send|setRequestHeader)\b|sendBeacon\b|(?:^|\.)WebSocket\b|EventSource\b|HTML(?:Image|Script|Link|Media|IFrame)Element\.src\b|Navigator\.sendBeacon\b/i.test(
    method || "",
  );

// Pull a URL-ish argument out of a parsed js-call args array (fetch(url,..),
// xhr.open(method,url,..), new Image().src=url, sendBeacon(url,..)).
const destUrlFromArgs = (argsRaw) => {
  try {
    const arr = JSON.parse(argsRaw);
    for (const a of Array.isArray(arr) ? arr : []) {
      if (typeof a === "string" && /^(https?:)?\/\/|^\//.test(a)) return a;
    }
  } catch {
    /* args not JSON-parseable; fall through */
  }
  return null;
};

// ---- streaming element extractor -------------------------------------------
// Yields { tag, attrs, body } for each <node>/<edge>/<key> element. Data values
// are XML-escaped, so a literal `</node>` never appears inside one; scanning for
// the close tag is safe. Keeps a carry buffer across chunk boundaries.
async function* streamElements(path) {
  const stream = createReadStream(path, { encoding: "utf8" });
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
      if (end !== -1) {
        after = end + closeTag.length;
      } else {
        // maybe a self-closed element like <key .../>
        const selfClose = buf.indexOf("/>", openRe.lastIndex);
        const nextOpen = buf.indexOf("<", openRe.lastIndex);
        if (selfClose !== -1 && (nextOpen === -1 || selfClose < nextOpen)) {
          after = selfClose + 2;
          end = -2; // self-closed marker
        } else {
          break; // incomplete element; wait for more chunks
        }
      }
      const raw = buf.slice(start, after);
      const headEnd = raw.indexOf(">");
      const head = raw.slice(0, headEnd);
      const body = end === -2 ? "" : raw.slice(headEnd + 1, raw.length - closeTag.length);
      yield { tag, head, body };
      consumedTo = after;
      openRe.lastIndex = after;
    }
    buf = buf.slice(consumedTo);
  }
}

// ---- key table + attr helpers ----------------------------------------------
const keysByFor = { edge: {}, node: {} };
const attrId = (head, name) => {
  const m = head.match(/for="(edge|node)"/);
  const nm = head.match(/attr\.name="([^"]*)"/);
  const id = head.match(/id="(d\d+)"/);
  if (m && nm && id) keysByFor[m[1]][nm[1]] = id[1];
};
const attr = (kind) => (body, name) => {
  const kid = keysByFor[kind][name];
  if (!kid || body == null) return null;
  const m = body.match(new RegExp(`key="${kid}">([\\s\\S]*?)</data>`));
  return m ? unescapeXml(m[1]) : null;
};
const eAttr = attr("edge");
const nAttr = attr("node");
const idOf = (head) => (head.match(/id="(n\d+)"/) || [])[1];
const endpoints = (head) => {
  const s = head.match(/source="(n\d+)"/);
  const t = head.match(/target="(n\d+)"/);
  return [s && s[1], t && t[1]];
};

// PageGraph records string values JSON-quoted (`"isoLoc=US_CA_t3"`); unwrap the
// outer quoting to get the real string before parsing/matching.
const unwrap = (v) => {
  if (v == null) return v;
  if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') {
    try {
      const p = JSON.parse(v);
      if (typeof p === "string") return p;
    } catch {
      return v.slice(1, -1);
    }
  }
  return v;
};

// ---- parse a document.cookie jar string into name -> value -----------------
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

// ============================================================================
// PASS 1 — nodes + non-jscall edges: cookie values, readers, .get sites, and
// the maps needed to resolve a script node to its source URL.
// ============================================================================
let pageUrl = readPageUrl(graphmlPath);
let cookieJarId = null;
const scriptIds = new Set(); // script node ids
const webApiMethod = new Map(); // web API / JS builtin node id -> method
const resourceUrl = new Map(); // resource node id -> url
const executeSrc = new Map(); // script node id -> element node id (execute edge)
const elementReqUrl = new Map(); // element/script node id -> resource url (request edge)

// cookie name -> { values:Set, readers:Map(scriptNode -> true) }
const cookies = new Map();
const cookieOf = (name) => {
  let c = cookies.get(name);
  if (!c) {
    c = { values: new Set(), readers: new Set() };
    cookies.set(name, c);
  }
  return c;
};
// script node -> Set of `.get` call positions on the cookie jar
const getSites = new Map();

for await (const el of streamElements(graphmlPath)) {
  if (el.tag === "key") {
    attrId(el.head, null);
    continue;
  }
  if (el.tag === "node") {
    const id = idOf(el.head);
    const type = nAttr(el.body, "node type");
    if (type === "cookie jar") cookieJarId = id;
    else if (type === "script") scriptIds.add(id);
    else if (type === "web API" || type === "JS builtin")
      webApiMethod.set(id, nAttr(el.body, "method") || nAttr(el.body, "id"));
    else if (type === "resource") resourceUrl.set(id, nAttr(el.body, "url"));
    continue;
  }
  // edge
  const et = eAttr(el.body, "edge type");
  if (!et) continue;
  const [s, t] = endpoints(el.head);
  if (et === "execute") {
    if (t) executeSrc.set(t, s);
  } else if (et === "request start" || et === "request complete") {
    const url = t && resourceUrl.get(t);
    if (s && url && !elementReqUrl.has(s)) elementReqUrl.set(s, url);
  } else if (et === "storage read result" && s === cookieJarId) {
    // jar -> script. On the cookie jar the edge `key` is the document URL
    // (context), NOT a cookie name; the `value` is the whole document.cookie
    // string. Parse it into name=value pairs and attribute each to the reader.
    const value = unwrap(eAttr(el.body, "value"));
    for (const [name, val] of parseJar(value)) {
      const c = cookieOf(name);
      if (val) c.values.add(val);
      if (t) c.readers.add(t);
    }
  } else if (et === "read storage call" && t === cookieJarId) {
    // script -> jar; the `.get` call site. `document.cookie` returns the whole
    // jar, so a site isn't per-cookie — record it against the script; the
    // cookies actually read come from the paired storage-read-result value.
    if (s) {
      let set = getSites.get(s);
      if (!set) getSites.set(s, (set = new Set()));
      const pos = eAttr(el.body, "script position");
      set.add(pos == null ? "?" : pos);
    }
  } else if (et === "storage set" && t === cookieJarId) {
    const key = eAttr(el.body, "key");
    // A `storage set` records the whole `document.cookie` assignment, ATTRIBUTES
    // INCLUDED (`v; path=/; domain=.x.com`). Seeding the taint set with that string
    // makes unrelated cookies share the `; path=/; domain=…` boilerplate and match
    // it everywhere, fabricating consumers. A cookie value cannot contain an
    // unencoded ";", so truncating at the first one is always correct.
    const value = unwrap(eAttr(el.body, "value"))?.split(";")[0].trim();
    if (key && value) cookieOf(key).values.add(value);
  }
}
// resolve a script node -> source URL (external script's src, else page url)
const scriptUrlCache = new Map();
const scriptUrl = (scriptNode) => {
  if (scriptUrlCache.has(scriptNode)) return scriptUrlCache.get(scriptNode);
  const elem = executeSrc.get(scriptNode);
  const url = (elem && elementReqUrl.get(elem)) || pageUrl || null;
  scriptUrlCache.set(scriptNode, url);
  return url;
};

// Build the value set to match consumers against (skip trivially short/empty
// values that would match everything).
const valueToCookies = new Map(); // value string -> Set(cookieName)
for (const [name, c] of cookies) {
  for (const v of c.values) {
    if (v && v.length >= 6) {
      let set = valueToCookies.get(v);
      if (!set) valueToCookies.set(v, (set = new Set()));
      set.add(name);
    }
  }
}
const distinctValues = [...valueToCookies.keys()];

// ============================================================================
// PASS 2 — js call edges only: match each call's args against known cookie
// values; record the consumers (network sinks and plain functions alike).
// ============================================================================
// cookie name -> array of consumer records
const consumers = new Map();
const addConsumer = (name, rec) => {
  let arr = consumers.get(name);
  if (!arr) consumers.set(name, (arr = []));
  arr.push(rec);
};

if (distinctValues.length > 0) {
  for await (const el of streamElements(graphmlPath)) {
    if (el.tag !== "edge") continue;
    if (eAttr(el.body, "edge type") !== "js call") continue;
    const argsRaw = eAttr(el.body, "args");
    if (!argsRaw) continue;
    // quick reject: only run the (few) value checks if args is non-trivial
    let matched = null;
    for (const v of distinctValues) {
      if (argsRaw.includes(v)) {
        matched = v;
        break;
      }
    }
    if (!matched) continue;
    const [s, t] = endpoints(el.head);
    const method = (t && webApiMethod.get(t)) || "(unknown)";
    const idx = argsRaw.indexOf(matched);
    const snippet = argsRaw.slice(
      Math.max(0, idx - 40),
      idx + Math.min(matched.length + 40, ARG_SNIPPET),
    );
    const rec = {
      method,
      isNetworkSink: isNetworkSink(method),
      viaScriptUrl: s ? scriptUrl(s) : null,
      destUrl: destUrlFromArgs(argsRaw),
      argSnippet: snippet,
    };
    for (const name of valueToCookies.get(matched)) addConsumer(name, rec);
  }
}

// ============================================================================
// Assemble per-cookie records.
// ============================================================================
const detailFor = (name) => {
  const c = cookies.get(name);
  const readers = [...c.readers].map((sn) => ({
    scriptUrl: scriptUrl(sn),
    scriptNode: sn,
    getSites: [...(getSites.get(sn) || [])],
  }));
  const cons = consumers.get(name) || [];
  return {
    cookie: name,
    valuePreview: [...c.values][0]?.slice(0, PREVIEW) ?? null,
    values: [...c.values],
    readCount: readers.length,
    readers,
    consumerCount: cons.length,
    consumers: cons,
  };
};

const indexEntry = (name) => {
  const d = detailFor(name);
  const methods = {};
  const dests = new Set();
  for (const con of d.consumers) {
    methods[con.method] = (methods[con.method] || 0) + 1;
    if (con.isNetworkSink && con.destUrl) dests.add(con.destUrl);
  }
  const detailBytes = Buffer.byteLength(JSON.stringify(d));
  return {
    cookie: name,
    valuePreview: d.valuePreview,
    readCount: d.readCount,
    readerScripts: [...new Set(d.readers.map((r) => r.scriptUrl))],
    consumerCount: d.consumerCount,
    consumerMethods: methods,
    networkDestinations: [...dests],
    detailBytes, // size hint so a driver can batch small cookies / split large ones
  };
};

const names = [...cookies.keys()].sort();

if (splitDir) {
  mkdirSync(splitDir, { recursive: true });
  const index = [];
  for (const name of names) {
    const safe = name.replace(/[^\w.-]/g, "_");
    const file = join(splitDir, `${safe}.json`);
    writeFileSync(file, JSON.stringify(detailFor(name), null, 2));
    index.push({ ...indexEntry(name), file });
  }
  index.sort((a, b) => b.detailBytes - a.detailBytes);
  process.stdout.write(
    JSON.stringify({ pageUrl, cookieCount: names.length, index }, null, 2) + "\n",
  );
} else if (onlyCookie) {
  if (!cookies.has(onlyCookie)) {
    process.stderr.write(`cookie not found in graph: ${onlyCookie}\n`);
    process.exit(2);
  }
  process.stdout.write(JSON.stringify(detailFor(onlyCookie), null, 2) + "\n");
} else {
  const index = names.map(indexEntry).sort((a, b) => b.detailBytes - a.detailBytes);
  process.stdout.write(
    JSON.stringify({ pageUrl, cookieCount: names.length, index }, null, 2) + "\n",
  );
}
