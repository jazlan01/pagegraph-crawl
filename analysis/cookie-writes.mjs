#!/usr/bin/env node
// cookie-writes.mjs — streaming, ALL-COOKIES write/delete provenance.
//
//   node analysis/cookie-writes.mjs <graphml> [cookieName] [--json]
//
// The streaming twin of `cookie-sites.mjs` (same relationship as
// `edge-stacks.mjs` -> `edge-stacks-stream.mjs`). Two reasons it exists:
//
//  1. `cookie-sites.mjs` uses `readFileSync`, so it cannot touch multi-GB graphs —
//     on those, JS write provenance was simply unavailable and every cookie's
//     `setChannel` came back "unknown".
//  2. It reports EVERY cookie in ONE pass. `cookie-sites.mjs` takes a single cookie
//     name, so a driver had to invoke it once per cookie — N full parses of the
//     same graph. This does it once.
//
// Emits, per cookie: the `storage set` / `delete storage` edges targeting the
// cookie jar, each resolved to the writing script's source URL, plus the
// `cookie source` channel (js | cookie-store | set-cookie-header).

import { graphStream, readPageUrl } from "./lib/graph-source.mjs";

const argv = process.argv.slice(2);
const asJson = argv.includes("--json");
const positional = argv.filter((a) => !a.startsWith("--"));
const graphmlPath = positional[0];
const onlyCookie = positional[1] || null;
if (!graphmlPath) {
  process.stderr.write("usage: node analysis/cookie-writes.mjs <graphml> [cookieName] [--json]\n");
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
const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// ---------------------------------------------------------------------------
// One streaming pass. Node maps and the resolution edges (execute / request) are
// interleaved with the storage edges, so storage edges are buffered and resolved
// after the stream completes.
// ---------------------------------------------------------------------------
const pageUrl = await readPageUrl(graphmlPath);
let cookieJarId = null;
const resourceUrl = new Map();   // resource node -> url
const executeSrc = new Map();    // script node -> element node
const elementReqUrl = new Map(); // element node -> requested url
const pendingWrites = [];        // { kind, s, key, value, source, position, timestamp }

for await (const el of streamElements(graphmlPath)) {
  if (el.tag === "key") { attrId(el.head); continue; }
  if (el.tag === "node") {
    const type = nAttr(el.body, "node type");
    if (type === "cookie jar") cookieJarId = idOf(el.head);
    else if (type === "resource") resourceUrl.set(idOf(el.head), nAttr(el.body, "url"));
    continue;
  }
  const et = eAttr(el.body, "edge type");
  if (!et) continue;
  const [s, t] = endpoints(el.head);
  if (et === "execute") { if (t) executeSrc.set(t, s); continue; }
  if (et === "request start" || et === "request complete") {
    const url = t && resourceUrl.get(t);
    if (s && url && !elementReqUrl.has(s)) elementReqUrl.set(s, url);
    continue;
  }
  if (et !== "storage set" && et !== "delete storage") continue;
  // `storage set` targets the jar; HTTP-synthesised edges also target it.
  if (t !== cookieJarId && cookieJarId !== null) continue;
  const key = eAttr(el.body, "key");
  if (!key || (onlyCookie && key !== onlyCookie)) continue;
  pendingWrites.push({
    kind: et === "storage set" ? "set" : "delete",
    s,
    key,
    value: eAttr(el.body, "value"),
    source: eAttr(el.body, "cookie source"),
    position: eAttr(el.body, "script position"),
    timestamp: eAttr(el.body, "timestamp"),
    requestId: eAttr(el.body, "request id"),
  });
}

// resolve a script node -> its source URL (external script src, else the page)
const urlCache = new Map();
const resolveScript = (scriptNode) => {
  if (urlCache.has(scriptNode)) return urlCache.get(scriptNode);
  const elem = executeSrc.get(scriptNode);
  const u = (elem && elementReqUrl.get(elem)) || null;
  const res = u ? { url: u, inline: false } : { url: pageUrl, inline: true };
  urlCache.set(scriptNode, res);
  return res;
};

// ---------------------------------------------------------------------------
// Assemble per cookie.
// ---------------------------------------------------------------------------
const cookies = new Map();
const recOf = (name) => {
  let r = cookies.get(name);
  if (!r) cookies.set(name, (r = { cookie: name, writes: [], deletes: [], writeSpecs: [] }));
  return r;
};
for (const w of pendingWrites) {
  const r = recOf(w.key);
  // A set-cookie-header edge is synthesised from a response: its "actor" is the
  // resource node, not a script, so resolve it as a URL directly.
  const isHeader = w.source === "set-cookie-header";
  const resolved = isHeader
    ? { url: resourceUrl.get(w.s) || null, inline: false }
    : resolveScript(w.s);
  const off = w.position != null ? Number(w.position) : null;
  const entry = {
    scriptUrl: resolved.url,
    inline: resolved.inline,
    offset: off,
    source: w.source,
    timestamp: w.timestamp,
    requestId: w.requestId,
    spec: !resolved.inline && off != null && resolved.url ? `${escapeRegex(resolved.url)}#${off}` : null,
  };
  if (w.kind === "set") {
    entry.value = w.value;
    r.writes.push(entry);
  } else {
    r.deletes.push(entry);
  }
}
for (const r of cookies.values()) {
  r.writeSpecs = [...new Set(r.writes.map((w) => w.spec).filter(Boolean))];
}

const names = [...cookies.keys()].sort();
const out = { pageUrl, cookieCount: names.length, cookies: Object.fromEntries(names.map((n) => [n, cookies.get(n)])) };

if (onlyCookie) {
  process.stdout.write(JSON.stringify(cookies.get(onlyCookie) ?? { cookie: onlyCookie, writes: [], deletes: [], writeSpecs: [] }, null, 2) + "\n");
} else if (asJson) {
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
} else {
  process.stdout.write(`page: ${pageUrl}\ncookies with write/delete edges: ${names.length}\n\n`);
  for (const n of names) {
    const r = cookies.get(n);
    const chans = [...new Set(r.writes.map((w) => w.source || "?"))].join(",");
    const hosts = [...new Set(r.writes.map((w) => { try { return new URL(w.scriptUrl).hostname; } catch { return w.scriptUrl; } }).filter(Boolean))];
    process.stdout.write(`${n}: ${r.writes.length} write(s) [${chans}], ${r.deletes.length} delete(s) <- ${hosts.join(", ") || "?"}\n`);
  }
}
