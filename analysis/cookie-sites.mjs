#!/usr/bin/env node
// cookie-sites.mjs — extract a cookie's write / delete / read sites from a
// PageGraph .graphml, resolve each acting script to its source URL, and emit
// ready-to-use `--debug-breakpoint` specs.
//
//   node analysis/cookie-sites.mjs <graphml> <cookieName>
//
// Output (stdout): JSON { cookie, pageUrl, writes[], deletes[], reads{}, writeSpecs[] }.
// Each write/delete carries { offset, scriptUrl, inline, value, source, timestamp, spec }.
// `spec` is "<escapedScriptUrl>#<offset>" for external scripts (feed straight to
// `--debug-breakpoint`); null for inline scripts (offset is document-relative).

import { readFileSync } from "node:fs";

const [, , graphmlPath, cookieName] = process.argv;
if (!graphmlPath || !cookieName) {
  process.stderr.write(
    "usage: node analysis/cookie-sites.mjs <graphml> <cookieName>\n",
  );
  process.exit(1);
}

const data = readFileSync(graphmlPath, "utf8");

// attr.name -> data-key id, scoped by `for` (some names like "timestamp" /
// "id" / "frame id" are defined for BOTH node and edge with different key ids).
const keysByFor = { edge: {}, node: {} };
for (const m of data.matchAll(
  /<key id="(d\d+)" for="(edge|node)" attr\.name="([^"]*)"/g,
)) {
  keysByFor[m[2]][m[3]] = m[1];
}

const nodes = new Map();
for (const m of data.matchAll(/<node id="(n\d+)">([\s\S]*?)<\/node>/g)) {
  nodes.set(m[1], m[2]);
}
const edges = [];
for (const m of data.matchAll(
  /<edge id="e\d+" source="(n\d+)" target="(n\d+)">([\s\S]*?)<\/edge>/g,
)) {
  edges.push([m[1], m[2], m[3]]);
}

const unescapeXml = (s) =>
  s == null
    ? null
    : s
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&amp;/g, "&");

const attrFor = (kind) => (body, name) => {
  const kid = keysByFor[kind][name];
  if (!kid || body == null) return null;
  const m = body.match(new RegExp(`key="${kid}">([^<]*)</data>`));
  return m ? unescapeXml(m[1]) : null;
};
const eAttr = attrFor("edge");
const nAttr = attrFor("node");

const edgeType = (b) => eAttr(b, "edge type");

const pageUrl = (() => {
  const m = data.match(/<url>([^<]*)<\/url>/);
  return m ? m[1] : null;
})();

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// script node -> { url, inline } via:  <script> elem --execute--> script node,
//                                       <script> elem --request--> resource(url)
const urlCache = new Map();
const resolveScriptUrl = (scriptNodeId) => {
  if (urlCache.has(scriptNodeId)) return urlCache.get(scriptNodeId);
  let result = { url: pageUrl, inline: true };
  for (const [s, t, b] of edges) {
    if (t !== scriptNodeId || edgeType(b) !== "execute") continue;
    const elem = s;
    for (const [s2, t2, b2] of edges) {
      if (s2 !== elem) continue;
      const et = edgeType(b2);
      if (et !== "request start" && et !== "request complete") continue;
      const u = nAttr(nodes.get(t2), "url");
      if (u) {
        result = { url: u, inline: false };
        break;
      }
    }
    break;
  }
  urlCache.set(scriptNodeId, result);
  return result;
};

const cookieJarId = [...nodes].find(([, b]) => nAttr(b, "node type") === "cookie jar")?.[0];

const makeSpec = (url, inline, offset) =>
  !inline && offset != null && url ? `${escapeRegex(url)}#${offset}` : null;

const writes = [];
const deletes = [];
const readSites = [];
const readersReturningCookie = new Set();
const seenReadSite = new Set();

const cookieEq = `${cookieName}=`;

for (const [s, t, b] of edges) {
  const et = edgeType(b);
  if (et === "storage set" && eAttr(b, "key") === cookieName) {
    const { url, inline } = resolveScriptUrl(s);
    const offset = eAttr(b, "script position");
    const off = offset != null ? Number(offset) : null;
    writes.push({
      offset: off,
      scriptUrl: url,
      inline,
      value: eAttr(b, "value"),
      source: eAttr(b, "cookie source"),
      timestamp: eAttr(b, "timestamp"),
      spec: makeSpec(url, inline, off),
    });
  } else if (et === "delete storage" && eAttr(b, "key") === cookieName) {
    const { url, inline } = resolveScriptUrl(s);
    const offset = eAttr(b, "script position");
    const off = offset != null ? Number(offset) : null;
    deletes.push({
      offset: off,
      scriptUrl: url,
      inline,
      timestamp: eAttr(b, "timestamp"),
      spec: makeSpec(url, inline, off),
    });
  } else if (et === "read storage call" && t === cookieJarId) {
    // document.cookie reads return the whole jar (not keyed per cookie).
    const { url, inline } = resolveScriptUrl(s);
    const offset = eAttr(b, "script position");
    const off = offset != null ? Number(offset) : null;
    const sig = `${url}#${off}`;
    if (!seenReadSite.has(sig)) {
      seenReadSite.add(sig);
      readSites.push({ offset: off, scriptUrl: url, inline, spec: makeSpec(url, inline, off) });
    }
  } else if (et === "storage read result" && s === cookieJarId) {
    // Reads whose returned value actually contained this cookie.
    const val = eAttr(b, "value");
    if (val && val.includes(cookieEq)) {
      const { url } = resolveScriptUrl(t);
      if (url) readersReturningCookie.add(url);
    }
  }
}

const writeSpecs = [...new Set(writes.map((w) => w.spec).filter(Boolean))];

const out = {
  cookie: cookieName,
  pageUrl,
  writes,
  deletes,
  reads: {
    note: "document.cookie reads return the whole jar; offsets are read sites on the cookie jar.",
    sites: readSites.slice(0, 40),
    readersReturningCookie: [...readersReturningCookie],
  },
  writeSpecs,
};

process.stdout.write(JSON.stringify(out, null, 2) + "\n");
