// Streaming GraphML reader shared by the analysis scripts.
//
// Extracted verbatim from cookie-flow.mjs, where this same code had been
// copy-pasted into roughly nine scripts. New scripts should import from here.
// The existing copies still work and have not been migrated — that is a
// mechanical change best done with each script's own assertions in hand.
//
// Never readFileSync a graphml: real captures reach multiple GB, well past
// V8's max string length. Everything here streams.

import { createReadStream, openSync, readSync, closeSync } from "node:fs";

export const unescapeXml = (s) =>
  s == null
    ? null
    : s
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&amp;/g, "&");

// The crawled page's URL, read from the head of the file without loading it all.
export const readPageUrl = (path) => {
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

// Yields every <node>, <edge> and <key> element as {tag, head, body}, holding
// only a partial element in memory at a time.
export async function* streamElements(path) {
  yield* streamElementsFiltered(path, ["node", "edge", "key"]);
}

/**
 * The same scanner, restricted to the tags you actually want.
 *
 * Filtering is the whole point on a multi-GB graph — `create node` alone is the highest-volume
 * edge type — but it introduces a failure the unfiltered version cannot have. When nothing in a
 * chunk matches, `consumedTo` stays 0, so the carry buffer keeps every byte that streamed past.
 * On a graph where the interesting elements are sparse that grows until it exceeds V8's maximum
 * string length and the process dies with an unhelpful error. Hence the bound below.
 *
 * ALWAYS include "key" in `tags`: attribute ids (dNN) are only resolvable from the <key> block,
 * and it appears once at the head of the file.
 */
export async function* streamElementsFiltered(path, tags) {
  const stream = createReadStream(path, { encoding: "utf8" });
  let buf = "";
  const openRe = new RegExp(`<(${tags.join("|")})\\b`, "g");
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
        if (selfClose !== -1 && (nextOpen === -1 || selfClose < nextOpen)) {
          after = selfClose + 2;
          end = -2;
        } else break;
      }
      const raw = buf.slice(start, after);
      const headEnd = raw.indexOf(">");
      yield {
        tag,
        head: raw.slice(0, headEnd),
        body:
          end === -2 ? "" : raw.slice(headEnd + 1, raw.length - closeTag.length),
      };
      consumedTo = after;
      openRe.lastIndex = after;
    }
    buf = buf.slice(consumedTo);
    // Keep only from the earliest unconsumed opening tag — an element may legitimately span
    // chunks and be large (a stack trace runs to tens of KB). With no opening tag at all, keep
    // just enough to catch a tag split across the chunk boundary.
    if (buf.length > 1 << 20) {
      openRe.lastIndex = 0;
      const next = openRe.exec(buf);
      buf = next ? buf.slice(next.index) : buf.slice(-64);
    }
  }
}

// Attribute ids (dNN) are assigned by the engine in enum order and shift when
// the engine adds an attribute, so always resolve them by attr.name from the
// <key> block rather than hardcoding.
export const makeAttrReader = () => {
  const keysByFor = { edge: {}, node: {} };
  const noteKey = (head) => {
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
  return { noteKey, eAttr: mk("edge"), nAttr: mk("node"), keysByFor };
};

export const idOf = (head) => (head.match(/id="(n\d+)"/) || [])[1];
export const edgeIdOf = (head) => (head.match(/id="(e\d+)"/) || [])[1];
export const endpoints = (head) => [
  (head.match(/source="(n\d+)"/) || [])[1],
  (head.match(/target="(n\d+)"/) || [])[1],
];

// Graph values are sometimes JSON-quoted strings; unwrap one level.
export const unwrap = (v) => {
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
