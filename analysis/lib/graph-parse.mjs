// graph-parse.mjs — shared streaming + parsing primitives for the PageGraph graphml.
//
// Extracted verbatim from cookie-code-trace.mjs so the cookie-code tools (cookie-code-trace,
// cookie-code-sites, resolve-cookie-reads) share ONE implementation of the fiddly bits: the
// carry-buffer streamer, the graphml key table, byte-offset → source windows, and stack decoding.
// Never readFileSync a multi-GB graphml — everything here streams.

// Opening the graph lives in graph-source.mjs: a graph may be stored plain or archived as .zst,
// and every reader here works the same either way. `readPageUrl` is ASYNC now — a zstd frame
// cannot be pread from an arbitrary byte range, so the header has to be streamed. Callers are ESM
// and use top-level await.
import { graphStream, readPageUrl, graphBase, isGraphPath, resolveGraphPath, graphExists } from "./graph-source.mjs";

export { readPageUrl, graphBase, isGraphPath, resolveGraphPath, graphStream, graphExists };

export const un = (s) => s == null ? null : s
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
  .replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, "&");

// Yield each <node>/<edge>/<key> element as {tag, head, body}. Bounds the carry buffer so millions of
// uninteresting elements streaming past cannot grow it past V8's max string length.
export async function* stream(path) {
  const st = graphStream(path);
  let buf = "";
  const open = /<(node|edge|key)\b/g;
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
    buf = buf.slice(consumed);
    if (buf.length > 1 << 20) { open.lastIndex = 0; const nxt = open.exec(buf); buf = nxt ? buf.slice(nxt.index) : buf.slice(-64); }
  }
}

// A per-parse key table: graphml maps attribute names to dN ids in <key> headers. Build one table per
// stream (call `key` on every <key> element), then read attributes off node/edge bodies with nA/eA.
export const makeKeys = () => {
  const K = { edge: {}, node: {} };
  const key = (h) => { const f = h.match(/for="(edge|node)"/), n = h.match(/attr\.name="([^"]*)"/), i = h.match(/id="(d\d+)"/); if (f && n && i) K[f[1]][n[1]] = i[1]; };
  const mk = (kind) => (body, name) => {
    const id = K[kind][name];
    if (!id || body == null) return null;
    const m = body.match(new RegExp(`key="${id}">([\\s\\S]*?)</data>`));
    return m ? un(m[1]) : null;
  };
  return { K, key, nA: mk("node"), eA: mk("edge") };
};

export const idOf = (h) => (h.match(/id="(n\d+)"/) || [])[1];
export const ends = (h) => [(h.match(/source="(n\d+)"/) || [])[1], (h.match(/target="(n\d+)"/) || [])[1]];

export const unwrap = (v) => {
  if (v == null) return v;
  if (v.length >= 2 && v[0] === '"' && v.at(-1) === '"') {
    try { const p = JSON.parse(v); if (typeof p === "string") return p; } catch { return v.slice(1, -1); }
  }
  return v;
};
export const valueOnly = (v) => v == null ? v : String(v).split(";")[0].trim();
export const parseJar = (s) => {
  const o = [];
  if (!s) return o;
  for (const p of s.split(";")) { const e = p.indexOf("="); if (e === -1) continue; const n = p.slice(0, e).trim(), v = p.slice(e + 1).trim(); if (n) o.push([n, v]); }
  return o;
};

// byte offset -> {line, col, offset, before, after} — a raw source window around the offset. Callers
// format (e.g. newline markers) themselves. ctxAfter defaults to ctxBefore (symmetric window).
export const codeWindow = (src, off, ctxBefore = 320, ctxAfter = ctxBefore) => {
  if (src == null || off == null || !Number.isFinite(off)) return null;
  const o = Math.max(0, Math.min(off, src.length));
  const line = src.slice(0, o).split("\n").length;
  const col = o - (src.lastIndexOf("\n", o - 1) + 1);
  return { line, col, offset: o, before: src.slice(Math.max(0, o - ctxBefore), o), after: src.slice(o, Math.min(src.length, o + ctxAfter)) };
};

// line/col -> byte offset (stack frames are 0-based line/col)
export const fromLineCol = (src, line, col) => {
  if (src == null) return null;
  const lines = src.split("\n");
  if (line < 0 || line >= lines.length) return null;
  let off = 0;
  for (let i = 0; i < line; i++) off += lines[i].length + 1;
  return off + Math.max(0, Math.min(col, lines[line].length));
};

// Flatten a PageGraph stack-trace JSON into an ordered frame list (each frame keeps its raw fields
// plus an `async` marker for parent stacks). Callers reshape as needed.
export const decodeStack = (raw) => {
  if (!raw) return [];
  let o; try { o = JSON.parse(raw); } catch { return []; }
  const out = [];
  const walk = (st, depth) => {
    if (!st) return;
    for (const f of st.callFrames || []) out.push({ ...f, async: depth > 0 });
    if (st.parent) walk(st.parent, depth + 1);
  };
  walk(o, 0);
  return out;
};
