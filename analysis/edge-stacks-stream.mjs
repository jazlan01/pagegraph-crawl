#!/usr/bin/env node
// Streaming variant of edge-stacks.mjs for multi-GB graphs.
//   node analysis/edge-stacks-stream.mjs <graphml> [--key STR] [--type STR] [--all] [--frames N] [--json]
import { createReadStream } from "node:fs";

const args = process.argv.slice(2);
const graphmlPath = args.find((a) => !a.startsWith("--"));
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] !== undefined ? args[i + 1] : dflt;
};
const has = (name) => args.includes(name);
const asJson = has("--json");
const maxFrames = Number(opt("--frames", "8"));
const keyFilter = opt("--key", null);
const typeFilter = opt("--type", null);
const includeAll = has("--all");

const defaultCookieTypes = [
  "storage set",
  "delete storage",
  "read storage call",
  "storage read result",
];
const wantedTypes = typeFilter
  ? typeFilter.split(",").map((s) => s.trim())
  : includeAll
    ? null
    : defaultCookieTypes;

const unescapeXml = (s) =>
  s == null
    ? null
    : s
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&amp;/g, "&");

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
        const selfClose = buf.indexOf("/>", openRe.lastIndex);
        const nextOpen = buf.indexOf("<", openRe.lastIndex);
        if (selfClose !== -1 && (nextOpen === -1 || selfClose < nextOpen)) {
          after = selfClose + 2;
          end = -2;
        } else break;
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

const keysByFor = { edge: {}, node: {} };
const attrId = (head) => {
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

// Pass 1: script node v8 id -> {nodeId,url}. Also collect matching edges (buffer
// raw, resolve frames after we have script map — but script nodes precede edges
// typically; to be safe do two streams).
const scriptNodeByV8Id = new Map();
const matches = [];
for await (const el of streamElements(graphmlPath)) {
  if (el.tag === "key") { attrId(el.head); continue; }
  if (el.tag === "node") {
    if (nAttr(el.body, "node type") === "script") {
      const v8 = nAttr(el.body, "script id");
      if (v8 != null) scriptNodeByV8Id.set(String(v8), { nodeId: idOf(el.head), url: nAttr(el.body, "url") });
    }
    continue;
  }
  if (el.tag === "edge") {
    const edgeType = eAttr(el.body, "edge type");
    if (wantedTypes && !wantedTypes.some((t) => (edgeType || "").includes(t))) continue;
    if (keyFilter && eAttr(el.body, "key") !== keyFilter) continue;
    const stackRaw = eAttr(el.body, "stack trace");
    const s = el.head.match(/source="(n\d+)"/);
    const t = el.head.match(/target="(n\d+)"/);
    matches.push({
      edgeId: (el.head.match(/id="(e\d+)"/) || [])[1],
      source: s && s[1], target: t && t[1],
      edgeType, key: eAttr(el.body, "key"),
      value: eAttr(el.body, "value"),
      cookieSource: eAttr(el.body, "cookie source"),
      timestamp: eAttr(el.body, "timestamp"),
      stackRaw,
    });
  }
}

const flattenFrames = (stack) => {
  const out = [];
  let node = stack, asyncLabel = null;
  while (node) {
    out.push({ asyncLabel, frames: node.callFrames || [] });
    asyncLabel = node.parent ? node.parent.description || "async" : null;
    node = node.parent;
  }
  return out;
};
const describeFrame = (f) => {
  const fn = f.functionName || "(anonymous)";
  const where = f.url ? `${f.url}:${f.lineNumber}:${f.columnNumber}` : "(native)";
  const node = scriptNodeByV8Id.get(String(f.scriptId));
  return `${fn} @ ${where}${node ? ` [script node ${node.nodeId}]` : ""}`;
};

const results = matches.map((r) => {
  let stack = null;
  if (r.stackRaw) { try { stack = JSON.parse(r.stackRaw); } catch {} }
  return { ...r, stack, stackRaw: undefined };
});

if (asJson) { process.stdout.write(JSON.stringify(results, null, 2) + "\n"); process.exit(0); }
if (results.length === 0) { process.stdout.write("No matching edges.\n"); process.exit(0); }
for (const r of results) {
  const head = [r.edgeType, r.key, (r.value||"").slice(0,60)].filter(Boolean).join("  ");
  process.stdout.write(`\n== ${r.edgeId} (${r.source} -> ${r.target})  ${head}` +
    (r.cookieSource ? `  [source=${r.cookieSource}]` : "") +
    (r.timestamp ? `  @${r.timestamp}ms` : "") + "\n");
  if (!r.stack) { process.stdout.write("   (no stack)\n"); continue; }
  for (const group of flattenFrames(r.stack)) {
    if (group.asyncLabel) process.stdout.write(`   --- async: ${group.asyncLabel} ---\n`);
    for (const f of group.frames.slice(0, maxFrames)) process.stdout.write(`   at ${describeFrame(f)}\n`);
  }
}
