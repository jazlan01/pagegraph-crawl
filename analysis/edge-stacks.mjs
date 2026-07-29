#!/usr/bin/env node
// edge-stacks.mjs — list the JS call stacks the engine recorded on graph edges,
// joining each stack frame's V8 scriptId to the PageGraph script node it came
// from. Built for cookie-lifecycle work: by default it shows the cookie
// storage edges (set / delete / read), each with the stack that caused it.
//
//   node analysis/edge-stacks.mjs <graphml> [options]
//     --type STR   only edges whose "edge type" contains STR (repeatable via
//                  comma, e.g. --type "storage set,delete storage").
//     --key STR    only edges whose "key" equals STR (a cookie name).
//     --all        include every edge that carries a stack, not just cookie ones.
//     --frames N   show at most N (sync) frames per stack (default 8).
//     --json       emit structured JSON instead of text.
//
// The "stack trace" edge attribute is a DevTools Runtime.StackTrace object:
// { callFrames: [{ functionName, scriptId, url, lineNumber, columnNumber }],
//   parent?: <same shape, the async parent chain> }.

import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const graphmlPath = args.find((a) => !a.startsWith("--"));
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] !== undefined ? args[i + 1] : dflt;
};
const has = (name) => args.includes(name);

if (!graphmlPath) {
  process.stderr.write(
    "usage: node analysis/edge-stacks.mjs <graphml> [--type STR] [--key STR] [--all] [--frames N] [--json]\n",
  );
  process.exit(1);
}

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

const data = readFileSync(graphmlPath, "utf8");

// attr.name -> data-key id, scoped by `for` (some names are defined for both
// node and edge with different key ids).
const keysByFor = { edge: {}, node: {} };
for (const m of data.matchAll(
  /<key id="(d\d+)" for="(edge|node)" attr\.name="([^"]*)"/g,
)) {
  keysByFor[m[2]][m[3]] = m[1];
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
  const m = body.match(new RegExp(`key="${kid}">([\\s\\S]*?)</data>`));
  return m ? unescapeXml(m[1]) : null;
};
const eAttr = attrFor("edge");
const nAttr = attrFor("node");

// V8 scriptId -> { nodeId, url } via the script node's own "script id" attr
// (the engine writes the same V8 id there, which is what stack frames carry).
const scriptNodeByV8Id = new Map();
for (const m of data.matchAll(/<node id="(n\d+)">([\s\S]*?)<\/node>/g)) {
  const body = m[2];
  if (nAttr(body, "node type") !== "script") continue;
  const v8Id = nAttr(body, "script id");
  if (v8Id != null) {
    scriptNodeByV8Id.set(String(v8Id), {
      nodeId: m[1],
      url: nAttr(body, "url"),
    });
  }
}

const flattenFrames = (stack) => {
  // Walk the sync callFrames then recurse into async parents, tagging each
  // async boundary with its description (e.g. "setTimeout", "Promise.then").
  const out = [];
  let node = stack;
  let asyncLabel = null;
  while (node) {
    const frames = node.callFrames || [];
    out.push({ asyncLabel, frames });
    asyncLabel = node.parent ? node.parent.description || "async" : null;
    node = node.parent;
  }
  return out;
};

const describeFrame = (f) => {
  const fn = f.functionName || "(anonymous)";
  const where = f.url ? `${f.url}:${f.lineNumber}:${f.columnNumber}` : "(native)";
  const node = scriptNodeByV8Id.get(String(f.scriptId));
  const join = node ? ` [script node ${node.nodeId}]` : "";
  return `${fn} @ ${where}${join}`;
};

const results = [];
for (const m of data.matchAll(
  /<edge id="(e\d+)" source="(n\d+)" target="(n\d+)">([\s\S]*?)<\/edge>/g,
)) {
  const [, edgeId, source, target, body] = m;
  const edgeType = eAttr(body, "edge type");
  if (wantedTypes && !wantedTypes.some((t) => (edgeType || "").includes(t))) {
    continue;
  }
  if (keyFilter && eAttr(body, "key") !== keyFilter) {
    continue;
  }
  const stackRaw = eAttr(body, "stack trace");
  if (!stackRaw) {
    continue;
  }
  let stack;
  try {
    stack = JSON.parse(stackRaw);
  } catch {
    continue;
  }
  results.push({
    edgeId,
    source,
    target,
    edgeType,
    key: eAttr(body, "key"),
    value: eAttr(body, "value"),
    cookieSource: eAttr(body, "cookie source"),
    timestamp: eAttr(body, "timestamp"),
    stack,
  });
}

if (asJson) {
  process.stdout.write(JSON.stringify(results, null, 2) + "\n");
  process.exit(0);
}

if (results.length === 0) {
  process.stdout.write("No edges with a stack trace matched.\n");
  process.exit(0);
}

for (const r of results) {
  const head = [r.edgeType, r.key, r.value].filter(Boolean).join("  ");
  process.stdout.write(
    `\n== ${r.edgeId} (${r.source} -> ${r.target})  ${head}` +
      (r.cookieSource ? `  [source=${r.cookieSource}]` : "") +
      (r.timestamp ? `  @${r.timestamp}ms` : "") +
      "\n",
  );
  for (const group of flattenFrames(r.stack)) {
    if (group.asyncLabel) {
      process.stdout.write(`   --- async: ${group.asyncLabel} ---\n`);
    }
    for (const f of group.frames.slice(0, maxFrames)) {
      process.stdout.write(`   at ${describeFrame(f)}\n`);
    }
  }
}
