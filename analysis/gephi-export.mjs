#!/usr/bin/env node
// Extract a small, pre-styled storage subgraph (cookies + localStorage + sessionStorage)
// from a PageGraph .graphml and write it as a Gephi-ready GEXF (viz color/size/position).
//
//   node analysis/gephi-export.mjs <graphml> --out <file.gexf> [selectors]
//
// Selectors:
//   --channel cookie|local|session|storage|all   which storage hub(s)      (default all)
//   --key <name>       exact storage key to keep (repeatable)
//   --prefix <str>     keep keys starting with <str> (repeatable)
//   --vendor <name>    preset key bundles spanning channels (px, wunderkind)
//   (no key/prefix/vendor = every key in the chosen channel[s])
//
// Streaming parser (handles multi-GB single-line graphs); never buffers the whole file.

import { graphStream } from "./lib/graph-source.mjs";
import { writeFileSync } from "node:fs";

const args = process.argv.slice(2);
const graphmlPath = args.find((a) => !a.startsWith("--"));
const optAll = (name) => args.reduce((acc, a, i) => (a === name && args[i + 1] !== undefined ? [...acc, args[i + 1]] : acc), []);
const opt = (name, dflt) => { const v = optAll(name); return v.length ? v[v.length - 1] : dflt; };

const outPath = opt("--out", null);
if (!graphmlPath || !outPath) {
  process.stderr.write("usage: node analysis/gephi-export.mjs <graphml> --out <file.gexf> [--channel ..] [--key ..] [--prefix ..] [--vendor ..]\n");
  process.exit(2);
}
const channel = opt("--channel", "all");
const exactKeys = new Set(optAll("--key"));
const prefixes = [...optAll("--prefix")];
const vendor = opt("--vendor", null);

const VENDORS = {
  px: ["_px", "PXu6b0qd2S"],
  wunderkind: ["_bc_", "logBeacons"],
};
if (vendor) {
  if (!VENDORS[vendor]) { process.stderr.write(`unknown --vendor ${vendor}; known: ${Object.keys(VENDORS).join(", ")}\n`); process.exit(2); }
  prefixes.push(...VENDORS[vendor]);
}
const filterActive = exactKeys.size > 0 || prefixes.length > 0;
const keyMatches = (k) => !filterActive || exactKeys.has(k) || prefixes.some((p) => (k || "").startsWith(p));

// storage hub node types -> channel metadata
const HUBS = {
  "cookie jar": { channel: "cookie", label: "Cookie jar", color: [240, 181, 61] },
  "local storage": { channel: "local", label: "localStorage", color: [155, 89, 182] },
  "session storage": { channel: "session", label: "sessionStorage", color: [26, 188, 156] },
  storage: { channel: "storage", label: "storage", color: [127, 140, 141] },
};
const CHANNEL_HUBS = {
  cookie: ["cookie jar"], local: ["local storage"], session: ["session storage"],
  storage: ["storage"], all: Object.keys(HUBS),
};
const wantedHubTypes = new Set(CHANNEL_HUBS[channel] || CHANNEL_HUBS.all);

const NODE_COLOR = {
  script: [52, 152, 219], resource: [189, 195, 199],
  parser: [46, 204, 113], "DOM root": [46, 204, 113], "HTML element": [46, 204, 113],
  "web API": [230, 126, 34], network: [231, 76, 60],
};
const nodeColor = (nodeType) => HUBS[nodeType]?.color || NODE_COLOR[nodeType] || [77, 84, 92];

const STORAGE_OPS = { "storage set": "set", "read storage call": "read", "delete storage": "delete" };
const includeJarReads = !args.includes("--no-jar-reads");
const followNetwork = args.includes("--follow-network") || opt("--hops", "1") === "2";
const asJson = args.includes("--json") || (outPath || "").endsWith(".json");

const unescapeXml = (s) => s == null ? null : s
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
const escXml = (s) => (s == null ? "" : String(s)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"));

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
      if (end !== -1) { after = end + closeTag.length; }
      else {
        const selfClose = buf.indexOf("/>", openRe.lastIndex);
        const nextOpen = buf.indexOf("<", openRe.lastIndex);
        if (selfClose !== -1 && (nextOpen === -1 || selfClose < nextOpen)) { after = selfClose + 2; end = -2; }
        else break;
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

// ---- single streaming pass -------------------------------------------------
const nodes = new Map();          // id -> {nodeType,url,host,tagName,scriptType}
const rawEdges = [];              // storage edges (post edge-type gate)
const scriptToElement = new Map(); // script node <- execute <- HTML <script> element
const elementToResource = new Map(); // element -> resource (carries the source URL)
const requestsBySource = new Map(); // node id -> Set(resource id) it fetched (2nd hop)
for await (const el of streamElements(graphmlPath)) {
  if (el.tag === "key") { attrId(el.head); continue; }
  if (el.tag === "node") {
    const id = idOf(el.head);
    if (id) nodes.set(id, {
      nodeType: nAttr(el.body, "node type"), url: nAttr(el.body, "url"),
      host: nAttr(el.body, "host"), tagName: nAttr(el.body, "tag name"),
      scriptType: nAttr(el.body, "script type"),
    });
    continue;
  }
  // edge — keep storage ops plus the execute/request edges needed to resolve script URLs
  const edgeType = eAttr(el.body, "edge type");
  const isStorage = edgeType in STORAGE_OPS;
  const isExecute = edgeType === "execute";
  const isRequest = edgeType === "request start" || edgeType === "request complete";
  if (!isStorage && !isExecute && !isRequest) continue;
  const source = (el.head.match(/source="(n\d+)"/) || [])[1];
  const target = (el.head.match(/target="(n\d+)"/) || [])[1];
  if (isExecute) { if (target) scriptToElement.set(target, source); continue; }
  if (isRequest) {
    if (source && !elementToResource.has(source)) elementToResource.set(source, target);
    if (source && target) (requestsBySource.get(source) ?? requestsBySource.set(source, new Set()).get(source)).add(target);
    continue;
  }
  rawEdges.push({ op: STORAGE_OPS[edgeType], source, target, key: eAttr(el.body, "key"), value: eAttr(el.body, "value") });
}

// resolve a node's source URL: a script node carries none, so walk
// script <-execute- element -request-> resource(url).
const resolveUrl = (id) => {
  const n = nodes.get(id);
  if (n?.url) return n.url;
  const elId = scriptToElement.get(id);
  if (elId != null) {
    const resId = elementToResource.get(elId);
    if (resId != null && nodes.get(resId)?.url) return nodes.get(resId).url;
    if (nodes.get(elId)?.url) return nodes.get(elId).url;
  }
  return null;
};

// ---- resolve hub/actor for each storage edge -------------------------------
// A cookie READ is a whole-jar read (document.cookie returns every cookie), so its
// `key` is the reading page URL, not a cookie name — model it as a generic edge to the
// cookie jar. Writes, and all localStorage/sessionStorage ops, are precisely keyed.
const JAR_KEY = "(whole jar)";
const resolved = [];
for (const e of rawEdges) {
  const sHub = HUBS[nodes.get(e.source)?.nodeType], tHub = HUBS[nodes.get(e.target)?.nodeType];
  let hubId, actorId, hubMeta;
  if (tHub) { hubId = e.target; actorId = e.source; hubMeta = tHub; }
  else if (sHub) { hubId = e.source; actorId = e.target; hubMeta = sHub; }
  else continue;
  const hubType = nodes.get(hubId).nodeType;
  if (!wantedHubTypes.has(hubType)) continue;
  const isJarRead = hubMeta.channel === "cookie" && e.op === "read";
  resolved.push({ actorId, hubId, channel: hubMeta.channel, op: e.op, isJarRead, key: isJarRead ? JAR_KEY : e.key, value: e.value });
}

// value lookup from write edges, to annotate keyed reads
const valueByCK = new Map();
for (const r of resolved) if (r.op === "set" && r.value != null) valueByCK.set(`${r.channel}|${r.key}`, r.value);

// ---- filter + aggregate ----------------------------------------------------
let referenced = new Set();
let agg = new Map(); // `${actor}|${hub}|${op}|${key}` -> {actor,hub,op,key,channel,weight,value}
const addEdge = (r) => {
  const ak = `${r.actorId}|${r.hubId}|${r.op}|${r.key}`;
  const cur = agg.get(ak) || { actor: r.actorId, hub: r.hubId, op: r.op, key: r.key, channel: r.channel, weight: 0, value: null };
  cur.weight += 1;
  if (cur.value == null) cur.value = r.value ?? valueByCK.get(`${r.channel}|${r.key}`) ?? null;
  agg.set(ak, cur);
  referenced.add(r.actorId); referenced.add(r.hubId);
};
// phase 1: keyed ops (writes any channel; localStorage/sessionStorage reads)
const matchedActors = new Set();
for (const r of resolved) {
  if (r.isJarRead || !keyMatches(r.key)) continue;
  addEdge(r); matchedActors.add(r.actorId);
}
// phase 2: whole-jar cookie reads. They bypass the key filter (a jar read sees every
// cookie, incl. the filtered ones); when a filter is active, restrict to actors that
// already touched a matching key so a vendor graph stays about that vendor's scripts.
if (includeJarReads) for (const r of resolved) {
  if (!r.isJarRead) continue;
  if (filterActive && !matchedActors.has(r.actorId)) continue;
  addEdge(r);
}

if (agg.size === 0) {
  process.stderr.write(`No storage edges matched (channel=${channel}${filterActive ? `, keys=${[...exactKeys, ...prefixes.map((p) => p + "*")].join(",")}` : ""}).\n`);
  process.exit(1);
}

// original node ids that read a selected key (before merge) — the 2nd-hop starting points
const readerOrigIds = new Set([...agg.values()].filter((e) => e.op === "read").map((e) => e.actor));

// collapse the multiple script-node instances of the same source URL into one node
let repOf = (id) => id;
if (!args.includes("--no-merge")) {
  const keyOf = (id) => (HUBS[nodes.get(id)?.nodeType] ? id : resolveUrl(id) || `__${id}`);
  const repById = new Map(); // urlKey -> representative node id
  for (const id of referenced) { const k = keyOf(id); if (!repById.has(k)) repById.set(k, id); }
  repOf = (id) => repById.get(keyOf(id)) ?? id;
  const merged = new Map();
  for (const e of agg.values()) {
    const a = repOf(e.actor), h = repOf(e.hub);
    const ak = `${a}|${h}|${e.op}|${e.key}`;
    const cur = merged.get(ak) || { ...e, actor: a, hub: h, weight: 0 };
    cur.weight += e.weight;
    if (cur.value == null) cur.value = e.value;
    merged.set(ak, cur);
  }
  agg = merged;
  referenced = new Set();
  for (const e of agg.values()) { referenced.add(e.actor); referenced.add(e.hub); }
}

// ---- 2nd hop: reader script -> the network hosts it fetches ----------------
const netEdges = []; // {actor, node, host, weight}
if (followNetwork) {
  const hostOf = (u) => { try { return new URL(u).hostname; } catch { return null; } };
  const netAgg = new Map(); // `${actorRep}|${host}` -> {actor, host, weight}
  for (const origId of readerOrigIds) {
    const actor = repOf(origId);
    const dests = requestsBySource.get(origId);
    if (!dests) continue;
    for (const resId of dests) {
      const host = hostOf(nodes.get(resId)?.url);
      if (!host) continue;
      const nk = `${actor}|${host}`;
      const cur = netAgg.get(nk) || { actor, host, weight: 0 };
      cur.weight += 1;
      netAgg.set(nk, cur);
    }
  }
  for (const e of netAgg.values()) {
    const nodeId = `net:${e.host}`;
    if (!nodes.has(nodeId)) nodes.set(nodeId, { nodeType: "network", url: `https://${e.host}/`, host: e.host });
    netEdges.push({ actor: e.actor, node: nodeId, host: e.host, weight: e.weight });
    referenced.add(e.actor); referenced.add(nodeId);
  }
}

// ---- labels / layout -------------------------------------------------------
const shortLabel = (id) => {
  const n = nodes.get(id); if (!n) return id;
  if (HUBS[n.nodeType]) return HUBS[n.nodeType].label;
  const url = resolveUrl(id);
  if (url) {
    try { const u = new URL(url); const last = u.pathname.split("/").filter(Boolean).pop(); return last ? `${u.hostname}/${last}` : u.hostname; }
    catch { return url.slice(0, 48); }
  }
  return n.tagName || n.nodeType || id;
};
// edges as emitted: reads flow hub->reader->network so arrows trace the data path;
// writes/deletes flow script->hub (into storage).
const emit = [];
for (const e of agg.values()) {
  const [src, tgt] = e.op === "read" ? [e.hub, e.actor] : [e.actor, e.hub];
  emit.push({ src, tgt, weight: e.weight, op: e.op, channel: e.channel, key: e.key, value: e.value,
    label: `${e.op} ${e.key}${e.weight > 1 ? ` ×${e.weight}` : ""}` });
}
for (const e of netEdges) {
  emit.push({ src: e.actor, tgt: e.node, weight: e.weight, op: "request", channel: "network", key: e.host, value: "",
    label: `fetch ${e.host}${e.weight > 1 ? ` ×${e.weight}` : ""}` });
}

// JSON output (for the Streamlit viewer): full reduced graph, app filters client-side
if (asJson) {
  const kindOf = (id) => (HUBS[nodes.get(id)?.nodeType] ? "hub" : nodes.get(id)?.nodeType === "network" ? "network" : "script");
  const jnodes = [...referenced].map((id) => {
    const n = nodes.get(id) || {};
    return { id, label: shortLabel(id), url: resolveUrl(id) || null, nodeType: n.nodeType || null,
      channel: HUBS[n.nodeType]?.channel || (n.nodeType === "network" ? "network" : null), kind: kindOf(id) };
  });
  const jedges = [
    ...[...agg.values()].map((e) => ({ kind: "storage", actor: e.actor, target: e.hub, op: e.op, channel: e.channel, key: e.key, value: (e.value || "").slice(0, 240), weight: e.weight })),
    ...netEdges.map((e) => ({ kind: "network", actor: e.actor, target: e.node, op: "fetch", channel: "network", key: e.host, value: "", weight: e.weight })),
  ];
  writeFileSync(outPath, JSON.stringify({ source: graphmlPath.split("/").pop(), nodes: jnodes, edges: jedges }));
  process.stderr.write(`Wrote ${outPath} (json)  nodes: ${jnodes.length}  edges: ${jedges.length}\n`);
  process.exit(0);
}

const degree = new Map();
for (const e of emit) { degree.set(e.src, (degree.get(e.src) || 0) + 1); degree.set(e.tgt, (degree.get(e.tgt) || 0) + 1); }

const typeOf = (id) => nodes.get(id)?.nodeType;
const hubIds = [...referenced].filter((id) => HUBS[typeOf(id)]);
const netIds = [...referenced].filter((id) => typeOf(id) === "network");
const actorIds = [...referenced].filter((id) => !HUBS[typeOf(id)] && typeOf(id) !== "network");
const pos = new Map();
const ring = (ids, radius) => ids.forEach((id, i) => { const a = (2 * Math.PI * i) / Math.max(1, ids.length); pos.set(id, [Math.cos(a) * radius, Math.sin(a) * radius]); });
ring(hubIds, 90); ring(actorIds, 420); ring(netIds, 720);

// ---- emit GEXF -------------------------------------------------------------
const nodeXml = [...referenced].map((id) => {
  const n = nodes.get(id) || {};
  const isHub = !!HUBS[n.nodeType];
  const [r, g, b] = nodeColor(n.nodeType);
  const size = isHub ? 40 : Math.min(32, 8 + 2.5 * (degree.get(id) || 1));
  const [x, y] = pos.get(id) || [0, 0];
  const chan = isHub ? HUBS[n.nodeType].channel : n.nodeType === "network" ? "network" : "";
  return `      <node id="${escXml(id)}" label="${escXml(shortLabel(id))}">
        <attvalues>
          <attvalue for="0" value="${escXml(n.nodeType)}"/>
          <attvalue for="1" value="${escXml(chan)}"/>
          <attvalue for="2" value="${escXml(resolveUrl(id))}"/>
        </attvalues>
        <viz:color r="${r}" g="${g}" b="${b}"/>
        <viz:size value="${size.toFixed(1)}"/>
        <viz:position x="${x.toFixed(1)}" y="${y.toFixed(1)}" z="0.0"/>
      </node>`;
}).join("\n");

let eid = 0;
const edgeXml = emit.map((e) => `      <edge id="${eid++}" source="${escXml(e.src)}" target="${escXml(e.tgt)}" weight="${e.weight}" label="${escXml(e.label)}">
        <attvalues>
          <attvalue for="0" value="${escXml(e.op)}"/>
          <attvalue for="1" value="${escXml(e.channel)}"/>
          <attvalue for="2" value="${escXml(e.key)}"/>
          <attvalue for="3" value="${escXml((e.value || "").slice(0, 120))}"/>
        </attvalues>
      </edge>`).join("\n");

const gexf = `<?xml version="1.0" encoding="UTF-8"?>
<gexf xmlns="http://gexf.net/1.3" xmlns:viz="http://gexf.net/1.3/viz" version="1.3">
  <meta lastmodifieddate="${new Date().toISOString().slice(0, 10)}">
    <creator>pagegraph-crawl gephi-export</creator>
    <description>storage subgraph (channel=${escXml(channel)}${filterActive ? `, keys=${escXml([...exactKeys, ...prefixes.map((p) => p + "*")].join(","))}` : ""}) from ${escXml(graphmlPath.split("/").pop())}</description>
  </meta>
  <graph mode="static" defaultedgetype="directed">
    <attributes class="node">
      <attribute id="0" title="node type" type="string"/>
      <attribute id="1" title="channel" type="string"/>
      <attribute id="2" title="url" type="string"/>
    </attributes>
    <attributes class="edge">
      <attribute id="0" title="op" type="string"/>
      <attribute id="1" title="channel" type="string"/>
      <attribute id="2" title="key" type="string"/>
      <attribute id="3" title="value" type="string"/>
    </attributes>
    <nodes>
${nodeXml}
    </nodes>
    <edges>
${edgeXml}
    </edges>
  </graph>
</gexf>
`;
writeFileSync(outPath, gexf);

// ---- summary to stderr -----------------------------------------------------
const chans = new Set([...agg.values()].map((e) => e.channel));
const keys = new Set([...agg.values()].map((e) => e.key));
process.stderr.write(`Wrote ${outPath}\n  nodes: ${referenced.size} (${hubIds.length} hub, ${actorIds.length} actor${netIds.length ? `, ${netIds.length} network` : ""})  edges: ${emit.length}${netEdges.length ? ` (${netEdges.length} network)` : ""}\n  channels: ${[...chans].join(", ")}\n  keys (${keys.size}): ${[...keys].sort().join(", ")}\n`);
if (followNetwork && netIds.length) process.stderr.write(`  fetch destinations: ${netIds.map((id) => nodes.get(id).host).sort().join(", ")}\n`);
