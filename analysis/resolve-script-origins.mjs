#!/usr/bin/env node
// resolve-script-origins.mjs — work out WHICH VENDOR each script belongs to.
//
//   node analysis/resolve-script-origins.mjs <graphml> --out <flowdir>
//
// Knowing that a cookie was read tells you very little. Knowing *whose script* read it
// is the point: a third-party tag loaded into the page reads `document.cookie` and sees
// every JS-accessible first-party cookie, including ones set by other vendors. So a read
// of a Google cookie by a Meta script is a cross-vendor disclosure that happens entirely
// inside the first-party context, with no cross-domain request involved and nothing for
// a network-level audit to see.
//
// PageGraph does not put a URL on the script node for remote scripts. It has to be
// resolved: script <- execute <- element -> request -> resource(url). This is a light
// pass (only execute / request edges) so it can run after the main extraction rather
// than forcing it to be redone.

import { writeFileSync, existsSync } from "node:fs";
import { graphStream, isGraphPath, readPageUrl } from "./lib/graph-source.mjs";
import { join } from "node:path";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const graphmlPath = argv.find(a => !a.startsWith("--") && isGraphPath(a));
const OUT = flag("--out", null);
if (!graphmlPath || !OUT || !existsSync(OUT)) {
  process.stderr.write("usage: node analysis/resolve-script-origins.mjs <graphml> --out <flowdir>\n");
  process.exit(1);
}

const un = s => s == null ? null : s
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
  .replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, "&");

async function* stream(path, want) {
  const st = graphStream(path);
  let buf = "";
  const open = new RegExp(`<(${want.join("|")})\\b`, "g");
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
    // Bound the carry buffer. Elements we are not interested in never match, so
    // `consumed` can stay at 0 while megabytes of them stream past — the buffer then
    // grows until it exceeds V8's maximum string length and the process dies. Keep only
    // from the earliest unconsumed opening tag (an element may legitimately span chunks
    // and be large); if there is no opening tag at all, keep just enough to catch a tag
    // split across the boundary.
    buf = buf.slice(consumed);
    if (buf.length > 1 << 20) {
      open.lastIndex = 0;
      const nxt = open.exec(buf);
      buf = nxt ? buf.slice(nxt.index) : buf.slice(-64);
    }
  }
}

const K = { edge: {}, node: {} };
const key = h => { const f = h.match(/for="(edge|node)"/), n = h.match(/attr\.name="([^"]*)"/), i = h.match(/id="(d\d+)"/); if (f && n && i) K[f[1]][n[1]] = i[1]; };
const A = kind => (b, n) => { const id = K[kind][n]; if (!id || b == null) return null;
  const m = b.match(new RegExp(`key="${id}">([\\s\\S]*?)</data>`)); return m ? un(m[1]) : null; };
const eA = A("edge"), nA = A("node");
const idOf = h => (h.match(/id="(n\d+)"/) || [])[1];
const ends = h => [(h.match(/source="(n\d+)"/) || [])[1], (h.match(/target="(n\d+)"/) || [])[1]];

// the page URL lives in <desc><url> in the header, not on the DOM root node
let pageUrl = await readPageUrl(graphmlPath);
const scriptNodes = new Set(), resUrl = new Map(), directUrl = new Map();
// Nodes that can appear in a script-loading chain: script nodes, <script> elements, and the
// parser. Only these are retained, so the maps stay small on multi-GB graphs where `create node`
// is by far the highest-volume edge type.
const scriptElems = new Set(), parserNodes = new Set();
for await (const el of stream(graphmlPath, ["key", "node"])) {
  if (el.tag === "key") { key(el.head); continue; }
  const id = idOf(el.head), t = nA(el.body, "node type");
  if (t === "script") { scriptNodes.add(id); const u = nA(el.body, "url"); if (u) directUrl.set(id, u); }
  else if (t === "resource") resUrl.set(id, nA(el.body, "url"));
  else if (t === "parser") parserNodes.add(id);
  else if (t === "HTML element") { const tag = nA(el.body, "tag name"); if (tag && /^script$/i.test(tag)) scriptElems.add(id); }
}

const execOf = new Map();     // script node -> element node that executed it
const elemReq = new Map();    // element node -> url it requested
const createdBy = new Map();  // <script> element (or script) -> node that created it
for await (const el of stream(graphmlPath, ["edge"])) {
  const et = eA(el.body, "edge type");
  if (et !== "execute" && et !== "request start" && et !== "request complete"
      && et !== "execute from attribute" && et !== "create node") continue;
  const [s, t] = ends(el.head);
  if (et === "create node") {
    // Only chain-relevant targets are kept; every other created node is discarded immediately.
    if (t && (scriptElems.has(t) || scriptNodes.has(t)) && !createdBy.has(t)) createdBy.set(t, s);
    continue;
  }
  if (et === "execute" || et === "execute from attribute") { if (t) execOf.set(t, s); continue; }
  const u = t && resUrl.get(t);
  if (s && u && !elemReq.has(s)) elemReq.set(s, u);
}

const hostOf = u => { try { return new URL(String(u)).hostname; } catch { return null; } };
const regOf = h => { if (!h) return null; if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return h;
  const p = h.split("."); return p.length <= 2 ? h : p.slice(-2).join("."); };
const pageReg = regOf(hostOf(pageUrl));

const out = {};
for (const sn of scriptNodes) {
  let url = directUrl.get(sn) || null;
  if (!url) { const e = execOf.get(sn); if (e) url = elemReq.get(e) || null; }
  const host = hostOf(url);
  const reg = regOf(host);
  out[sn] = {
    url: url || null,
    host: host || null,
    registrableDomain: reg || null,
    // "inline" means genuinely written into the page, not merely unresolved
    inline: !url,
    party: reg == null ? "inline/first-party document" : (reg === pageReg ? "first-party" : "third-party"),
  };
}
// The LOADING CHAIN: who caused this script to be on the page. A JS call stack shows the frames
// inside one (usually minified) bundle; it does not show that the bundle was injected by a tag
// manager which was itself injected by the consent banner. That path is in the graph as
// script <- execute <- <script> element <- create node <- script, walked here to the parser.
const chainOf = (sn) => {
  const chain = []; const seen = new Set();
  let cur = sn, guard = 0;
  while (cur && guard++ < 12 && !seen.has(cur)) {
    seen.add(cur);
    const e = execOf.get(cur);
    if (!e) break;
    const url = elemReq.get(e) || directUrl.get(cur) || null;
    chain.push({ script: cur, url, host: hostOf(url), inline: !url });
    const c = createdBy.get(e) ?? createdBy.get(cur);
    if (!c) break;
    if (parserNodes.has(c)) { chain.push({ parser: true, url: pageUrl, host: hostOf(pageUrl) }); break; }
    if (!scriptNodes.has(c)) break;
    cur = c;
  }
  return chain;
};
const chains = {};
for (const sn of scriptNodes) {
  const c = chainOf(sn);
  if (c.length) chains[sn] = c;
}
const viaParser = Object.values(chains).filter(c => c.some(x => x.parser)).length;
process.stderr.write(`built ${Object.keys(chains).length} loading chains (${viaParser} reach the page HTML)\n`);
writeFileSync(join(OUT, "_script-origins.json"), JSON.stringify({ pageUrl, pageRegistrableDomain: pageReg, scripts: out, chains }, null, 1));
const third = Object.values(out).filter(s => s.party === "third-party");
const vendors = [...new Set(third.map(s => s.registrableDomain))].sort();
process.stderr.write(`resolved ${Object.keys(out).length} scripts; ${third.length} third-party from: ${vendors.join(", ") || "none"}\n`);
console.log(JSON.stringify({ pageUrl, scripts: Object.keys(out).length, thirdPartyVendors: vendors }, null, 1));
