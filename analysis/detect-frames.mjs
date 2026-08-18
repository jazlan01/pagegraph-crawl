#!/usr/bin/env node
// detect-frames.mjs — did a tracking request come from the main document or an embedded iframe?
//
// A request issued inside a cross-origin iframe is a different arrangement from one issued by the
// top document: the iframe is its own browsing context with its own storage partition, and the
// pattern where an ad vendor's iframe fans out to a dozen exchanges (cookie syncing) looks
// nothing like the first-party page calling one analytics endpoint. The report should be able to
// say which it was.
//
// Two independent views, because neither alone is complete:
//   VOLUME — PageGraph tags every edge with the `frame id` it occurred in, so requests can be
//   split between the main document and embedded frames. DOM-root nodes do not carry that id in
//   this build, so the main frame is identified behaviourally: it is the one that fetches the
//   page's own document. Where that is not observed it is inferred from request volume and
//   flagged as such.
//   IDENTITY — DOM-root nodes carry each document's URL, which names the embedded frames
//   directly. This build records no IFRAME elements at all, so the document URL is the evidence,
//   and it is better evidence than the element would be: an ad-tech sync frame usually states its
//   purpose in its own URL (`cookie_sync=1`, Floodlight `activityi`, `/container/…iframe/`).
//
// Usage: node analysis/detect-frames.mjs <graphml> [--out <file>]

import { writeFileSync } from "node:fs";
import { graphStream, isGraphPath, readPageUrl } from "./lib/graph-source.mjs";
import { roleOf } from "./lib/host-role.mjs";

const graphmlPath = process.argv.find(a => !a.startsWith("--") && isGraphPath(a));
const flag = (n, d) => { const i = process.argv.indexOf(n); return i !== -1 ? process.argv[i + 1] : d; };
const outPath = flag("--out", null);
if (!graphmlPath) { process.stderr.write("usage: detect-frames.mjs <graphml> [--out <file>]\n"); process.exit(1); }

const un = s => s == null ? null : s.replace(/&lt;/g, "<").replace(/&gt;/g, ">")
  .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, "&");

async function* stream(path, want) {
  const st = graphStream(path);
  let buf = "";
  const open = new RegExp(`<(${want.join("|")})\\b`, "g");
  for await (const ch of st) {
    buf += ch; let consumed = 0; open.lastIndex = 0; let m;
    while ((m = open.exec(buf)) !== null) {
      const tag = m[1], s = m.index, close = `</${tag}>`;
      let e = buf.indexOf(close, open.lastIndex), after;
      if (e !== -1) after = e + close.length;
      else { const sc = buf.indexOf("/>", open.lastIndex), no = buf.indexOf("<", open.lastIndex);
        if (sc !== -1 && (no === -1 || sc < no)) { after = sc + 2; e = -2; } else break; }
      const raw = buf.slice(s, after), he = raw.indexOf(">");
      yield { tag, head: raw.slice(0, he), body: e === -2 ? "" : raw.slice(he + 1, raw.length - close.length) };
      consumed = after; open.lastIndex = after;
    }
    buf = buf.slice(consumed);
    if (buf.length > (1 << 20)) { open.lastIndex = 0; const nx = open.exec(buf); buf = nx ? buf.slice(nx.index) : buf.slice(-64); }
  }
}

const K = { edge: {}, node: {} };
const key = h => { const f = h.match(/for="(edge|node)"/), n = h.match(/attr\.name="([^"]*)"/), i = h.match(/id="(d\d+)"/); if (f && n && i) K[f[1]][n[1]] = i[1]; };
const A = kind => (b, n) => { const id = K[kind][n]; if (!id || b == null) return null;
  const m = b.match(new RegExp(`key="${id}">([\\s\\S]*?)</data>`)); return m ? un(m[1]) : null; };
const eA = A("edge"), nA = A("node");
const idOf = h => (h.match(/id="(n\d+)"/) || [])[1];
const ends = h => [(h.match(/source="(n\d+)"/) || [])[1], (h.match(/target="(n\d+)"/) || [])[1]];

const pageUrl = await readPageUrl(graphmlPath);
const MULTI = new Set(["co.uk","com.au","co.jp","co.nz","com.br","co.in","org.uk","gov.uk"]);
const registrable = h => { if (!h) return null; const p = String(h).toLowerCase().split(".");
  if (p.length <= 2) return p.join("."); const l2 = p.slice(-2).join("."); return MULTI.has(l2) ? p.slice(-3).join(".") : l2; };
const hostOf = u => { try { return new URL(String(u)).hostname; } catch { return null; } };
const pageHost = hostOf(pageUrl), pageReg = registrable(pageHost);

const resUrl = new Map();
// DOM-root nodes are the documents that existed — i.e. the frames. Their URLs name each embedded
// document directly, which is far better evidence than the iframe element (this build records no
// IFRAME elements at all). A frame's identity therefore comes from its own document URL.
const documents = [];
for await (const el of stream(graphmlPath, ["key", "node"])) {
  if (el.tag === "key") { key(el.head); continue; }
  const t = nA(el.body, "node type");
  if (t === "resource") { const id = idOf(el.head); resUrl.set(id, nA(el.body, "url")); }
  else if (t === "DOM root") {
    const u = nA(el.body, "url"), o = nA(el.body, "security origin");
    if (u && u !== "about:blank") documents.push({ url: u, origin: o || null });
  }
}

// per-frame: which hosts it requested, how many requests, and whether it wrote storage
const frames = new Map();
const F = f => { const k = String(f ?? "?"); if (!frames.has(k)) frames.set(k, { requests: 0, hosts: new Map(), storageWrites: 0, fetchedPageDoc: false }); return frames.get(k); };
for await (const el of stream(graphmlPath, ["edge"])) {
  const et = eA(el.body, "edge type");
  if (et !== "request start" && et !== "storage set") continue;
  const f = eA(el.body, "frame id");
  const rec = F(f);
  if (et === "storage set") { rec.storageWrites++; continue; }
  const [, t] = ends(el.head);
  const u = resUrl.get(t); if (!u) continue;
  const h = hostOf(u); if (!h) continue;
  rec.requests++;
  rec.hosts.set(h, (rec.hosts.get(h) || 0) + 1);
  if (h === pageHost) rec.fetchedPageDoc = true;
}

// The main frame fetches the page's own host and is by far the busiest; embedded frames are the
// rest. Where no frame fetches the page host, the busiest is reported as main but flagged.
let mainId = null, bestScore = -1, mainCertain = false;
for (const [id, r] of frames) {
  const score = (r.fetchedPageDoc ? 1e6 : 0) + r.requests;
  if (score > bestScore) { bestScore = score; mainId = id; mainCertain = r.fetchedPageDoc; }
}

const summarise = (id, r) => {
  const hosts = [...r.hosts.entries()].sort((a, b) => b[1] - a[1]);
  const third = hosts.filter(([h]) => registrable(h) !== pageReg);
  const adOnly = third.filter(([h]) => { const role = roleOf(h); return role && role.roles.includes("advertising") && !role.roles.includes("analytics"); });
  return {
    frameId: id, main: id === mainId,
    requests: r.requests, storageWrites: r.storageWrites,
    distinctHosts: hosts.length,
    topHosts: hosts.slice(0, 6).map(([h, n]) => ({ host: h, n })),
    thirdPartyHosts: third.length,
    adOnlyHosts: [...new Set(adOnly.map(([h]) => registrable(h)))],
  };
};

// Embedded documents: every frame document that is not the page itself. Classified by Tracker
// Radar and by self-describing URL markers (a cookie-sync endpoint usually says so).
const seenDoc = new Set();
const embeddedDocs = [];
for (const d of documents) {
  const h = hostOf(d.url); if (!h) continue;
  if (registrable(h) === pageReg && (d.url === pageUrl || h === pageHost)) continue;
  const kkey = d.url.slice(0, 120);
  if (seenDoc.has(kkey)) continue; seenDoc.add(kkey);
  const role = roleOf(h);
  const marks = [];
  if (/[?&;]cookie_sync=1|\/track\/cei\b/i.test(d.url)) marks.push("cookie sync (stated in URL)");
  if (/\bactivityi[;?]|\bsrc=\d+;type=|\bfls\.doubleclick\.net\b/i.test(d.url)) marks.push("conversion / Floodlight activity");
  if (/\/container\/[^?]*iframe/i.test(d.url)) marks.push("ad container");
  if (/sw_iframe|service_worker/i.test(d.url)) marks.push("service-worker bridge");
  if (/client_storage/i.test(d.url)) marks.push("client storage bridge");
  embeddedDocs.push({
    url: d.url.slice(0, 200), host: h, registrable: registrable(h),
    thirdParty: registrable(h) !== pageReg,
    vendor: role ? { owner: role.owner, categories: role.categories, roles: role.roles } : null,
    markers: marks,
  });
}

const all = [...frames.entries()].filter(([, r]) => r.requests > 0 || r.storageWrites > 0).map(([id, r]) => summarise(id, r));
const embedded = all.filter(f => !f.main);
const adFrames = embedded.filter(f => f.adOnlyHosts.length);
const report = {
  pageUrl, mainFrameId: mainId, mainFrameIdentified: mainCertain,
  frameCount: all.length,
  embeddedFrameCount: embedded.length,
  embeddedFramesContactingAdEndpoints: adFrames.length,
  requestsFromMainFrame: all.filter(f => f.main).reduce((a, f) => a + f.requests, 0),
  requestsFromEmbeddedFrames: embedded.reduce((a, f) => a + f.requests, 0),
  frames: all.sort((a, b) => b.requests - a.requests),
  embeddedDocuments: embeddedDocs,
  embeddedThirdPartyDocuments: embeddedDocs.filter(d => d.thirdParty).length,
};
if (outPath) writeFileSync(outPath, JSON.stringify(report, null, 2));

console.log(`${pageUrl}`);
console.log(`  ${report.frameCount} frames issuing activity — main=${mainId}${mainCertain ? "" : " (inferred, page document not seen)"}, ${report.embeddedFrameCount} embedded`);
console.log(`  requests: ${report.requestsFromMainFrame} from main frame, ${report.requestsFromEmbeddedFrames} from embedded frames`);
if (embeddedDocs.length) {
  console.log(`  ${embeddedDocs.length} embedded document(s), ${report.embeddedThirdPartyDocuments} third-party:`);
  for (const d of embeddedDocs.slice(0, 10))
    console.log(`     ${d.host}${d.markers.length ? "  [" + d.markers.join("; ") + "]" : ""}`);
}
if (adFrames.length) {
  console.log(`  ${adFrames.length} embedded frame(s) contacting advertising-only endpoints:`);
  for (const f of adFrames.slice(0, 8)) console.log(`     frame ${f.frameId}: ${f.adOnlyHosts.join(", ")}`);
}
