#!/usr/bin/env node
// Network-channel evidence for stack detection: response headers per host, plus the
// request-body schemas a vendor endpoint receives.
//
// Source text says what a script *is*; headers say what served it and what runs behind it
// (CDN, origin server, framework), which no amount of JS reading can reveal. Set-Cookie
// scope from the wire is also the only authoritative record of the domain a server asked
// for -- the cookie jar shows the scope that survived, not the one requested.
//
// Streams the graphml: these files reach multiple GB, so never readFileSync one.
//
// Usage: node analysis/stack-network.mjs <crawl-dir> [--out out.json]

import { createReadStream, readdirSync, writeFileSync } from "node:fs";
import { graphStream, isGraphPath } from "./lib/graph-source.mjs";
import { join } from "node:path";
import { createInterface } from "node:readline";

const dir = process.argv[2];
if (!dir) { console.error("usage: stack-network.mjs <crawl-dir> [--out out.json]"); process.exit(1); }
const outAt = process.argv.indexOf("--out");
const outFile = outAt > 0 ? process.argv[outAt + 1] : null;

const files = readdirSync(dir);
const graph = files.find(f => isGraphPath(f));
const bodies = files.find(f => f.endsWith(".bodies.ndjson"));
if (!graph) { console.error("no .graphml in " + dir); process.exit(1); }

const un = s => s == null ? null : s.replace(/&lt;/g, "<").replace(/&gt;/g, ">")
  .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, "&");

// ---- streaming element reader (bounded carry buffer) ----------------------
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
      else {
        const selfClose = buf.indexOf("/>", open.lastIndex), nextOpen = buf.indexOf("<", open.lastIndex);
        if (selfClose !== -1 && (nextOpen === -1 || selfClose < nextOpen)) { after = selfClose + 2; e = -2; }
        else break;
      }
      const raw = buf.slice(s, after), he = raw.indexOf(">");
      yield { tag, head: raw.slice(0, he), body: e === -2 ? "" : raw.slice(he + 1, raw.length - close.length) };
      consumed = after; open.lastIndex = after;
    }
    buf = buf.slice(consumed);
    if (buf.length > (1 << 20)) { open.lastIndex = 0; const nx = open.exec(buf); buf = nx ? buf.slice(nx.index) : buf.slice(-64); }
  }
}

const K = { edge: {}, node: {} };
const attr = kind => (body, name) => {
  const id = K[kind][name]; if (!id || body == null) return null;
  const m = body.match(new RegExp(`key="${id}">([\\s\\S]*?)</data>`));
  return m ? un(m[1]) : null;
};
const eA = attr("edge"), nA = attr("node");

// ---- pass: nodes then edges (PageGraph emits nodes first) -----------------
const urlOf = new Map();
for await (const el of stream(join(dir, graph), ["key", "node"])) {
  if (el.tag === "key") {
    const f = el.head.match(/for="(edge|node)"/), n = el.head.match(/attr\.name="([^"]*)"/), i = el.head.match(/id="(d\d+)"/);
    if (f && n && i) K[f[1]][n[1]] = i[1];
    continue;
  }
  const id = (el.head.match(/id="(n\d+)"/) || [])[1];
  const u = nA(el.body, "url");
  if (id && u) urlOf.set(id, u);
}

// Headers that identify infrastructure rather than describe the payload.
const INTERESTING = /^(server|x-powered-by|via|x-cache|x-amz-cf-id|x-amz-cf-pop|cf-ray|x-akamai[\w-]*|akamai[\w-]*|x-served-by|x-vercel[\w-]*|x-nextjs[\w-]*|x-drupal[\w-]*|x-generator|x-aspnet[\w-]*|x-shopify[\w-]*|x-magento[\w-]*|x-wp[\w-]*|x-varnish|x-fastly[\w-]*|x-envoy[\w-]*|x-goog[\w-]*)$/i;

const hostInfo = new Map(); // host -> {headers:Map(name->Set(value)), setCookieScopes:Set, types:Set}
const rec = (host) => {
  if (!hostInfo.has(host)) hostInfo.set(host, { headers: new Map(), setCookieScopes: new Set(), types: new Set() });
  return hostInfo.get(host);
};

let edgesWithHeaders = 0;
for await (const el of stream(join(dir, graph), ["edge"])) {
  const raw = eA(el.body, "headers");
  if (!raw) continue;
  const src = (el.head.match(/source="(n\d+)"/) || [])[1];
  const tgt = (el.head.match(/target="(n\d+)"/) || [])[1];
  const url = urlOf.get(src) || urlOf.get(tgt);
  if (!url) continue;
  let host; try { host = new URL(url).hostname; } catch { continue; }

  let list;
  try { list = JSON.parse(raw); } catch { continue; }
  edgesWithHeaders++;
  const entries = Array.isArray(list)
    ? list.map(h => [h.name ?? h[0], h.value ?? h[1]])
    : Object.entries(list);

  const info = rec(host);
  const rt = eA(el.body, "resource type"); if (rt) info.types.add(rt);
  for (const [n, v] of entries) {
    if (!n) continue;
    const name = String(n).toLowerCase();
    if (INTERESTING.test(name)) {
      if (!info.headers.has(name)) info.headers.set(name, new Set());
      const set = info.headers.get(name);
      if (set.size < 4) set.add(String(v).slice(0, 120));
    } else if (name === "set-cookie") {
      // the scope the SERVER asked for -- may differ from what the jar accepted
      const d = /;\s*domain=([^;]+)/i.exec(String(v));
      const nm = /^\s*([^=]+)=/.exec(String(v));
      if (info.setCookieScopes.size < 25) {
        info.setCookieScopes.add(`${(nm ? nm[1] : "?").trim()} -> ${d ? d[1].trim() : "(host-only)"}`);
      }
    }
  }
}

// ---- body schemas: what shape does each endpoint receive? -----------------
const endpoints = new Map(); // host+path -> {method, fields:Set, samples:n}
if (bodies) {
  const rl = createInterface({ input: createReadStream(join(dir, bodies), { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let r; try { r = JSON.parse(line); } catch { continue; }
    if (r.kind !== "request" || !r.body || r.dropped) continue;
    let host, path;
    try { const u = new URL(r.url); host = u.hostname; path = u.pathname; } catch { continue; }
    const k = `${host}${path}`;
    if (!endpoints.has(k)) endpoints.set(k, { method: r.method, fields: new Set(), samples: 0 });
    const ep = endpoints.get(k); ep.samples++;
    if (ep.fields.size > 40) continue;
    const b = String(r.body);
    // form-encoded or JSON -- take top-level field names only; they are the API's shape
    if (/^[\w.[\]%-]+=/.test(b)) for (const kv of b.split("&").slice(0, 40)) ep.fields.add(kv.split("=")[0]);
    else {
      try {
        const o = JSON.parse(b);
        if (o && typeof o === "object") for (const f of Object.keys(o).slice(0, 40)) ep.fields.add(f);
        else ep.encoding = "json scalar";
      } catch {
        // Not form-encoded and not JSON. Record HOW it is encoded rather than inventing
        // field names out of an opaque blob -- an encoded payload is itself a finding.
        if (/^eJ[\w+/]+=*$/.test(b.trim())) ep.encoding = "base64(zlib) — opaque";
        else if (/^[A-Za-z0-9+/]{40,}=*$/.test(b.trim())) ep.encoding = "base64 — opaque";
        else ep.encoding = "unstructured";
      }
    }
  }
}

const report = {
  crawlDir: dir,
  edgesWithHeaders,
  hosts: [...hostInfo.entries()].map(([host, i]) => ({
    host,
    resourceTypes: [...i.types],
    infraHeaders: Object.fromEntries([...i.headers].map(([k, v]) => [k, [...v]])),
    serverSetCookies: [...i.setCookieScopes],
  })).filter(h => Object.keys(h.infraHeaders).length || h.serverSetCookies.length)
    .sort((a, b) => a.host.localeCompare(b.host)),
  postEndpoints: [...endpoints.entries()].map(([k, v]) => ({
    endpoint: k, method: v.method, fields: [...v.fields], encoding: v.encoding || "structured",
  })).filter(e => e.fields.length || e.encoding !== "structured").sort((a, b) => a.endpoint.localeCompare(b.endpoint)),
};

if (outFile) writeFileSync(outFile, JSON.stringify(report, null, 2));
console.log(`${dir}\n  ${edgesWithHeaders} edges carried headers | ${report.hosts.length} hosts with infra headers | ${report.postEndpoints.length} endpoints with a readable body\n`);
for (const h of report.hosts.slice(0, 40)) {
  const bits = Object.entries(h.infraHeaders).map(([k, v]) => `${k}: ${v.join(" / ")}`);
  if (bits.length) console.log(`  ${h.host}\n      ${bits.join("\n      ")}`);
}
