#!/usr/bin/env node
// detect-cloaking.mjs — find scripts that REWRITE outbound requests.
//
//   node analysis/detect-cloaking.mjs <graphml> [--json] [--ctx N]
//
// Why this exists: every host-based or party-based signal in this repo can be
// defeated by a page that patches the request APIs and rewrites tracker URLs onto
// its own domain. themeisle.com does exactly that — a Stape server-side-GTM proxy
// wraps fetch / XHR.open / sendBeacon / HTMLImageElement.src / HTMLScriptElement.src /
// Element.setAttribute, and rewrites Google endpoints to
// `data.themeisle.com/<path>?<obfuscated>=<base64 of the real path>`. Under a
// destination-host analysis that site reads as "no third-party flow" — which is the
// exact conclusion the mechanism is built to produce.
//
// So the presence of request-API interception is itself evidence, and it is
// behavioural: it does not depend on the cookie's name, its party, or a vendor list.
// Scripts are searched for the patch idioms, then for the rewrite machinery
// (base64 assembly of a URL, an allow/deny path list) that distinguishes a genuine
// proxy from a benign wrapper such as a logger or a polyfill.

import { createReadStream, openSync, readSync, closeSync } from "node:fs";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const asJson = argv.includes("--json");
const CTX = parseInt(flag("--ctx", "260"), 10);
const graphmlPath = argv.find(a => !a.startsWith("--") && a.endsWith(".graphml"));
if (!graphmlPath) {
  process.stderr.write("usage: node analysis/detect-cloaking.mjs <graphml> [--json] [--ctx N]\n");
  process.exit(1);
}

const un = s => s == null ? null : s
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
  .replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, "&");

const readPageUrl = p => {
  const fd = openSync(p, "r");
  try {
    const b = Buffer.alloc(262144);
    const n = readSync(fd, b, 0, b.length, 0);
    const m = b.toString("utf8", 0, n).match(/<url>([^<]*)<\/url>/);
    return m ? m[1] : null;
  } finally { closeSync(fd); }
};

// The interception surface. Each entry is a request-initiating API that, if
// reassigned or redefined, lets a script rewrite where data goes.
const PATCHES = [
  { id: "fetch",            re: /(?:window|self|globalThis)\s*\.\s*fetch\s*=/ },
  { id: "XHR.open",         re: /XMLHttpRequest\s*\.\s*prototype\s*\.\s*open\s*=/ },
  { id: "XHR.send",         re: /XMLHttpRequest\s*\.\s*prototype\s*\.\s*send\s*=/ },
  { id: "sendBeacon",       re: /navigator\s*\.\s*sendBeacon\s*=/ },
  { id: "Image.src",        re: /HTMLImageElement\s*\.\s*prototype\s*,\s*["']src["']|defineProperty\s*\(\s*HTMLImageElement/ },
  { id: "Script.src",       re: /HTMLScriptElement\s*\.\s*prototype\s*,\s*["']src["']|defineProperty\s*\(\s*HTMLScriptElement/ },
  { id: "setAttribute",     re: /Element\s*\.\s*prototype\s*\.\s*setAttribute\s*=/ },
  { id: "WebSocket",        re: /(?:window|self|globalThis)\s*\.\s*WebSocket\s*=/ },
];
// Machinery that turns a wrapper into a rewriting proxy.
const REWRITE = [
  { id: "base64-url-assembly", re: /btoa\s*\(/ },
  { id: "encodeURIComponent-on-url", re: /encodeURIComponent\s*\(\s*btoa/ },
  { id: "path-allowlist", re: /\[\s*\/\^\\\/[^\]]{0,400}\]/ },
  { id: "indexOf-path-guard", re: /\.indexOf\s*\(\s*["']\// },
];

async function* stream(path) {
  const st = createReadStream(path, { encoding: "utf8" });
  let buf = "";
  const open = /<(node|key)\b/g;
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

const K = { node: {}, edge: {} };
const key = h => {
  const f = h.match(/for="(edge|node)"/), n = h.match(/attr\.name="([^"]*)"/), i = h.match(/id="(d\d+)"/);
  if (f && n && i) K[f[1]][n[1]] = i[1];
};
const nA = (body, name) => {
  const id = K.node[name];
  if (!id || body == null) return null;
  const m = body.match(new RegExp(`key="${id}">([\\s\\S]*?)</data>`));
  return m ? un(m[1]) : null;
};

const pageUrl = readPageUrl(graphmlPath);
const findings = [];
let scanned = 0, withSource = 0;

for await (const el of stream(graphmlPath)) {
  if (el.tag === "key") { key(el.head); continue; }
  if (el.tag !== "node") continue;
  if (nA(el.body, "node type") !== "script") continue;
  scanned++;
  const src = nA(el.body, "source");
  if (!src) continue;
  withSource++;
  const hits = PATCHES.filter(p => p.re.test(src));
  if (!hits.length) continue;
  const rw = REWRITE.filter(r => r.re.test(src));
  const id = (el.head.match(/id="(n\d+)"/) || [])[1];
  // excerpt at the first patch site
  const first = src.search(hits[0].re);
  findings.push({
    scriptNode: id,
    url: nA(el.body, "url"),
    scriptId: nA(el.body, "script id"),
    length: src.length,
    patched: hits.map(h => h.id),
    rewriteMachinery: rw.map(r => r.id),
    // a wrapper that patches >=3 request APIs AND assembles base64 URLs is a proxy,
    // not a polyfill or a logger
    verdict: hits.length >= 3 && rw.length >= 2 ? "REQUEST-REWRITING PROXY"
           : hits.length >= 3 ? "broad request interception"
           : "request wrapper",
    excerpt: first >= 0 ? src.slice(Math.max(0, first - 60), first + CTX) : null,
  });
}

const out = { pageUrl, graph: graphmlPath, scriptsScanned: scanned, scriptsWithSource: withSource, findings };

if (asJson) { process.stdout.write(JSON.stringify(out, null, 2) + "\n"); process.exit(0); }

console.log("═".repeat(78));
console.log(`REQUEST-API INTERCEPTION SCAN`);
console.log(`page    ${pageUrl}`);
console.log(`scripts ${withSource} of ${scanned} carry source`);
console.log("═".repeat(78));
if (!findings.length) { console.log("\nno request-API patching detected.\n"); process.exit(0); }
for (const f of findings) {
  console.log(`\n${"─".repeat(78)}`);
  console.log(`${f.verdict}`);
  console.log(`  script  : ${f.url || "(inline)"}  [node ${f.scriptNode}, ${f.length} chars]`);
  console.log(`  patches : ${f.patched.join(", ")}`);
  console.log(`  rewrite : ${f.rewriteMachinery.join(", ") || "none detected"}`);
  if (f.excerpt) {
    console.log(`\n  ${"·".repeat(60)}`);
    console.log("  " + f.excerpt.replace(/\n/g, "\n  "));
    console.log(`  ${"·".repeat(60)}`);
  }
}
console.log(`\n${"═".repeat(78)}`);
const proxies = findings.filter(f => f.verdict === "REQUEST-REWRITING PROXY").length;
console.log(`${findings.length} script(s) intercept request APIs; ${proxies} classified as rewriting proxies.`);
if (proxies) console.log(`Destination-host and party evidence on this page is UNRELIABLE — URLs are rewritten before they are observed.`);
