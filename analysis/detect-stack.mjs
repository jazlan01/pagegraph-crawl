#!/usr/bin/env node
// Identify the technology stack of a crawled page from PageGraph evidence.
//
// Unlike static fingerprinters (Wappalyzer et al.), which read the delivered HTML and
// response headers, this works from what actually *executed*: every script the renderer
// compiled, its resolved origin, and its full source text. Two consequences that matter
// for compliance work:
//   * code injected at runtime (tag-manager children, vendor bundles pulled by other
//     vendors) is seen, because it ran;
//   * code served from the first-party origin to evade network-level blocking is still
//     identified, because the signature is in the source, not the hostname.
//
// Every detection carries the evidence that produced it. A signature table is a declared
// input, not a hidden judgement — same rule as the host-role table in the labeller.
//
// Usage:  node analysis/detect-stack.mjs <flows-dir> [--json out.json]
//   <flows-dir> is an extract-cookie-flows output dir (needs _scripts.json,
//   _script-origins.json and _src/).

import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2];
if (!dir) {
  console.error("usage: detect-stack.mjs <flows-dir> [--json out.json]");
  process.exit(1);
}
const jsonAt = process.argv.indexOf("--json");
const jsonOut = jsonAt > 0 ? process.argv[jsonAt + 1] : null;

// ---------------------------------------------------------------------------
// Signature table. `src` matches script source text, `url` matches the origin URL.
// `id` extracts an account/tenant identifier — the field a privacy team actually needs,
// because it names the data controller instance rather than just the product.
// ---------------------------------------------------------------------------
const SIGS = [
  // --- frameworks -------------------------------------------------------
  { name: "Next.js", cat: "framework", url: /\/_next\/static\//,
    ver: /"buildId":"([^"]{6,40})"/, verLabel: "buildId" },
  { name: "React", cat: "framework",
    src: /__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom\.production|createElementWithValidation/ },
  { name: "webpack", cat: "bundler",
    src: /webpackJsonp|__webpack_require__|webpackChunk/ },
  { name: "jQuery", cat: "library",
    src: /jQuery\.fn\.jquery|jQuery\.extend\(|jquery[/-]\d+\.\d+\.\d+/,
    ver: /jquery[/-]?(\d+\.\d+\.\d+)/i },
  { name: "Vue.js", cat: "framework", src: /__VUE_DEVTOOLS_GLOBAL_HOOK__|Vue\.config\.productionTip/ },
  { name: "Angular", cat: "framework",
    src: /angular\.module\(|__NG_DEVTOOLS|platformBrowserDynamic|ng-version="/ },

  // --- tag management / CDP --------------------------------------------
  { name: "Google Tag Manager", cat: "tag manager", url: /googletagmanager\.com\/gtm\.js|\/gtm\.js\?/,
    id: /[?&]id=(GTM-[A-Z0-9]+)/, idLabel: "container" },
  { name: "Google Tag (gtag.js)", cat: "tag manager", url: /googletagmanager\.com\/gtag\/js/,
    id: /[?&]id=(G-[A-Z0-9]+|AW-[0-9]+|UA-[0-9-]+|DC-[0-9]+)/, idLabel: "tag id" },
  { name: "Tealium iQ", cat: "tag manager", url: /tags\.tiqcdn\.com|utag\.js/,
    id: /tiqcdn\.com\/utag\/([^/]+\/[^/]+)/, idLabel: "account/profile" },
  { name: "Adobe Launch / DTM", cat: "tag manager", url: /assets\.adobedtm\.com/,
    id: /adobedtm\.com\/([a-f0-9]{8,})/, idLabel: "property" },
  { name: "Segment", cat: "CDP", url: /cdn\.segment\.(com|io)/,
    id: /analytics\.js\/v1\/([A-Za-z0-9]{10,})\//, idLabel: "write key" },
  { name: "Ensighten", cat: "tag manager", url: /nexus\.ensighten\.com/ },

  // --- analytics --------------------------------------------------------
  { name: "Google Analytics 4", cat: "analytics", url: /google-analytics\.com\/g\/collect|\/gtag\/js\?id=G-/,
    src: /gtag\(['"]config['"]/, id: /\b(G-[A-Z0-9]{6,})\b/, idLabel: "measurement id" },
  { name: "Adobe Analytics", cat: "analytics", src: /AppMeasurement|s_account|\bs_code\.js\b/,
    url: /omtrdc\.net|AppMeasurement/, id: /([a-z0-9]+)\.sc\.omtrdc\.net/, idLabel: "report suite" },
  { name: "New Relic Browser", cat: "APM", src: /NREUM|nr-data\.net/, url: /nr-data\.net|newrelic/,
    id: /"applicationID":"(\d+)"/, idLabel: "app id" },
  { name: "Quantum Metric", cat: "session replay", url: /quantummetric/, src: /QuantumMetricAPI/ },
  { name: "Glassbox", cat: "session replay",
    src: /_glassbox|glassbox\.com|GlassboxSDK|window\._detector\b/, url: /glassbox/ },
  { name: "Dynatrace RUM", cat: "APM", src: /ruxitagentjs|\bdtrum\b|dT_\s*=|dynatrace/i,
    url: /ruxitagentjs|dynatrace/ },
  { name: "Decibel Insight", cat: "session replay", src: /decibelInsight\s*[({.]/, url: /decibelinsight/ },
  { name: "Contentsquare", cat: "session replay", src: /\bCS_CONF\b|contentsquare/i, url: /contentsquare/ },
  { name: "FullStory", cat: "session replay", src: /\bFS\.identify\b|fullstory\.com/, url: /fullstory\.com/ },
  { name: "Hotjar", cat: "session replay", url: /static\.hotjar\.com/, id: /hjid:(\d+)/, idLabel: "site id" },
  { name: "Celebrus", cat: "customer data", url: /celebrus/, src: /Celebrus|celebrus/ },
  { name: "Optimizely", cat: "experimentation", url: /optimizely\.com/, src: /optimizely/ },
  { name: "Qualtrics", cat: "survey", url: /qualtrics\.com/, src: /QSI\.API|qualtrics/ },
  { name: "ZineOne", cat: "personalisation", url: /zineone/, src: /zineone|ZineOne/ },
  { name: "Invoca", cat: "call tracking", url: /invoca(cdn)?\.(net|com)/, src: /Invoca\.Client/ },

  // --- advertising ------------------------------------------------------
  { name: "Meta Pixel", cat: "advertising", url: /connect\.facebook\.net\/.*fbevents\.js/,
    src: /fbq\(['"]init['"]|SignalsFBEvents/, id: /fbq\(['"]init['"],\s*['"](\d{8,})['"]/, idLabel: "pixel id" },
  { name: "Google Ads / Floodlight", cat: "advertising", url: /googleadservices\.com|doubleclick\.net/ },
  { name: "The Trade Desk", cat: "advertising", url: /adsrvr\.org/ },
  { name: "Criteo", cat: "advertising", url: /criteo\.(com|net)/ },
  { name: "Bing / Microsoft UET", cat: "advertising", url: /bat\.bing\.com/, id: /ti:\s*"(\d+)"/, idLabel: "tag id" },
  { name: "TikTok Pixel", cat: "advertising", url: /analytics\.tiktok\.com/ },

  // --- consent ----------------------------------------------------------
  { name: "OneTrust", cat: "consent", url: /cdn\.cookielaw\.org|onetrust/, src: /OneTrust|Optanon/,
    id: /data-domain-script=["']([a-f0-9-]{8,})/, idLabel: "domain script" },
  { name: "TrustArc", cat: "consent", url: /consent\.trustarc\.com|truste/ },
  { name: "Usercentrics", cat: "consent", url: /usercentrics\.eu/ },
  { name: "reads IAB TCF signal (__tcfapi)", cat: "consent signal", src: /__tcfapi/ },
  { name: "reads US Privacy signal (__uspapi)", cat: "consent signal", src: /__uspapi/ },
  { name: "reads Global Privacy Control", cat: "consent signal", src: /globalPrivacyControl/ },

  // --- bot / security ---------------------------------------------------
  { name: "Akamai Bot Manager", cat: "bot defence",
    src: /bmak\.|_abck|sensor_data/, url: /^https?:\/\/[^/]+\/[A-Za-z0-9_-]{8,}\/[A-Za-z0-9_-]{4,}\/[A-Za-z0-9_-]{4,}\// },
  { name: "PerimeterX / HUMAN", cat: "bot defence", src: /_pxAppId|PXjJ0cYtn9|perimeterx/i, url: /perimeterx|px-cloud/ },
  { name: "DataDome", cat: "bot defence", src: /datadome/i, url: /datadome/ },
  { name: "Cloudflare Challenge", cat: "bot defence",
    src: /__CF\$cv\$params|cf_chl_|turnstile/, url: /challenges\.cloudflare\.com/ },
  { name: "reCAPTCHA", cat: "bot defence", url: /google\.com\/recaptcha/ },
];

// ---------------------------------------------------------------------------
const scripts = JSON.parse(readFileSync(join(dir, "_scripts.json"), "utf8"));
const origins = JSON.parse(readFileSync(join(dir, "_script-origins.json"), "utf8")).scripts;
const pageUrl = JSON.parse(readFileSync(join(dir, "_script-origins.json"), "utf8")).pageUrl;

const srcOf = (rec) => {
  const m = /-> (_src\/[^>]+)>/.exec(rec.source || "");
  if (m) { const p = join(dir, m[1]); return existsSync(p) ? readFileSync(p, "utf8") : ""; }
  return rec.source || "";
};

const pageDomain = (() => { try { return new URL(pageUrl).hostname.split(".").slice(-2).join("."); } catch { return ""; } })();

const VENDOR_TOKENS = /elasticApm|instana|PLUMBR|decibelInsight|CS_CONF|glassbox|hotjar|newrelic|NREUM|appdynamics|ruxit|dynatrace|quantum|fullstory|mouseflow|smartlook|clarity/gi;
const looksLikeVendorDictionary = (src, index) => {
  if (index == null || !src) return false;
  const win = src.slice(Math.max(0, index - 260), index + 260);
  const names = new Set((win.match(VENDOR_TOKENS) || []).map(x => x.toLowerCase()).filter(Boolean));
  // Three or more distinct competitor names crowded around the hit, each paired with a key,
  // is a lookup table of other people's products.
  // The tell is a run of `name: "GlobalVariable"` pairs -- object-literal keys are usually
  // unquoted in minified code, so the quote must only be required on the value side.
  return names.size >= 3 && /\w\s*:\s*["'`]\w/.test(win);
};

const found = new Map(); // name -> detection
for (const [nid, rec] of Object.entries(scripts)) {
  const o = origins[nid] || {};
  const url = o.url || "";
  let src = null; // read lazily: only when a source signature is in play

  for (const sig of SIGS) {
    let via = null;
    if (sig.url && url && sig.url.test(url)) via = "url";
    if (!via && sig.src) {
      if (src === null) src = srcOf(rec);
      if (src) {
        const m = sig.src.exec(src);
        if (m && !looksLikeVendorDictionary(src, m.index)) via = "source";
      }
    }
    if (!via) continue;

    if (src === null) src = srcOf(rec);
    const hay = `${url}\n${src}`;
    const cur = found.get(sig.name) || {
      name: sig.name, category: sig.cat, via: new Set(), hosts: new Set(),
      parties: new Set(), ids: new Set(), versions: new Set(), scripts: 0, example: null,
      // A signature can match for two very different reasons: the vendor's own bundle is
      // present, or first-party code merely CALLS the vendor's API. Those are different
      // findings, so record which script matched and show the matching code.
      vendorHosted: false, firstPartyMatches: [],
    };
    cur.via.add(via);
    // The URL pattern is the vendor's own domain, so a URL match means vendor-hosted code.
    if (via === "url") cur.vendorHosted = true;
    if (o.host && pageDomain && o.host.endsWith(pageDomain) && cur.firstPartyMatches.length < 3) {
      const m = sig.src ? sig.src.exec(src || "") : null;
      cur.firstPartyMatches.push({
        host: o.host, url: url || "(inline)",
        snippet: m ? (src.slice(Math.max(0, m.index - 70), m.index + 90).replace(/\s+/g, " ")) : null,
      });
    }
    if (o.host) cur.hosts.add(o.host);
    cur.parties.add(o.inline ? "inline" : o.party || "unknown");
    cur.scripts++;
    if (!cur.example) cur.example = url || "(inline script)";
    if (sig.id) { const m = sig.id.exec(hay); if (m) cur.ids.add(`${sig.idLabel || "id"}=${m[1]}`); }
    if (sig.ver) { const m = sig.ver.exec(hay); if (m) cur.versions.add(`${sig.verLabel || "v"}=${m[1]}`); }
    found.set(sig.name, cur);
  }
}

// A vendor signature on a first-party URL means the vendor's code is being served from the
// site's own origin — the arrangement that defeats hostname blocklists and, for a compliance
// audit, the one worth surfacing on its own.
const VENDOR_CATS = new Set(["advertising", "analytics", "session replay", "tag manager",
  "CDP", "bot defence", "consent", "customer data", "personalisation", "call tracking",
  "experimentation", "survey", "APM"]);
const out = [...found.values()].map(d => ({
  name: d.name, category: d.category,
  detectedBy: [...d.via].join(" + "),
  scripts: d.scripts,
  servedFrom: [...d.hosts],
  parties: [...d.parties],
  accountIds: [...d.ids],
  versions: [...d.versions],
  // Served first-party only when the vendor's code appears on the site's own origin AND the
  // vendor is not also serving it from its own domain. Otherwise a first-party match is a
  // call site in the site's own code, which is a different arrangement.
  firstPartyServed: VENDOR_CATS.has(d.category) && d.firstPartyMatches.length > 0 && !d.vendorHosted,
  firstPartyCallSite: VENDOR_CATS.has(d.category) && d.firstPartyMatches.length > 0 && d.vendorHosted,
  firstPartyEvidence: d.firstPartyMatches,
  example: d.example,
})).sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));

// ---------------------------------------------------------------------------
// Network channel (optional): --net <stack-network.mjs output>.
// Headers name the CDN, origin server and backend framework -- facts no amount of JS
// reading reveals. Body schemas and Set-Cookie scopes identify vendors that ship no
// script at all, which the source channel cannot see by construction.
// ---------------------------------------------------------------------------
const netAt = process.argv.indexOf("--net");
const netFile = netAt > 0 ? process.argv[netAt + 1] : null;
const infra = [], wireOnly = [], endpointSigs = [];

if (netFile && existsSync(netFile)) {
  const net = JSON.parse(readFileSync(netFile, "utf8"));

  const HDR = [
    [/cloudflare/i, "Cloudflare", "CDN"], [/akamai/i, "Akamai", "CDN"],
    [/cloudfront/i, "AWS CloudFront", "CDN"], [/AmazonS3/i, "Amazon S3", "origin"],
    [/Google Frontend|1\.1 google/i, "Google Cloud", "origin"], [/varnish/i, "Varnish", "cache"],
    [/nginx/i, "nginx", "origin"], [/apache/i, "Apache", "origin"],
    [/Express/i, "Express (Node.js)", "backend"], [/ASP\.NET/i, "ASP.NET", "backend"],
    [/PHP/i, "PHP", "backend"], [/vercel/i, "Vercel", "hosting"], [/fastly/i, "Fastly", "CDN"],
    [/envoy/i, "Envoy", "proxy"], [/openresty/i, "OpenResty", "origin"],
  ];
  for (const h of net.hosts) {
    const hay = Object.entries(h.infraHeaders).map(([k, v]) => `${k}: ${v.join(" ")}`).join("\n");
    for (const [re, name, role] of HDR) {
      if (!re.test(hay)) continue;
      infra.push({ host: h.host, name, role,
        evidence: Object.entries(h.infraHeaders).filter(([k, v]) => re.test(k) || v.some(x => re.test(x)))
          .map(([k, v]) => `${k}: ${v[0]}`)[0] || hay.split("\n")[0],
        firstParty: pageDomain && h.host.endsWith(pageDomain) });
    }
  }

  const scriptHosts = new Set(out.flatMap(d => d.servedFrom));
  for (const h of net.hosts) {
    if (scriptHosts.has(h.host)) continue;
    if (pageDomain && h.host.endsWith(pageDomain)) continue;
    wireOnly.push({ host: h.host, resourceTypes: h.resourceTypes,
      serverSetCookies: h.serverSetCookies });
  }

  // Body shape identifies the product even when no script was recognised.
  const BODY = [
    [/\bsensor_data\b/, "Akamai Bot Manager"], [/\bapi_key\b.*\bdevice_id\b|braze/i, "Braze"],
    [/\bwriteKey\b|\bwrite_key\b/, "Segment"], [/\baccount_id\b.*\bvisitors\b/, "Optimizely"],
    [/\bnetwork_id\b.*\btag_id\b/, "Invoca"], [/\bconsentreceipts\b|\bpurposes\b.*\bdsDataElements\b/, "OneTrust"],
    [/\bcustomerId\b.*\bdeviceId\b.*z1/i, "ZineOne"],
  ];
  for (const e of net.postEndpoints) {
    const hay = `${e.endpoint} ${e.fields.join(" ")}`;
    for (const [re, name] of BODY) if (re.test(hay)) endpointSigs.push({ name, endpoint: e.endpoint, fields: e.fields.slice(0, 8) });
  }
}

const report = { pageUrl, scriptsAnalysed: Object.keys(scripts).length, detections: out,
  infrastructure: infra, networkOnlyHosts: wireOnly, endpointSignatures: endpointSigs };
if (jsonOut) writeFileSync(jsonOut, JSON.stringify(report, null, 2));

console.log(`${pageUrl}   (${report.scriptsAnalysed} scripts that actually executed)\n`);
let cat = null;
for (const d of out) {
  if (d.category !== cat) { cat = d.category; console.log(`  ${cat.toUpperCase()}`); }
  const bits = [];
  if (d.accountIds.length) bits.push(d.accountIds.join(", "));
  if (d.versions.length) bits.push(d.versions.join(", "));
  bits.push(`via ${d.detectedBy}`);
  if (d.firstPartyServed) bits.push("SERVED FIRST-PARTY");
  console.log(`    ${d.name.padEnd(26)} ${bits.join("  |  ")}`);
  console.log(`    ${" ".repeat(26)} ${d.servedFrom.slice(0, 3).join(", ") || "inline"}`);
}

if (infra.length) {
  console.log("\n  INFRASTRUCTURE (from response headers)");
  const seen = new Set();
  for (const i of infra) {
    const k = `${i.host}|${i.name}`; if (seen.has(k)) continue; seen.add(k);
    console.log(`    ${i.host.padEnd(34)} ${i.name} (${i.role})${i.firstParty ? "  <- first-party host" : ""}`);
    console.log(`    ${" ".repeat(34)} ${i.evidence}`);
  }
}
if (endpointSigs.length) {
  console.log("\n  IDENTIFIED BY REQUEST BODY SHAPE");
  for (const e of endpointSigs) console.log(`    ${e.name.padEnd(24)} ${e.endpoint}\n    ${" ".repeat(24)} fields: ${e.fields.join(", ")}`);
}
if (wireOnly.length) {
  console.log(`\n  NETWORK-ONLY HOSTS (${wireOnly.length}) — contacted, but ran no script here`);
  for (const w of wireOnly) {
    const sc = w.serverSetCookies.length ? `  sets: ${w.serverSetCookies.slice(0, 2).join(", ")}` : "";
    console.log(`    ${w.host.padEnd(38)}${w.resourceTypes.slice(0, 2).join(",")}${sc}`);
  }
}
