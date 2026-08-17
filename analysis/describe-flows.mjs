#!/usr/bin/env node
// describe-flows.mjs — say what each stored item was actually USED FOR.
//
//   node analysis/describe-flows.mjs <flowdir> [--item <name>] [--json]
//
// Reads the output of extract-cookie-flows.mjs and turns it into behaviour, not
// tallies. How often a value was read is close to meaningless — a value read once and
// written into an ad request matters more than one read continuously and never sent.
// So this reports DISTINCT behaviours: where the value came from, which function asked
// for it, what was done to it, and by what mechanism it left the page.
//
// The distinction that carries the most weight is passive vs deliberate:
//   - the browser attaching a cookie to a request is NOT evidence about the cookie. Every
//     in-scope cookie rides every matching request; it is a property of the browser, true
//     of everything, and so says nothing. It is recorded but never described as behaviour.
//   - a script lifting the value out of storage and re-encoding it into a URL, an image
//     src, or a custom header is deliberate harvesting, and is what the label turns on
//
// The other thing worth surfacing is WHO read it. A third-party tag running in the page
// reads `document.cookie` and receives every JS-accessible first-party cookie, including
// ones set by other vendors — a cross-vendor disclosure with no cross-domain request
// involved, invisible to any network-level audit. Reader identity comes from
// _script-origins.json (resolve-script-origins.mjs).

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const asJson = argv.includes("--json");
const only = flag("--item", null);
const DIR = argv.find(a => !a.startsWith("--") && !["--item", only].includes(a));
if (!DIR || !existsSync(join(DIR, "_summary.json"))) {
  process.stderr.write("usage: node analysis/describe-flows.mjs <flowdir> [--item <name>] [--json]\n");
  process.exit(1);
}

const summary = JSON.parse(readFileSync(join(DIR, "_summary.json"), "utf8"));
const originsPath = join(DIR, "_script-origins.json");
const ORIGINS = existsSync(originsPath) ? JSON.parse(readFileSync(originsPath, "utf8")) : null;
const whoIs = (nodeId) => {
  const s = ORIGINS?.scripts?.[nodeId];
  if (!s) return null;
  if (s.party === "third-party") return { label: `${s.registrableDomain} (third-party script)`, third: true, vendor: s.registrableDomain };
  if (s.inline) return { label: "the page's own inline script", third: false, vendor: null };
  return { label: `${s.registrableDomain || "the site"} (first-party script)`, third: false, vendor: s.registrableDomain };
};
// The script's LOADING PATH: what caused it to be on the page, walked back to the page HTML.
// A JS call stack shows frames inside one bundle; it does not show that the bundle was injected
// by a tag manager which was itself injected by the consent banner. Presented root-first
// (page HTML → … → this script), which is how a reader follows responsibility.
const loadPathOf = (nodeId) => {
  const c = ORIGINS?.chains?.[nodeId];
  if (!c || !c.length) return null;
  return c.slice().reverse().map(h => ({
    url: h.parser ? (h.url || "the page") : (h.url || null),
    host: h.host || null,
    page: !!h.parser,
    inline: !h.parser && !h.url,
  }));
};
const hostOf = u => { try { return new URL(String(u)).hostname; } catch {
  const m = String(u).match(/^\/\/?([^/?#]+)/); return m ? m[1] : null; } };
const regOf = h => { if (!h) return null; const p = h.split("."); return p.length <= 2 ? h : p.slice(-2).join("."); };

// transforms worth naming when a value passes through them
const TRANSFORM = {
  "Window.btoa": "base64-encoded", "Window.atob": "base64-decoded",
  "JsonStringify": "serialised to JSON", "JsonParse": "parsed from JSON",
  "TextEncoder.encode": "encoded to bytes", "Window.encodeURIComponent": "URL-encoded",
  "SubtleCrypto.digest": "hashed",
};
const NETSINK = /(?:^|\.)fetch\b|XMLHttpRequest\.(?:open|send|setRequestHeader)\b|sendBeacon\b|(?:^|\.)WebSocket\b|EventSource\b/i;

const describe = (doc) => {
  const nodes = doc.involvedNodes || {};
  const behaviours = [];   // distinct, de-duplicated
  const add = (kind, text, detail) => {
    const k = kind + "|" + text;
    if (!behaviours.some(b => b.k === k)) behaviours.push({ k, kind, text, detail });
  };

  // ---------- where it came from ----------
  for (const op of doc.operations) {
    const et = op.a["edge type"];
    if (et !== "storage set") continue;
    const src = nodes[op.s] || {};
    const via = op.a["cookie source"];
    if (via === "set-cookie-header") {
      const h = hostOf(src.url);
      add("origin", `issued by the server in a Set-Cookie response from ${h || "an unnamed endpoint"}`,
        { host: h, url: src.url });
    } else {
      // Name the script that wrote it. The write edge's source node identifies the script
      // exactly as it does for reads; attributing every write to an unnamed "page script"
      // discards that and makes a first-party write indistinguishable from a vendor's.
      const fn = op.actingFn
        || (() => { try { return JSON.parse(op.a["stack trace"] || "null")?.callFrames?.[0]?.functionName || null; }
                    catch { return null; } })();
      const who = whoIs(op.s);
      // The top stack frame's own URL is the most precise answer available, and can differ
      // from the script node when the write happens in a callback another bundle installed.
      const topUrl = op.frames?.[0]?.url || null;
      const topHost = hostOf(topUrl);
      const writer = who ? who.label
        : topHost ? `${regOf(topHost)} script`
        : "a script whose origin was not resolved";
      add("origin", `written by ${writer}${fn ? ` in function ${fn}()` : ""}`,
        { fn, writer: who?.label || regOf(topHost), thirdPartyWriter: !!who?.third,
          vendor: who?.vendor || regOf(topHost), scriptUrl: who ? undefined : topUrl,
          frames: op.frames || null, loadPath: loadPathOf(op.s) });
    }
  }
  if (!doc.operations.some(o => o.a["edge type"] === "storage set")) {
    add("origin", "present in storage but its creation was not observed in this crawl", {});
  }

  // ---------- who wanted it ----------
  for (const op of doc.operations) {
    const ri = op.readIntent;
    if (!ri || !ri.looksFor?.length) continue;
    const ev = ri.evidence?.[doc.item];
    if (!ev) continue;
    const who = whoIs(op.s);
    add("read", `read back by ${who ? who.label : "a script"}${ev.fn ? `, in ${ev.fn}()` : ""}${ev.idioms?.length ? `, parsing the jar with ${ev.idioms.join(" and ")}` : ""}`,
      { fn: ev.fn, chain: ri.callChain?.slice(0, 6), reader: who?.label, thirdPartyReader: !!who?.third,
        vendor: who?.vendor, frames: op.frames || null, loadPath: loadPathOf(op.s) });
  }
  if (doc.bucket !== "cookie") {
    for (const op of doc.operations) {
      if (op.a["edge type"] !== "read storage call") continue;
      const who2 = whoIs(op.s);
      add("read", `read back from ${doc.bucket} by name${who2 ? ` by ${who2.label}` : ""}`,
        { reader: who2?.label, thirdPartyReader: !!who2?.third, vendor: who2?.vendor });
      break;
    }
  }

  // ---------- what was done with it ----------
  for (const c of doc.carriedOn) {
    const et = c.a["edge type"];
    const src = nodes[c.s] || {}, tgt = nodes[c.t] || {};

    if (et === "set attribute" && /src/i.test(c.a.key || "")) {
      const h = hostOf(c.a.value);
      add("exfil", `placed into the ${tgt["tag name"] || "element"} \`src\` attribute pointing at ${h || "a URL"}, which loads it as a request`,
        { host: h, mechanism: "element src", url: String(c.a.value).slice(0, 300), deliberate: true });
      continue;
    }
    if (et === "js call") {
      const method = tgt.method || tgt.id || "an unnamed function";
      if (TRANSFORM[method]) { add("transform", `${TRANSFORM[method]} by ${method}`, { method }); continue; }
      if (NETSINK.test(method)) {
        let dest = null;
        try { const a = JSON.parse(c.a.args); for (const x of Array.isArray(a) ? a : [])
          if (typeof x === "string" && /^(https?:)?\/\/|^\//.test(x)) { dest = x; break; } } catch { /* */ }
        add("exfil", `passed to ${method}${dest ? ` targeting ${hostOf(dest) || dest.slice(0, 60)}` : ""}`,
          { method, host: hostOf(dest), mechanism: method, deliberate: true });
        continue;
      }
      add("consume", `passed to ${method}`, { method });
      continue;
    }
    if (et === "request start" || et === "request complete" || et === "request redirect") {
      const url = tgt.url || src.url;
      const h = hostOf(url);
      // is the value in the URL itself, or only in the Cookie header?
      const inUrl = url && String(url).includes(c.matched);
      let inCookieHdr = false;
      try { for (const hd of JSON.parse(c.a.headers || "[]"))
        if (/^cookie$/i.test(hd.name) && String(hd.value).includes(c.matched)) inCookieHdr = true; } catch { /* */ }
      if (inUrl) {
        add("exfil", `written into the request URL sent to ${h || "an endpoint"}`,
          { host: h, mechanism: "query string", url: String(url).slice(0, 300), deliberate: true });
      } else if (inCookieHdr) {
        // browser-automatic; true of every in-scope cookie, so not reported as behaviour
        add("carriage", `__auto__${h || ""}`, { host: h, mechanism: "Cookie header", deliberate: false });
      } else {
        // Neither in the URL nor in a Cookie header we could read. Most often this is
        // ordinary carriage on a request whose headers were not captured. Claiming
        // deliberate harvesting here would be an over-reach, so it is reported as
        // unresolved and does NOT count towards "sent".
        add("unclear", `appears in a ${et === "request redirect" ? "redirect" : "request"} to ${h || "an endpoint"}, but the mechanism could not be determined from the recorded headers`,
          { host: h, mechanism: et, deliberate: false });
      }
      continue;
    }
    if (et === "js result") {
      add("transform", "returned from a function call, so it flows onward through derived values", {});
    }
  }


  // ---------- capability probe ----------
  // A script that writes a throwaway key, reads it straight back, and deletes it is
  // testing whether the storage bucket works — not identifying anyone. The giveaway is
  // the round trip with no transmission, and often key === value. Classifying these as
  // "never used" would be wrong: they were used, just not for anything about the user.
  const ops = doc.operations.map(o => o.a["edge type"]);
  const wrote = ops.includes("storage set");
  const readBack = ops.includes("storage read result") || ops.includes("read storage call");
  const deleted = ops.includes("delete storage");
  const keyEqualsValue = (doc.values || []).some(v => v === doc.item);
  const looksLikeTestName = /test|probe|check|__storage/i.test(doc.item);
  const nothingSent = !behaviours.some(b => b.kind === "exfil" || b.kind === "carriage");
  const isProbe = wrote && readBack && nothingSent && (deleted || keyEqualsValue || looksLikeTestName);
  if (isProbe) {
    behaviours.length = 0;
    add("probe", `storage availability probe — written, read straight back${deleted ? ", then deleted" : ""}${keyEqualsValue ? ", key and value identical" : ""}; never transmitted`, { deleted, keyEqualsValue });
  }

  // ---------- summarise ----------
  const exfil = behaviours.filter(b => b.kind === "exfil");
  const hosts = [...new Set(exfil.map(b => b.detail?.host).filter(Boolean))];
  const pageHost = hostOf(doc.pageUrl);
  const pageReg = regOf(pageHost);
  const offsite = [...new Set(hosts.map(regOf).filter(h => h && h !== pageReg))];
  const readers = behaviours.filter(b => b.kind === "read");
  const thirdPartyReaders = [...new Set(readers.filter(b => b.detail?.thirdPartyReader).map(b => b.detail.vendor).filter(Boolean))];
  return {
    item: doc.item, bucket: doc.bucket,
    values: doc.values || [],
    thirdPartyReaders,
    behaviours: behaviours.map(({ kind, text, detail }) => ({ kind, text, detail })),
    deliberatelySent: exfil.length > 0,
    passiveCarriageOnly: exfil.length === 0 && behaviours.some(b => b.kind === "carriage"),
    destinations: hosts,
    offsiteDestinations: offsite,
    transforms: behaviours.filter(b => b.kind === "transform").map(b => b.text),
    isProbe,
    neverUsed: !behaviours.some(b => ["read", "exfil", "carriage", "consume", "transform", "probe"].includes(b.kind)),
  };
};

const docs = readdirSync(join(DIR, "flows"))
  .map(f => JSON.parse(readFileSync(join(DIR, "flows", f), "utf8")))
  .filter(d => !only || d.item === only);

const described = docs.map(describe);
// two items holding the identical value cannot be told apart by value matching; say so
const valueOwners = new Map();
for (const d of described) for (const v of d.values) {
  if (!valueOwners.has(v)) valueOwners.set(v, []);
  valueOwners.get(v).push(`${d.bucket}:${d.item}`);
}
const nameBuckets = new Map();
for (const d of described) {
  if (!nameBuckets.has(d.item)) nameBuckets.set(d.item, new Set());
  nameBuckets.get(d.item).add(d.bucket);
}
for (const d of described) {
  d.alsoInBuckets = [...(nameBuckets.get(d.item) || [])].filter(b => b !== d.bucket);
  const shared = new Set();
  for (const v of d.values) for (const o of valueOwners.get(v) || [])
    if (o !== `${d.bucket}:${d.item}`) shared.add(o);
  d.sharesValueWith = [...shared];
}
const out = described.sort((a, b) =>
  (b.offsiteDestinations.length - a.offsiteDestinations.length) ||
  (b.deliberatelySent - a.deliberatelySent) || a.item.localeCompare(b.item));

if (asJson) { process.stdout.write(JSON.stringify({ page: summary.pageUrl, items: out }, null, 2) + "\n"); process.exit(0); }

console.log("═".repeat(80));
console.log(`WHAT EACH STORED ITEM WAS USED FOR — ${summary.pageUrl}`);
console.log("═".repeat(80));
const ORDER = { probe: -1, origin: 0, read: 1, transform: 2, exfil: 3, carriage: 4, consume: 5, unclear: 6 };
const LABEL = { origin: "came from", read: "wanted by", transform: "transformed", exfil: "SENT", carriage: "carried", consume: "used by", unclear: "unresolved", probe: "probe" };
for (const it of out) {
  console.log(`\n${"─".repeat(80)}`);
  const tag = it.offsiteDestinations.length ? "  ⟵ leaves the site" : it.deliberatelySent ? "  ⟵ harvested and sent" : "";
  console.log(`${it.bucket} :: ${it.item}${tag}`);
  if (it.neverUsed) { console.log("    stored, but nothing read or sent it during this crawl"); continue; }
  const bs = it.behaviours.filter(b => b.kind !== "carriage")
    .slice().sort((a, b) => (ORDER[a.kind] ?? 9) - (ORDER[b.kind] ?? 9));
  let last = null;
  for (const b of bs) {
    const lbl = b.kind === last ? "".padEnd(11) : (LABEL[b.kind] || b.kind).padEnd(11);
    last = b.kind;
    console.log(`    ${lbl} ${b.text}`);
  }
  if (it.thirdPartyReaders?.length) console.log(`    ⚠ read by   ${it.thirdPartyReaders.join(", ")} — a third-party script reading first-party storage from inside the page (no cross-domain request involved)`);
  if (it.offsiteDestinations.length) console.log(`    off-site    ${it.offsiteDestinations.join(", ")}`);
  if (it.alsoInBuckets?.length) console.log(`    duplicated  the same name is also held in ${it.alsoInBuckets.join(" and ")} — storing an identifier in a second bucket survives clearing the first`);
  if (it.sharesValueWith?.length) console.log(`    caveat      identical value to ${it.sharesValueWith.join(", ")} — their flows cannot be separated by value alone`);
}
console.log(`\n${"═".repeat(80)}`);
const leaving = out.filter(i => i.offsiteDestinations.length).map(i => `${i.bucket}:${i.item}`);
const harvested = out.filter(i => i.deliberatelySent && !i.offsiteDestinations.length).map(i => `${i.bucket}:${i.item}`);
const passive = out.filter(i => i.passiveCarriageOnly).map(i => `${i.bucket}:${i.item}`);
const idle = out.filter(i => i.neverUsed && !i.isProbe).map(i => `${i.bucket}:${i.item}`);
if (leaving.length)   console.log(`value leaves the site : ${leaving.join(", ")}`);
if (harvested.length) console.log(`harvested, stays local: ${harvested.join(", ")}`);
const crossVendor = out.filter(i => i.thirdPartyReaders?.length).map(i => `${i.bucket}:${i.item} -> ${i.thirdPartyReaders.join("/")}`);
if (crossVendor.length) console.log(`read by other vendors : ${crossVendor.join(", ")}`);
if (passive.length)   console.log(`only browser carriage : ${passive.join(", ")}`);
const probes = out.filter(i => i.isProbe).map(i => `${i.bucket}:${i.item.slice(0, 28)}`);
if (probes.length)    console.log(`capability probes     : ${probes.join(", ")}`);
if (idle.length)      console.log(`never used            : ${idle.join(", ")}`);
