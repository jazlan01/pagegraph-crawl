// cookie-evidence.mjs — Stage 1: fuse the crawler's cookie sidecars and the
// existing streaming analysis scripts into one normalized CookieEvidence record
// per cookie. The analysis scripts are REUSED as-is (run as subprocesses in
// their JSON / --split modes); nothing here re-parses the graphml directly.
//
// Inputs (all derived from the graphml path's base `page_graph_<url>_<ts>`):
//   <base>.cookies.json         — authoritative inventory + attributes (required)
//   <base>.cookie-network.json  — HTTP channel: per-cookie {setBy[], sentTo[]} (optional)
//   cookie-reads.mjs  --split    — readers + value consumers (streaming; any size)
//   cookie-flow.mjs   --split    — taint → network hits (streaming; any size)
//   cookie-sites.mjs  <name>     — JS write/delete provenance + source channel
//                                  (readFileSync-based → size-gated; optional)

import { execFileSync } from "node:child_process";
import { graphBase } from "./graph-source.mjs";
import { readFileSync, existsSync, mkdtempSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { hostOf, registrableDomain, partyOf } from "./cookie-features.mjs";

const ANALYSIS_DIR = dirname(dirname(fileURLToPath(import.meta.url))); // .../analysis
const MAX_BUFFER = 512 * 1024 * 1024;

const safeName = (name) => name.replace(/[^\w.-]/g, "_");

const runJson = (script, args, log) => {
  try {
    const out = execFileSync("node", [join(ANALYSIS_DIR, script), ...args], {
      maxBuffer: MAX_BUFFER,
      encoding: "utf8",
    });
    return JSON.parse(out);
  } catch (e) {
    log?.(`  ! ${script} ${args.join(" ")} failed: ${String(e.message).split("\n")[0]}`);
    return null;
  }
};

const readJsonFile = (path) => {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
};

export const deriveBase = (graphmlPath) => graphBase(graphmlPath);

// ---------------------------------------------------------------------------
// Build all CookieEvidence records for a crawl.
// Returns { pageUrl, pageRegDomain, referenceEpochSec, cookies: Map<name, ev>, warnings[] }.
// ---------------------------------------------------------------------------
export const buildEvidence = (graphmlPath, opts = {}) => {
  const log = opts.log;
  const warnings = [];
  const base = deriveBase(graphmlPath);

  const inventory = readJsonFile(`${base}.cookies.json`);
  if (!inventory) {
    throw new Error(`missing or unreadable ${base}.cookies.json (run the crawl with --save-cookies)`);
  }
  const network = readJsonFile(`${base}.cookie-network.json`) || {};
  if (!existsSync(`${base}.cookie-network.json`)) {
    warnings.push("no .cookie-network.json — HTTP set/transmission channel unavailable");
  }

  // reference epoch for expiry-days: newest observed Set-Cookie timestamp isn't
  // in these sidecars, so fall back to the crawl timestamp embedded in the base
  // filename (…_<unixSeconds>). Coarse but deterministic and crash-proof.
  const tsMatch = base.match(/_(\d{9,11})$/);
  const referenceEpochSec = tsMatch ? Number(tsMatch[1]) : null;

  const tmp = mkdtempSync(join(tmpdir(), "cookie-evidence-"));
  log?.(`Stage 1: fusing evidence (tmp ${tmp})`);

  log?.("  running cookie-reads --split");
  const readsIndex = runJson("cookie-reads.mjs", [graphmlPath, "--split", join(tmp, "reads")], log);
  log?.("  running cookie-flow --split --rounds 1");
  const flowIndex = runJson("cookie-flow.mjs", [graphmlPath, "--split", join(tmp, "flow"), "--rounds", "1"], log);
  // Scans the `headers` blob stitched onto request edges for the cookie value in
  // URL query strings / Referer / custom headers — flows the js-call-arg matching
  // in cookie-reads/flow structurally cannot see.
  log?.("  running cookie-headers");
  const headerScan = runJson("cookie-headers.mjs", [graphmlPath, "--json"], log);

  const pageUrl = readsIndex?.pageUrl || flowIndex?.pageUrl || null;
  const pageRegDomain = pageUrl ? registrableDomain(pageUrl) : opts.pageRegDomain || null;

  // Write/delete provenance for ALL cookies in ONE streaming pass. Replaces the old
  // per-cookie `cookie-sites.mjs` invocations, which (a) used readFileSync so were
  // size-gated off on multi-GB graphs — leaving every cookie's setChannel "unknown" —
  // and (b) re-parsed the whole graph once per cookie (N parses for N cookies).
  log?.("  running cookie-writes (streaming, all cookies)");
  const writeScan = runJson("cookie-writes.mjs", [graphmlPath, "--json"], log);
  if (!writeScan) {
    warnings.push("cookie-writes failed — JS write provenance unavailable (setChannel may be 'unknown')");
  }

  // Request/response BODY exfiltration. This tool existed but was never invoked here, so a value
  // leaving inside a POST body was invisible to every classification ever produced — the one
  // channel PageGraph's own graph cannot show, since it records a request's size but not its
  // content. Non-fatal: bodies are a sidecar and may be absent (--no-save-bodies).
  // `--include-responses` also catches INFILTRATION — the value arriving in a response body
  // before being stored, which is how a server-minted id (and a bot-defence challenge token)
  // gets into a cookie. Both directions matter and the tool distinguishes them.
  const bodiesPath = `${base}.bodies.ndjson`;
  const bodiesExist = existsSync(bodiesPath) || existsSync(`${bodiesPath}.gz`);
  log?.("  running cookie-exfiltration (request/response bodies)");
  const bodyScan = bodiesExist
    ? runJson("cookie-exfiltration.mjs",
        [graphmlPath, existsSync(bodiesPath) ? bodiesPath : `${bodiesPath}.gz`,
         "--include-responses", "--json"], log)
    : null;
  if (!bodyScan) {
    warnings.push(bodiesExist
      ? "cookie-exfiltration failed — body exfiltration not assessed (absence is not evidence of none)"
      : "no .bodies.ndjson — body exfiltration not assessed (absence is not evidence of none)");
  }

  // Redirect chains. `.redirects.json` has been written by every crawl and read by nothing.
  // A setter that appears in a redirect chain is the cookie-sync signature (directv holds a
  // demdex → adsrvr chain), which the literature treats as a first-class tracking feature.
  const redirects = readJsonFile(`${base}.redirects.json`) || null;
  if (!redirects) warnings.push("no .redirects.json — redirect-chain features unavailable");

  // Hosts that appear in a redirect chain, and those that appear mid-chain (a hop that
  // redirected onward). Discriminate on hopStatus 3xx, NOT on the presence of hopIndex:
  // request_metadata_tracker records a hop for every tracked request, single-hop included,
  // so hopIndex is present on plenty of things that never redirected.
  const redirectHosts = new Set();
  const redirectChainHosts = new Set();
  for (const hops of Object.values(redirects || {})) {
    if (!Array.isArray(hops) || hops.length < 2) continue;
    for (const [i, hop] of hops.entries()) {
      const h = hostOf(hop?.url);
      if (!h) continue;
      redirectChainHosts.add(h);
      if (i < hops.length - 1 && Number(hop?.status) >= 300 && Number(hop?.status) < 400) {
        redirectHosts.add(h);
      }
    }
  }

  const cookies = new Map();

  for (const cdp of inventory) {
    const name = cdp.name;
    const ev = {
      name,
      domain: cdp.domain,
      path: cdp.path,
      value: cdp.value ?? "",
      attributes: {
        httpOnly: cdp.httpOnly,
        secure: cdp.secure,
        sameSite: cdp.sameSite ?? null,
        session: cdp.session,
        expires: cdp.expires,
        size: cdp.size,
        priority: cdp.priority ?? null,
        partitionKey: cdp.partitionKey ?? null,
        sourceScheme: cdp.sourceScheme ?? null,
      },
      set: { httpSetters: [], jsWrites: [], channels: new Set() },
      httpTransmission: [],
      reads: { readByJs: false, readerScripts: [] },
      jsExfil: { fired: false, destinations: [], consumerMethods: {} },
      headerExfil: { cookieHeaderRequests: 0, urlHits: 0, otherHeaderHits: 0, destinations: [] },
      // Request/response BODY exfiltration — the channel the graph cannot show, because
      // PageGraph records a request's size but never its content.
      // Split by direction. `request` = the value leaving (exfiltration). `response` = the value
      // arriving before being stored (infiltration — a server-minted id, or a bot-defence
      // challenge token). They are different claims and must not be summed.
      bodyExfil: { hits: 0, destinations: [], encodings: [], assessed: false },
      bodyInfil: { hits: 0, sources: [], assessed: false, lowConfidence: false },
      // Was this cookie's setter part of a redirect chain (the cookie-sync signature)?
      redirect: { setterInChain: false, setterRedirected: false, chainHosts: [], chains: [] },
      transforms: [],
      deletes: [],
    };

    // --- HTTP channel from .cookie-network.json --------------------------------
    const net = network[name];
    if (net) {
      for (const s of net.setBy || []) {
        const host = hostOf(s.url);
        ev.set.httpSetters.push({ requestId: s.requestId, url: s.url, host, party: partyOf(host, pageRegDomain) });
        ev.set.channels.add("http");
      }
      for (const t of net.sentTo || []) {
        const host = hostOf(t.url);
        ev.httpTransmission.push({ requestId: t.requestId, url: t.url, host, method: t.method, party: partyOf(host, pageRegDomain) });
      }
    }

    // --- reads + JS consumers from cookie-reads --------------------------------
    const reads = readJsonFile(join(tmp, "reads", `${safeName(name)}.json`));
    if (reads) {
      ev.reads.readByJs = (reads.readCount || 0) > 0;
      ev.reads.readerScripts = (reads.readers || []).map((r) => ({
        url: r.scriptUrl,
        host: hostOf(r.scriptUrl),
        party: partyOf(r.scriptUrl, pageRegDomain),
        getSites: r.getSites || [],
      }));
      for (const c of reads.consumers || []) {
        ev.jsExfil.consumerMethods[c.method] = (ev.jsExfil.consumerMethods[c.method] || 0) + 1;
        if (c.isNetworkSink) {
          const host = hostOf(c.destUrl) || hostOf(c.viaScriptUrl);
          ev.jsExfil.destinations.push({
            host,
            url: c.destUrl || null,
            party: partyOf(host, pageRegDomain),
            method: c.method,
            via: c.viaScriptUrl || null,
            round: 0,
          });
        }
      }
    }

    // --- taint → network from cookie-flow --------------------------------------
    const flow = readJsonFile(join(tmp, "flow", `${safeName(name)}.flow.json`));
    if (flow) {
      ev.jsExfil.fired = ev.jsExfil.fired || !!flow.firedNetworkRequest;
      for (const h of flow.networkHits || []) {
        const host = hostOf(h.destUrl) || hostOf(h.viaScriptUrl);
        ev.jsExfil.destinations.push({
          host,
          url: h.destUrl || null,
          party: partyOf(host, pageRegDomain),
          method: h.method,
          via: h.viaScriptUrl || null,
          round: h.round ?? 1,
        });
        if ((h.round ?? 0) > 0) ev.transforms.push(`value transformed before reaching ${host || "network"} (taint round ${h.round})`);
      }
    }
    if (ev.jsExfil.destinations.length > 0) ev.jsExfil.fired = true;
    // de-dup destinations by host|url|method
    {
      const seen = new Set();
      ev.jsExfil.destinations = ev.jsExfil.destinations.filter((d) => {
        const k = `${d.host}|${d.url}|${d.method}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
    }

    // --- value found in URLs / non-Cookie headers (cookie-headers) -------------
    const hs = headerScan?.cookies?.[name];
    if (hs) {
      ev.headerExfil.cookieHeaderRequests = hs.cookieHeaderRequests || 0;
      ev.headerExfil.urlHits = hs.urlHits || 0;
      ev.headerExfil.otherHeaderHits = hs.otherHeaderHits || 0;
      const seenDest = new Set();
      for (const h of hs.notable || []) {
        const key = `${h.host}|${h.header}|${h.channel}`;
        if (seenDest.has(key)) continue;
        seenDest.add(key);
        ev.headerExfil.destinations.push({
          host: h.host,
          party: partyOf(h.host, pageRegDomain),
          channel: h.channel, // "url" | "other-header"
          header: h.header,
          direction: h.direction,
          matchType: h.matchType, // "full" | "fragment" (prefix-stripped identifier)
          url: h.url,
          snippet: h.snippet,
        });
      }
      if (ev.headerExfil.destinations.some((d) => d.matchType === "fragment")) {
        ev.transforms.push("identifier fragment (prefix stripped) transmitted in a URL/header");
      }
    }

    // --- JS write provenance + source channel (streaming, any graph size) -----
    {
      const sites = writeScan?.cookies?.[name];
      if (sites) {
        for (const w of sites.writes || []) {
          const host = hostOf(w.scriptUrl);
          ev.set.jsWrites.push({
            scriptUrl: w.scriptUrl,
            host,
            party: partyOf(w.scriptUrl, pageRegDomain),
            offset: w.offset,
            source: w.source,
            timestamp: w.timestamp,
            // The VALUE of each write, not merely the fact of it. Dropping this collapsed the
            // difference between a cookie re-set with an identical value (an expiry refresh,
            // carrying no state) and one whose value genuinely mutates — the signature of a
            // session cookie maintaining measurement state while never being transmitted.
            // Keep only the assignment's value part: the attributes after the first ";" are
            // expiry/path noise that would make every write look distinct.
            value: typeof w.value === "string"
              ? w.value.replace(/^"|"$/g, "").split(";")[0]
              : null,
          });
          // `cookie source` = js | cookie-store | set-cookie-header
          if (w.source === "set-cookie-header") ev.set.channels.add("http");
          else if (w.source === "cookie-store") ev.set.channels.add("cookie-store");
          else ev.set.channels.add("js");
        }
        ev.deletes = (sites.deletes || []).map((d) => ({
          scriptUrl: d.scriptUrl,
          host: hostOf(d.scriptUrl),
          timestamp: d.timestamp,
        }));
      }
    }

    ev.set.channels = [...ev.set.channels];
    cookies.set(name, ev);
  }

  // --- body exfiltration + redirect-chain features, per cookie ---------------
  for (const [name, ev] of cookies) {
    const finds = bodyScan?.findings?.[name] || [];
    const out = finds.filter((f) => f.kind === "request");
    const back = finds.filter((f) => f.kind === "response");
    ev.bodyExfil.assessed = !!bodyScan;
    ev.bodyExfil.hits = out.length;
    ev.bodyExfil.destinations = [...new Set(out.map((f) => hostOf(f.url)).filter(Boolean))]
      .map((h) => ({ host: h, party: partyOf(h, pageRegDomain) }));
    ev.bodyExfil.encodings = [...new Set(out.map((f) => f.encoding).filter(Boolean))];
    ev.bodyInfil.assessed = !!bodyScan;
    ev.bodyInfil.hits = back.length;
    ev.bodyInfil.sources = [...new Set(back.map((f) => hostOf(f.url)).filter(Boolean))].slice(0, 8);
    // A short or low-entropy value matches the page's own markup everywhere — directv's `qmd`
    // is literally "directv.com" and "hits" every response. Treat infiltration for such values
    // as unreliable rather than letting a collision read as a server-issued identifier.
    ev.bodyInfil.lowConfidence = (ev.value || "").length < 16 || !/[0-9]/.test(ev.value || "");

    // Every host that set this cookie, by either channel.
    const setters = [
      ...ev.set.httpSetters.map((s) => s.host),
      ...ev.set.jsWrites.map((w) => w.host),
    ].filter(Boolean);
    ev.redirect.setterRedirected = setters.some((h) => redirectHosts.has(h));
    ev.redirect.setterInChain = setters.some((h) => redirectChainHosts.has(h));
    ev.redirect.chainHosts = [...new Set(setters.filter((h) => redirectChainHosts.has(h)))];
    // The hop sequence itself. "demdex.net -> adsrvr.org" is a cookie sync; the hostname list
    // alone cannot show the direction or who handed off to whom.
    if (ev.redirect.chainHosts.length) {
      for (const hops of Object.values(redirects || {})) {
        if (!Array.isArray(hops) || hops.length < 2) continue;
        const hosts = hops.map((h) => hostOf(h?.url)).filter(Boolean);
        if (!hosts.some((h) => ev.redirect.chainHosts.includes(h))) continue;
        ev.redirect.chains.push(hops.map((h) => ({ host: hostOf(h?.url), status: h?.status })).slice(0, 6));
        if (ev.redirect.chains.length >= 3) break;
      }
    }
  }

  return { pageUrl, pageRegDomain, referenceEpochSec, cookies, warnings, inventoryCount: inventory.length,
    redirectChainHosts: [...redirectChainHosts], redirectHosts: [...redirectHosts] };
};
