// behaviour-subgraph.mjs — the cookie's behaviour as a name-free edge-list subgraph.
//
// This is Pass B's ENTIRE input. It replaces the flattened, truncated feature vector. It carries
// the actual edges the classifier should reason over — who wrote it, who read it, every request
// that carried it, the JS taint path (value → consumer → transform → network), the redirect/sync
// hops — deduped so identical edges collapse to a count, but never arbitrarily sliced.
//
// TWO HARD RULES, both because Pass B must judge behaviour cold and independently:
//   1. NO cookie name. Not the name, not a name field, nowhere.
//   2. NO literal cookie value. A value like "GA1.1.123…" is a vendor tell — it leaks identity
//      through the back door. Mutation is conveyed by COUNTS and FLAGS (distinctValues, mutated,
//      timestampAdvanced), never by the bytes. Script URLs are kept: they are structural graph
//      endpoints, not content, and resolving a destination host to a purpose is B's whole job.
//
// De-dup, don't truncate: transmissions collapse by (host, method, channel) with a count; distinct
// hosts/scripts/paths are all kept. A hard cap fires only in pathological cases and is disclosed as
// an explicit `_moreNotShown`, never a silent `.slice`.

const HARD_CAP = 60; // per list; only real trackers-gone-wild hit this, and it is disclosed

const capped = (arr) => {
  if (arr.length <= HARD_CAP) return arr;
  const kept = arr.slice(0, HARD_CAP);
  kept.push({ _moreNotShown: arr.length - HARD_CAP });
  return kept;
};

// A script's identity is origin + path. The query string is per-beacon noise (a `b.rnc?…` privacy
// beacon carries 3.6 KB of base64 per call), so leaving it in both bloats the payload AND defeats
// dedup — 37 calls of ONE script look like 37 distinct write sites. Strip it. Also keeps the input
// name-blind: a query string can embed identifying params.
const scriptId = (url) => {
  if (!url) return null;
  try { const u = new URL(url); return `${u.origin}${u.pathname}`; }
  catch { return String(url).split("?")[0].slice(0, 160); }
};

const dedupCount = (items, keyOf) => {
  const m = new Map();
  for (const it of items) {
    const k = keyOf(it);
    if (!m.has(k)) m.set(k, { ...it, count: 0 });
    m.get(k).count++;
  }
  return [...m.values()];
};

// classify a transmission's channel: the cookie rode an automatic Cookie: header (httpTransmission)
// vs a value the page's JS put into a request (jsExfil). The caller tags them before dedup.
export const buildBehaviourSubgraph = (ev, f = {}) => {
  // --- writes (who set it, by which channel) — distinct sites, no values -----
  const writeSites = dedupCount(
    (ev.set?.jsWrites || []).map((w) => ({ script: scriptId(w.scriptUrl), host: w.host, party: w.party, channel: w.source || "js" }))
      .concat((ev.set?.httpSetters || []).map((s) => ({ script: null, host: s.host, party: s.party, channel: "set-cookie-header" }))),
    (x) => `${x.host}|${x.channel}|${x.script || ""}`,
  );

  // --- reads (who read the jar) ----------------------------------------------
  const readers = dedupCount(
    (ev.reads?.readerScripts || []).map((r) => ({ script: scriptId(r.url), host: r.host, party: r.party })),
    (x) => `${x.host}|${x.script || ""}`,
  );

  // --- transmissions: the value leaving on requests, deduped -----------------
  const auto = (ev.httpTransmission || []).map((t) => ({ host: t.host, method: t.method || "GET", party: t.party, channel: "auto-cookie-header" }));
  const jsSent = (ev.jsExfil?.destinations || []).filter((d) => (d.round ?? 0) === 0)
    .map((d) => ({ host: d.host, method: d.method || "js", party: d.party, channel: "js-initiated" }));
  const transmissions = dedupCount([...auto, ...jsSent], (x) => `${x.host}|${x.method}|${x.channel}`);

  // --- taint paths: value → consumer script → transform round → destination --
  // This is the behavioural signature modern tracking hides behind: the value is read, transformed
  // by JS, and only then sent. round>0 means a transform happened before the send.
  const taintPaths = dedupCount(
    (ev.jsExfil?.destinations || []).filter((d) => (d.round ?? 0) > 0 || d.via)
      .map((d) => ({ consumerScriptHost: hostish(d.via), method: d.method, transformRound: d.round ?? 0, destinationHost: d.host, party: d.party })),
    (x) => `${x.consumerScriptHost}|${x.method}|${x.transformRound}|${x.destinationHost}`,
  );

  // --- redirect / sync hops ---------------------------------------------------
  const redirectChains = (ev.redirect?.chains || []).map((c) => c.map((h) => `${h.host}${h.status ? `(${h.status})` : ""}`).join(" -> "));

  return {
    // edges
    writeSites: capped(writeSites),
    readers: capped(readers),
    transmissions: capped(transmissions),
    taintPaths: capped(taintPaths),
    redirectChains: redirectChains.slice(0, HARD_CAP),
    bodyExfil: { count: ev.bodyExfil?.hits || 0, toHosts: (ev.bodyExfil?.destinations || []).map((d) => d.host).filter(Boolean), assessed: !!ev.bodyExfil?.assessed },
    bodyInfil: { count: ev.bodyInfil?.hits || 0, fromHosts: ev.bodyInfil?.sources || [], lowConfidence: !!ev.bodyInfil?.lowConfidence, assessed: !!ev.bodyInfil?.assessed },

    // derived behavioural flags (from the existing feature computation) — alongside the edges,
    // not instead of them. No name, no value.
    signals: {
      writeCount: f.writeCount ?? (ev.set?.jsWrites || []).length,
      distinctWriteValues: f.distinctWriteValues,
      valueMutated: f.valueMutated,
      refreshedWithSameValue: f.refreshedWithSameValue,
      embeddedTimestampAdvanced: f.embeddedTimestampAdvanced,
      setChannels: f.setChannels ?? [...(ev.set?.channels || [])],
      setterParties: f.setterParties,
      setterRedirected: f.setterRedirected,
      setterInRedirectChain: f.setterInRedirectChain,
      setterAlsoEndpointForOtherCookies: f.setterAlsoEndpointForOtherCookies,
      cookieHeaderRequests: f.cookieHeaderRequests,
      transformedThenSent: f.transformedThenSent,
      readerScriptCount: f.readerScriptCount,
      readerAttributionIsJarWide: true,
      writerSetMaxJaccard: f.writerSetMaxJaccard,
    },
    // non-identity attributes: shape, not content
    attributes: {
      party: f.party,
      persistent: f.persistent,
      httpOnly: f.httpOnly,
      secure: f.secure,
      sameSite: f.sameSite,
      valueLength: f.valueLength,
    },
  };
};

function hostish(url) {
  if (!url) return null;
  try { return new URL(url).hostname; } catch { return String(url).replace(/^https?:\/\//, "").split("/")[0].slice(0, 80); }
}
