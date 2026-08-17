// cookie-features.mjs — turn a fused CookieEvidence record (see cookie-evidence.mjs)
// into a deterministic, behavior-only feature vector. NO cookie-name heuristics
// influence any feature here — every field is derived from observed attributes,
// storage channels, reads, and network destinations.

// ---- registrable-domain (eTLD+1) — dependency-free public-suffix-lite --------
// Enough to decide first- vs third-party. Covers the common multi-label public
// suffixes; everything else falls back to the last two labels. Documented
// limitation: exotic suffixes (e.g. some *.gov.* or private suffixes like
// s3.amazonaws.com) may register one label too shallow — acceptable for party
// determination, which only needs same-vs-different site.
const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "co.nz", "net.nz", "org.nz", "govt.nz",
  "com.br", "net.br", "org.br", "gov.br",
  "co.in", "net.in", "org.in", "gen.in", "firm.in",
  "com.cn", "net.cn", "org.cn", "gov.cn",
  "co.za", "org.za", "net.za",
  "com.mx", "com.tr", "com.sg", "com.hk", "com.tw", "com.ar", "com.co",
  "co.kr", "or.kr", "co.il", "co.id", "com.my", "com.ph", "com.ua",
]);

export const hostOf = (urlOrHost) => {
  if (!urlOrHost) return null;
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(urlOrHost)) return new URL(urlOrHost).hostname || null;
  } catch { /* fall through to raw parse */ }
  // strip scheme-relative, path, port, leading dot
  let h = String(urlOrHost).replace(/^\/\//, "").replace(/[/?#].*$/, "").replace(/:\d+$/, "");
  h = h.replace(/^\./, "").toLowerCase();
  return h || null;
};

export const registrableDomain = (urlOrHost) => {
  const host = hostOf(urlOrHost);
  if (!host || host === "localhost") return host;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return host; // IPv4
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join(".");
  const last3 = parts.slice(-3).join(".");
  if (MULTI_PART_SUFFIXES.has(last2)) return last3;
  return last2;
};

// Same registrable domain (or a subdomain of the page's) => first party.
export const partyOf = (cookieOrUrlHost, pageRegDomain) => {
  const rd = registrableDomain(cookieOrUrlHost);
  if (!rd || !pageRegDomain) return "unknown";
  return rd === pageRegDomain ? "first" : "third";
};

// ---- value shape ------------------------------------------------------------
export const shannonEntropy = (s) => {
  if (!s) return 0;
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  const n = s.length;
  for (const c of freq.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 100) / 100; // bits per char
};

// Total entropy of the value in bits (per-char entropy x length). This is the
// right scale for "could this re-identify a user": a dotted-numeric ID like
// "1.1.918030885.1783130340" has LOW per-char entropy (2.9) but ~70 total bits —
// far more than enough to be unique. Judging by per-char alone wrongly treats
// numeric identifiers as non-identifying.
export const totalEntropyBits = (s) => Math.round(shannonEntropy(s) * (s ? s.length : 0));

// Does the value carry enough durable, unique-looking state to re-identify a
// visitor across requests/sessions? Requires (a) enough total entropy and (b) a
// long unbroken alphanumeric run (a random ID or timestamp segment), which
// distinguishes identifiers from short flags ("1", "true", "en-US") and from
// long-but-low-information values (repeated/enumerated text).
// Does the value decode to STRUCTURED DATA (a record) rather than an opaque token?
// Consent strings are the important case and are everywhere: `CMP` is base64 JSON
// (`{"option1":false,…}`), `OptanonConsent` is a `k=v&k=v` list. Both carry high
// entropy and would otherwise be scored as durable tracking identifiers, which is a
// systematic mislabel — a consent record is the opposite of a tracking ID.
// (It may still embed IDs; that's why this only blocks the identifier heuristic and
// is surfaced to the head rather than forcing a category.)
export const looksLikeStructuredData = (value) => {
  if (!value || value.length < 8) return false;
  const tryJson = (s) => {
    const t = s.trim();
    if (!/^[[{]/.test(t)) return false;
    try { const p = JSON.parse(t); return typeof p === "object" && p !== null; } catch { return false; }
  };
  if (tryJson(value)) return true;
  // base64 (possibly URL-encoded) wrapping JSON
  // A cookie value is arbitrary bytes chosen by a third party; a stray "%" makes
  // decodeURIComponent throw. Unguarded, that URIError propagated out of the worker and killed
  // the whole site's run (fidelity.co.uk: 53 cookies lost to one malformed value).
  const rawDecoded = (() => { try { return decodeURIComponent(value); } catch { return value; } })();
  const b64 = rawDecoded.replace(/-/g, "+").replace(/_/g, "/");
  if (/^[A-Za-z0-9+/]{8,}={0,2}$/.test(b64)) {
    try { if (tryJson(Buffer.from(b64, "base64").toString("utf8"))) return true; } catch { /* not base64 */ }
  }
  // a query-string-style record: 2+ `key=value` pairs joined by & (OptanonConsent, utag)
  const decoded = (() => { try { return decodeURIComponent(value); } catch { return value; } })();
  if (/^[\w.%[\]-]+=[^&]*(?:&[\w.%[\]-]+=[^&]*){1,}$/.test(decoded)) return true;
  return false;
};

export const looksLikeIdentifier = (value) => {
  if (!value || value.length < 8) return false;
  if (looksLikeStructuredData(value)) return false;
  // A hostname/URL value is configuration, not an identifier, however much entropy it
  // carries — e.g. Shopify's `_up_shop` = "nuphy-store.myshopify.com" (routing) and
  // Hotjar's `_hjTLDTest` = ".example.org" (cookie-scope probe). Both would otherwise
  // score as durable identifiers and be mislabelled as tracking.
  if (/^https?:\/\//i.test(value) || /^\.?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\.?$/i.test(value)) return false;
  const bits = totalEntropyBits(value);
  const longestRun = (value.match(/[A-Za-z0-9]{6,}/g) || []).reduce((m, r) => Math.max(m, r.length), 0);
  return bits >= 40 && longestRun >= 6;
};

// ---- days until expiry (persistence) ----------------------------------------
// CDP `expires` is a unix epoch (seconds); -1 / absent => session cookie.
// We can't read wall-clock deterministically, but the crawl embeds no "now", so
// approximate lifetime from the cookie's own createdAt if present, else report
// the raw absolute expiry and a coarse persistence bucket from max-age hints.
// Keep sub-day precision: rounding to whole days collapsed a 30-minute security
// token to "0", which is indistinguishable from a session cookie and misleads any
// downstream reader (a blinded reviewer flagged exactly this ambiguity).
export const expiryDays = (expires, referenceEpochSec) => {
  if (expires == null || expires < 0) return null; // session cookie
  const ref = referenceEpochSec ?? null;
  if (ref == null) return null;
  const days = (expires - ref) / 86400;
  return days >= 1 ? Math.round(days) : Math.round(days * 1000) / 1000;
};

// Human-readable lifetime bucket, so "short-lived" is never inferred from a
// rounded number. Session cookies are explicitly distinguished from sub-day ones.
export const lifetimeBucket = (session, days) => {
  if (session || days == null) return "session (cleared on browser close)";
  if (days < 1 / 24) return `${Math.round(days * 1440)} minutes`;
  if (days < 1) return `${Math.round(days * 24)} hours`;
  if (days <= 30) return `${Math.round(days)} days`;
  return `${Math.round(days)} days (long-lived)`;
};

// ============================================================================
// Feature extraction
// ============================================================================
export const extractFeatures = (ev, ctx) => {
  const pageRegDomain = ctx.pageRegDomain;
  const refEpoch = ctx.referenceEpochSec ?? null;

  const attrs = ev.attributes || {};
  const party = partyOf(ev.domain, pageRegDomain);

  // setter channels + parties
  const setterParties = new Set();
  const httpSetterHosts = new Set();
  for (const s of ev.set?.httpSetters || []) {
    if (s.host) httpSetterHosts.add(s.host);
    if (s.party) setterParties.add(s.party);
  }
  const jsWriteHosts = new Set();
  for (const w of ev.set?.jsWrites || []) {
    if (w.host) jsWriteHosts.add(w.host);
    if (w.party) setterParties.add(w.party);
  }
  const channels = new Set(ev.set?.channels || []);
  const setChannel = channels.size === 0 ? "unknown" : [...channels].sort().join("+");

  // transmission / exfiltration destinations, unioned across all three channels:
  // automatic `Cookie:` carriage, JS network sinks, and the value appearing inside a
  // URL query string / non-Cookie header (the header-scan channel — often the ONLY
  // place a cross-domain ad/measurement flow is visible).
  const httpSentHosts = new Set((ev.httpTransmission || []).map((t) => t.host).filter(Boolean));
  const jsExfilHosts = new Set((ev.jsExfil?.destinations || []).map((d) => d.host).filter(Boolean));
  const headerExfilHosts = new Set((ev.headerExfil?.destinations || []).map((d) => d.host).filter(Boolean));

  const thirdPartyDests = new Set();
  const firstPartyDests = new Set();
  const bucket = (host) => {
    const p = partyOf(host, pageRegDomain);
    if (p === "third") thirdPartyDests.add(registrableDomain(host));
    else if (p === "first") firstPartyDests.add(registrableDomain(host));
  };
  httpSentHosts.forEach(bucket);
  jsExfilHosts.forEach(bucket);
  headerExfilHosts.forEach(bucket);

  const value = ev.value ?? "";

  return {
    party,
    setChannel,
    setterParties: [...setterParties],
    // attributes
    httpOnly: !!attrs.httpOnly,
    secure: !!attrs.secure,
    sameSite: attrs.sameSite ?? null,
    session: !!attrs.session,
    partitioned: !!attrs.partitionKey,
    expires: attrs.expires ?? null,
    expiryDays: expiryDays(attrs.expires, refEpoch),
    lifetime: lifetimeBucket(attrs.session, expiryDays(attrs.expires, refEpoch)),
    persistent: !(attrs.session || attrs.expires == null || attrs.expires < 0),
    // value shape
    valueLength: value.length,
    valueEntropy: shannonEntropy(value),
    valueTotalEntropyBits: totalEntropyBits(value),
    looksLikeIdentifier: looksLikeIdentifier(value),
    // surfaced so the head knows the value is a record (e.g. a consent string), not a token
    looksLikeStructuredData: looksLikeStructuredData(value),
    // access
    readByJs: !!ev.reads?.readByJs,
    readerHosts: [...new Set((ev.reads?.readerScripts || []).map((r) => r.host).filter(Boolean))],
    // exfiltration
    httpSentToHosts: [...httpSentHosts],
    jsExfilFired: !!ev.jsExfil?.fired,
    jsExfilHosts: [...jsExfilHosts],
    // value observed inside a URL query string or a non-Cookie header
    headerLeak: (ev.headerExfil?.destinations || []).length > 0,
    headerLeakHosts: [...headerExfilHosts],
    headerLeakChannels: [...new Set((ev.headerExfil?.destinations || []).map((d) => d.channel))],
    headerLeakDetail: (ev.headerExfil?.destinations || []).map((d) => ({ host: d.host, party: d.party, header: d.header, channel: d.channel, matchType: d.matchType })),
    cookieHeaderRequests: ev.headerExfil?.cookieHeaderRequests || 0,
    firstPartyDestinations: [...firstPartyDests],
    thirdPartyDestinations: [...thirdPartyDests],
    crossSiteReach: thirdPartyDests.size,
    consumerMethods: ev.jsExfil?.consumerMethods || {},
    hasTransform: (ev.transforms || []).length > 0,
    transforms: ev.transforms || [],
  };
};
