// graph-features.mjs — the research feature vector, name-free.
//
// Replaces a hand-written rule set tuned on eight sites with the feature basis the literature
// validated at scale (CookieGraph / CookieBlock), modernised in two ways that matter for how
// tracking works now:
//
//   1. TRANSFORM-AWARE EXFILTRATION. Cookies are rarely transmitted verbatim any more: JS reads
//      the value, transforms it, and sends the result. CookieGraph matches raw values plus a
//      static Base64/MD5/SHA-1/SHA-256 list, which sees none of that. Measured here: of 58
//      identifier-length cookies on directv, 43 matched in NO form at all, and encoded matching
//      added exactly zero over raw+urlencoded. `cookie-flow.mjs` propagates taint across
//      `js call` → `js result`, so it follows the value THROUGH the transform. That is the
//      replacement for encoding-matching, not a supplement to it.
//   2. CONSENT STATE. TCF/GPP/GPC did not exist in CookieGraph's framing and are now the
//      compliance question.
//
// NO COOKIE NAMES. Not as a feature, not as a regex, not as a family hint. Names are trivially
// renamed to evade, and every name-shaped rule we have written has eventually been wrong. Cookie
// identity still exists in the report, but as a described attribute tagged "name lookup" — never
// as an input here.
//
// Two caveats travel WITH the vector rather than in a comment, because a consumer that does not
// know them will over-read the numbers:
//   * `readerScriptCount` is JAR-WIDE. `document.cookie` returns everything, so one read credits
//     every cookie present. It measures how long a cookie existed at least as much as who wanted
//     it. Shipped as a ratio and flagged.
//   * `bodyInfil` on a short or low-entropy value collides with the page's own markup.

import { confidenceRank } from "./tcf-taxonomy.mjs";
import { buildSetterGraph } from "./setter-graph.mjs";

// CookieGraph considers only values of at least 8 characters — the identifier focus. Shorter
// values are kept in the output but marked, so the exclusion is visible rather than silent.
const MIN_IDENTIFIER_LEN = 8;

const distinct = (xs) => new Set(xs.filter((x) => x != null)).size;

// Does the value's own embedded timestamp advance across writes? GA4's session cookie carries
// `t<epoch>`; it advancing is the difference between "state is being maintained" and "the cookie
// was re-set with the same content". Deterministic, and no name is involved.
// NOT \b-anchored. GA4 packs its clock as `t1785669813` inside `GS2.1.s…$o1$g1$t…`; a word
// boundary cannot match between `t` and `1` because both are word characters, so a \b regex
// finds nothing in exactly the cookie this feature exists for. Anchor on "not a digit" instead.
const embeddedTimestamps = (v) =>
  [...String(v || "").matchAll(/(?<!\d)(\d{10}|\d{13})(?!\d)/g)].map((m) => Number(m[1]));

const timestampAdvanced = (values) => {
  let prevMax = null;
  for (const v of values) {
    const ts = embeddedTimestamps(v);
    if (!ts.length) continue;
    const max = Math.max(...ts);
    if (prevMax !== null && max > prevMax) return true;
    prevMax = prevMax === null ? max : Math.max(prevMax, max);
  }
  return false;
};

/**
 * Build the feature vector for every cookie in one pass over already-fused evidence.
 * `evidence` is the object returned by buildEvidence().
 */
export const buildGraphFeatures = (evidence) => {
  const { cookies, pageRegDomain } = evidence;
  const sg = buildSetterGraph(cookies, pageRegDomain);
  const out = new Map();

  for (const [name, ev] of cookies) {
    const writes = ev.set?.jsWrites || [];
    const writeValues = writes.map((w) => w.value).filter((v) => v != null);
    const httpSets = ev.set?.httpSetters || [];
    const channels = [...(ev.set?.channels || [])];

    const setterEndpoint = sg.setterAlsoEndpoint(name);
    const promiscuity = sg.writerPromiscuity(name);
    const overlap = sg.writerSetOverlap(name);

    const readerCount = (ev.reads?.readerScripts || []).length;

    out.set(name, {
      // ---- construction rules ------------------------------------------------
      // Identifier-length gate. Reported, never silently applied.
      valueLength: (ev.value || "").length,
      meetsIdentifierLength: (ev.value || "").length >= MIN_IDENTIFIER_LEN,

      // ---- flow: how much did this cookie DO --------------------------------
      writeCount: writes.length,
      deleteCount: (ev.deletes || []).length,
      distinctWriteSites: distinct(writes.map((w) => `${w.scriptUrl}#${w.offset}`)),
      httpSetCount: httpSets.length,

      // Mutation vs refresh. The hardest-mutating cookies on a page are usually WAF tokens, so
      // this is necessary but never sufficient — it is the write CHANNEL below that separates a
      // session-state cookie from a rotating challenge token.
      distinctWriteValues: distinct(writeValues),
      valueMutated: distinct(writeValues) > 1,
      refreshedWithSameValue: writeValues.length > 1 && distinct(writeValues) === 1,
      embeddedTimestampAdvanced: timestampAdvanced(writeValues),

      // ---- flow: where did the value GO -------------------------------------
      cookieHeaderRequests: ev.headerExfil?.cookieHeaderRequests ?? 0,
      urlParamExfil: ev.headerExfil?.urlHits ?? 0,
      requestHeaderExfil: ev.headerExfil?.otherHeaderHits ?? 0,
      bodyExfil: ev.bodyExfil?.hits ?? 0,
      bodyExfilAssessed: !!ev.bodyExfil?.assessed,

      // WHICH hosts received it. Domains are not content features — the papers exclude cookie
      // NAMES (trivially renamed); CookieGraph's own features are explicitly about setter and
      // endpoint DOMAINS. Omitting them was a mistake: it left the head reading "2 body
      // transmissions" with no way to know they went to facebook.com, so it downgraded a Meta
      // advertising cookie to Analytics. Resolving a destination host to a vendor purpose is the
      // one judgement the deterministic layer cannot make and the head exists for.
      exfilDestinations: [...new Set([
        ...(ev.httpTransmission || []).map((x) => x.host),
        ...(ev.jsExfil?.destinations || []).map((x) => x.host),
        ...(ev.headerExfil?.destinations || []).map((x) => x.host),
        ...(ev.bodyExfil?.destinations || []).map((x) => x.host),
      ].filter(Boolean))].slice(0, 12),
      thirdPartyExfilDestinations: [...new Set([
        ...(ev.jsExfil?.destinations || []).filter((x) => x.party === "third").map((x) => x.host),
        ...(ev.headerExfil?.destinations || []).filter((x) => x.party === "third").map((x) => x.host),
        ...(ev.bodyExfil?.destinations || []).filter((x) => x.party === "third").map((x) => x.host),
        ...(ev.httpTransmission || []).filter((x) => x.party === "third").map((x) => x.host),
      ].filter(Boolean))].slice(0, 12),
      setterHosts: [...new Set([
        ...(ev.set?.httpSetters || []).map((s) => s.host),
        ...(ev.set?.jsWrites || []).map((w) => w.host),
      ].filter(Boolean))].slice(0, 8),
      infilSourceHosts: (ev.bodyInfil?.sources || []).slice(0, 6),
      // WHICH script set it, by URL. The host says "googletagmanager.com"; the URL says
      // "/gtag/js?id=G-…" — the difference between knowing a vendor and knowing the product.
      // Origin + path only. A GA collect URL carries ~1.8 KB of beacon parameters that identify
      // nothing and would dominate any payload this vector is sent in; the PATH is what names the
      // product ("/gtag/js", "/ruxitagentjs…"). The tag id is kept because it is the one query
      // parameter with identifying value.
      settingScripts: [...new Set((ev.set?.jsWrites || []).map((w) => {
        if (!w.scriptUrl) return null;
        try {
          const u = new URL(w.scriptUrl);
          const id = u.searchParams.get("id") || u.searchParams.get("tid");
          return `${u.origin}${u.pathname}${id ? `?id=${id}` : ""}`;
        } catch { return String(w.scriptUrl).split("?")[0].slice(0, 160); }
      }).filter(Boolean))].slice(0, 6),
      // The redirect hop sequence, in order, for chains this cookie's setter took part in.
      redirectChain: (ev.redirect?.chains || []).map((c) => c.map((h) => `${h.host}${h.status ? `(${h.status})` : ""}`).join(" -> ")),

      // DEPRECATED (misnomer — means js-initiated send). `transformedThenSent` derives from
      // jsExfil.fired, which is true for ANY js-initiated send, raw value included; no transform
      // is implied or checked. Kept computing so old outputs keep their meaning; new consumers
      // read `jsInitiatedSend` / `derivedValueSent` and the per-destination
      // `outboundTransmissions` below, which state what actually left.
      transformedThenSent: !!ev.jsExfil?.fired,
      transformedThenSentCount: (ev.jsExfil?.destinations || []).length,
      transformCount: (ev.transforms || []).length,
      // What transformedThenSent actually meant all along:
      jsInitiatedSend: !!ev.jsExfil?.fired,
      // A genuinely derived value (taint round > 0) reached the network.
      derivedValueSent: (ev.outbound || []).some((o) => o.sentForm === "derived"),

      // Per-destination outbound characterisation — ENUMS ONLY. No excerpts and no part KEYS:
      // a key like "consentId" is a OneTrust tell, and this vector feeds the name-blind Pass B.
      // Kinds like "UUID" are shape, not identity. The full records (with request bytes) live
      // in ev.outbound, persisted separately for Pass C and the report.
      outboundTransmissions: (ev.outbound || []).slice(0, 20).map((o) => ({
        host: o.host,
        party: o.party,
        channels: o.channels,
        sentForm: o.sentForm,
        carriesIdentifier: o.carriesIdentifier,
        identifierKinds: o.identifierKinds,
        coverage: o.coverage,
        valueSnapshot: o.valueSnapshot,
      })),

      // ---- flow: where did the value COME FROM ------------------------------
      // Infiltration — arrived in a response, then was stored. A server-minted id or a
      // bot-defence challenge token rather than something the page computed.
      bodyInfil: ev.bodyInfil?.hits ?? 0,
      bodyInfilLowConfidence: !!ev.bodyInfil?.lowConfidence,

      // ---- setter features --------------------------------------------------
      setChannels: channels,
      setByHttpOnly: channels.length === 1 && channels[0] === "http",
      setByJs: channels.includes("js"),
      setterParties: [...new Set([
        ...httpSets.map((s) => s.party),
        ...writes.map((w) => w.party),
      ].filter(Boolean))],
      setterInRedirectChain: !!ev.redirect?.setterInChain,
      setterRedirected: !!ev.redirect?.setterRedirected,
      // The paper's cluster signal: a domain that plants this cookie AND collects others.
      setterAlsoEndpointForOtherCookies: setterEndpoint.otherCookieCount,

      // ---- structural -------------------------------------------------------
      writerCount: promiscuity.writerCount,
      maxCookiesPerWriter: promiscuity.maxCookiesPerWriter,
      meanCookiesPerWriter: promiscuity.meanCookiesPerWriter,
      writerSetMaxJaccard: overlap.maxJaccard,
      sharesWritersWith: overlap.sharesWritersWith,

      // Jar-wide. Ratio, not raw count, and flagged so a consumer cannot mistake it for
      // per-cookie read interest.
      readerScriptCount: readerCount,
      readerShareOfPage: sg.pageReaderCount
        ? +(readerCount / sg.pageReaderCount).toFixed(2)
        : 0,
      readerAttributionIsJarWide: true,

      // ---- attributes (not content, not name) -------------------------------
      persistent: !!ev.attributes?.expires && ev.attributes.expires > 0,
      httpOnly: !!ev.attributes?.httpOnly,
      secure: !!ev.attributes?.secure,
      sameSite: ev.attributes?.sameSite ?? null,
      party: pageRegDomain && ev.domain
        ? (ev.domain.replace(/^\./, "").endsWith(pageRegDomain) ? "first" : "third")
        : null,
    });
  }
  return out;
};

export { MIN_IDENTIFIER_LEN };
