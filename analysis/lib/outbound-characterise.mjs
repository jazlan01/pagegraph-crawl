// outbound-characterise.mjs — per-DESTINATION characterisation of what actually left the page.
//
// The evidence sources each answer a narrower question (body scan: "did a value appear in a
// request body", header scan: "in a URL/header", flow: "did tainted JS reach a network sink",
// cookie-network: "did the browser auto-attach it") and each keeps its own partial record. This
// module fuses them into one record per destination host that states, deterministically:
//
//   * WHAT FORM the value left in — `sentForm`: "raw" (verbatim), "re-encoded" (mechanically
//     transformed: base64/urlencoded/JSON-escaped), "fragment" (an identifier part travelled
//     without the rest of its cookie), "derived" (JS computed something from it before sending);
//   * whether the outbound bytes still CARRY AN IDENTIFIER — `carriesIdentifier` true/false/
//     "unknown", with the named part(s) that matched (`matchedParts`, e.g. consentId = UUID);
//   * the actual request bytes around the match (`excerpt`) with highlight offsets
//     (`matchRanges`, computed on the excerpt string itself, never haystack arithmetic).
//
// This is the record that grounds a purpose claim: "consent state propagated to the CMP" and
// "persistent identifier delivered to an analytics ingest endpoint" are different findings, and
// before this module both collapsed into one boolean.
//
// STRICTLY DETERMINISTIC. Part decomposition and identifier grading come from value-parts.mjs;
// no LLM is involved anywhere here.

import { namedParts, identifierNeedles } from "./value-parts.mjs";
import { partyOf } from "./cookie-features.mjs";

const EXCERPT_MAX = 500;
const RECORD_CAP = 40;

// Source precedence for the merged per-host record: the source that saw the most complete
// evidence wins the characterisation fields; every source still contributes its channel.
const RANK = { "body-full": 4, "body-part": 3, header: 2, js: 1, auto: 0 };

const originPath = (u) => {
  if (!u) return null;
  try { const x = new URL(u); return x.origin + x.pathname; } catch { return String(u).slice(0, 200); }
};

// Bound the excerpt and keep every range that survives the cut.
const boundExcerpt = (excerpt, ranges) => {
  if (excerpt == null) return { excerpt: null, matchRanges: [] };
  const ex = String(excerpt).slice(0, EXCERPT_MAX);
  const kept = (ranges || [])
    .filter(([s]) => s >= 0 && s < ex.length)
    .map(([s, e]) => [s, Math.min(e, ex.length)]);
  return { excerpt: ex, matchRanges: kept };
};

// Locate any of a part's plausible encoded forms inside an excerpt. A UUID survives
// encodeURIComponent unchanged, but a part containing `+`/`:`/space does not — so search the
// variants, not just the raw text.
const partForms = (text) => {
  const forms = new Set([text]);
  try { forms.add(encodeURIComponent(text)); } catch { /* unencodable */ }
  try { const d = decodeURIComponent(text); if (d !== text) forms.add(d); } catch { /* not encoded */ }
  return [...forms];
};
const findRanges = (excerpt, parts) => {
  const ranges = [];
  const matched = [];
  if (!excerpt) return { ranges, matched };
  for (const p of parts) {
    for (const form of partForms(p.text)) {
      const i = excerpt.indexOf(form);
      if (i === -1) continue;
      ranges.push([i, i + form.length]);
      matched.push(p);
      break;
    }
  }
  return { ranges, matched };
};

const partSummary = (p) => ({ key: p.key, kind: p.kind, isIdentifier: !!p.isIdentifier });

// carriesIdentifier for a FULL value that left: true when an identifier-grade part is inside it;
// "unknown" when the value is long enough to hide one but decomposes to nothing identifier-grade
// (an opaque bot-defence blob — we cannot rule an identifier out); false for short plain values.
const wholeValueCarries = (parts, value) => {
  if (parts.some((p) => p.isIdentifier)) return true;
  return (value || "").length >= 16 ? "unknown" : false;
};

/**
 * Build ev.outbound[] for one cookie.
 *
 * @param name             cookie name
 * @param value            current jar value
 * @param pageRegDomain    for party tagging (candidates already carry party; kept for callers)
 * @param bodyFindings     raw cookie-exfiltration findings for this cookie (request kind only is used)
 * @param headerDestinations  ev.headerExfil.destinations (matchType, snippet, channel url|other-header)
 * @param jsDestinations   ev.jsExfil.destinations (round, argSnippet, matchedValue after cookie-evidence keeps them)
 * @param httpTransmission ev.httpTransmission (auto Cookie: header carriage)
 * @param sharedIndex      Map<identifierPartText, Set<cookieName>> across the whole jar, for disclosure
 */
export const characteriseOutbound = ({
  name,
  value,
  pageRegDomain = null,
  bodyFindings = [],
  headerDestinations = [],
  jsDestinations = [],
  httpTransmission = [],
  sharedIndex = null,
}) => {
  const currentParts = namedParts(name, value);
  const currentNeedles = identifierNeedles(currentParts);
  const candidates = [];

  // ---- request bodies (cookie-exfiltration findings) ------------------------
  for (const f of bodyFindings) {
    if (f.kind !== "request") continue;
    const host = hostFrom(f.url);
    if (!host) continue;
    const scope = f.matchScope === "part" ? "part" : "full";
    if (scope === "full") {
      // Decompose the MATCHED value (which may be an earlier snapshot): if the whole snapshot
      // left, every part of it left — no need to re-scan the body per part.
      const sentParts = namedParts(name, f.value);
      const idParts = sentParts.filter((p) => p.isIdentifier);
      const off = typeof f.matchOffset === "number" && f.matchOffset >= 0 ? f.matchOffset : -1;
      const len = (f.matchedText || "").length;
      candidates.push({
        source: "body-full",
        host,
        url: originPath(f.url),
        channel: "js-body",
        sentForm: f.encoding === "raw" ? "raw" : "re-encoded",
        encoding: f.encoding || null,
        valueSnapshot: f.value === value ? "current" : "earlier",
        carriesIdentifier: wholeValueCarries(sentParts, f.value),
        identifierKinds: [...new Set(idParts.map((p) => p.kind))],
        matchedParts: sentParts.map(partSummary),
        coverage: "full-value",
        ...boundExcerpt(f.snippet, off >= 0 && len ? [[off, off + len]] : []),
      });
    } else {
      const off = typeof f.matchOffset === "number" && f.matchOffset >= 0 ? f.matchOffset : -1;
      const len = (f.matchedText || "").length;
      const mp = f.matchedPart || { key: "value", kind: "identifier" };
      candidates.push({
        source: "body-part",
        host,
        url: originPath(f.url),
        channel: "js-body",
        sentForm: "fragment",
        encoding: f.encoding || null,
        // A part hit says nothing about which snapshot the rest of the value was in.
        valueSnapshot: null,
        // Part needles are identifier-grade by construction (identifierNeedles).
        carriesIdentifier: true,
        identifierKinds: [mp.kind],
        matchedParts: [{ key: mp.key, kind: mp.kind, isIdentifier: true }],
        coverage: "identifier-only",
        ...boundExcerpt(f.snippet, off >= 0 && len ? [[off, off + len]] : []),
      });
    }
  }

  // ---- URLs / non-Cookie headers (cookie-headers destinations) --------------
  for (const h of headerDestinations) {
    if (!h.host) continue;
    if (h.matchType === "fragment") {
      // A prefix-stripped identifier fragment. Enrich deterministically: does the snippet
      // contain one of THIS value's identifier parts? If so we can name what travelled.
      const { ranges, matched } = findRanges(h.snippet || "", currentNeedles);
      candidates.push({
        source: "header",
        host: h.host,
        url: originPath(h.url),
        channel: "js-url",
        sentForm: "fragment",
        encoding: null,
        valueSnapshot: null,
        carriesIdentifier: matched.length ? true : "unknown",
        identifierKinds: [...new Set(matched.map((p) => p.kind))],
        matchedParts: matched.map(partSummary),
        coverage: matched.length ? "identifier-only" : "non-identifier-parts",
        ...boundExcerpt(h.snippet, ranges),
      });
    } else {
      const { ranges } = findRanges(h.snippet || "", [{ text: value, key: "value", kind: "value" }]);
      const idParts = currentParts.filter((p) => p.isIdentifier);
      candidates.push({
        source: "header",
        host: h.host,
        url: originPath(h.url),
        channel: "js-url",
        sentForm: "raw",
        encoding: null,
        valueSnapshot: "current",
        carriesIdentifier: wholeValueCarries(currentParts, value),
        identifierKinds: [...new Set(idParts.map((p) => p.kind))],
        matchedParts: currentParts.map(partSummary),
        coverage: "full-value",
        ...boundExcerpt(h.snippet, ranges),
      });
    }
  }

  // ---- JS network sinks (cookie-reads consumers + cookie-flow netHits) ------
  for (const d of jsDestinations) {
    if (!d.host) continue;
    const round = d.round ?? 0;
    const matchedValue = d.matchedValue ?? null;
    // What do we know about the bytes that went? Round 0: the stored value itself (matchedValue
    // when the flow path kept it, else the raw value the reads path matched). Round > 0: a
    // derived seed — check whether the ORIGINAL value's identifier parts survived into it.
    const sentBytes = matchedValue ?? (round === 0 ? value : null);
    let carries, kinds, mparts, coverage;
    if (round > 0) {
      const inDerived = sentBytes
        ? currentNeedles.filter((p) => partForms(p.text).some((f) => sentBytes.includes(f)))
        : [];
      carries = inDerived.length ? true : "unknown";
      kinds = [...new Set(inDerived.map((p) => p.kind))];
      mparts = inDerived.map(partSummary);
      coverage = inDerived.length ? "identifier-only" : "non-identifier-parts";
    } else {
      const sentParts = namedParts(name, sentBytes ?? value);
      carries = wholeValueCarries(sentParts, sentBytes ?? value);
      kinds = [...new Set(sentParts.filter((p) => p.isIdentifier).map((p) => p.kind))];
      mparts = sentParts.map(partSummary);
      coverage = "full-value";
    }
    const { ranges } = findRanges(
      d.argSnippet || "",
      sentBytes ? [{ text: sentBytes, key: "value", kind: "value" }, ...currentNeedles] : currentNeedles,
    );
    candidates.push({
      source: "js",
      host: d.host,
      url: originPath(d.url),
      channel: "js-body",
      sentForm: round > 0 ? "derived" : "raw",
      encoding: null,
      valueSnapshot: round > 0 ? null : (sentBytes != null ? (sentBytes === value ? "current" : "earlier") : "current"),
      carriesIdentifier: carries,
      identifierKinds: kinds,
      matchedParts: mparts,
      coverage,
      ...boundExcerpt(d.argSnippet ?? null, ranges),
    });
  }

  // ---- automatic Cookie: header carriage -------------------------------------
  for (const t of httpTransmission) {
    if (!t.host) continue;
    const idParts = currentParts.filter((p) => p.isIdentifier);
    candidates.push({
      source: "auto",
      host: t.host,
      url: originPath(t.url),
      channel: "auto-cookie-header",
      sentForm: "raw", // the browser attaches the whole cookie by definition
      encoding: null,
      valueSnapshot: "current",
      carriesIdentifier: wholeValueCarries(currentParts, value),
      identifierKinds: [...new Set(idParts.map((p) => p.kind))],
      matchedParts: currentParts.map(partSummary),
      coverage: "full-value",
      excerpt: null, // no header bytes captured for this channel (v1)
      matchRanges: [],
    });
  }

  // ---- merge per destination host --------------------------------------------
  // The display fields (excerpt, ranges, sentForm) come from the single strongest candidate;
  // `carriesIdentifier` aggregates across ALL candidates for the host — a cookie written 15
  // times produces snapshots with and without its identifier, and if ANY identifier-bearing
  // snapshot reached the host, the host received the identifier. The strongest candidate is
  // also biased toward one whose excerpt SHOWS the identifier, since that is the evidence
  // the record exists to display.
  const score = (c) =>
    RANK[c.source] * 100 +
    (c.carriesIdentifier === true ? 10 : 0) +
    (c.excerpt ? 5 : 0) +
    Math.min((c.matchRanges || []).length, 4);
  const byHost = new Map();
  for (const c of candidates) {
    const cur = byHost.get(c.host);
    if (!cur) { byHost.set(c.host, { best: c, all: [c], channels: new Set([c.channel]) }); continue; }
    cur.channels.add(c.channel);
    cur.all.push(c);
    if (score(c) > score(cur.best)) cur.best = c;
  }

  const out = [];
  for (const [host, { best, all, channels }] of byHost) {
    // Aggregate the identifier claim across every candidate for this host.
    const carriesIdentifier = all.some((c) => c.carriesIdentifier === true) ? true
      : all.some((c) => c.carriesIdentifier === "unknown") ? "unknown" : false;
    const identifierKinds = [...new Set(all.flatMap((c) => c.carriesIdentifier === true ? c.identifierKinds : []))];
    // best's parts, plus any identifier part another candidate proved left to this host.
    const matchedParts = [...(best.matchedParts || [])];
    const seenKeys = new Set(matchedParts.map((p) => p.key));
    for (const c of all) {
      if (c.carriesIdentifier !== true) continue;
      for (const p of c.matchedParts || []) {
        if (p.isIdentifier && !seenKeys.has(p.key)) { matchedParts.push(p); seenKeys.add(p.key); }
      }
    }
    // Disclosure: other cookies in the jar holding the same identifier part — a shared UUID
    // attributes one body hit to every cookie storing it, deliberately, and this names them.
    const shared = new Set();
    if (sharedIndex) {
      for (const p of matchedParts) {
        if (!p.isIdentifier) continue;
        const owner = currentParts.find((x) => x.key === p.key);
        const names = owner && sharedIndex.get(owner.text);
        if (names) for (const n of names) if (n !== name) shared.add(n);
      }
      // full-value replication too
      const names = sharedIndex.get(value);
      if (names) for (const n of names) if (n !== name) shared.add(n);
    }
    const { source, channel, ...rest } = best;
    out.push({
      host,
      party: partyOf(host, pageRegDomain),
      ...rest,
      carriesIdentifier,
      identifierKinds,
      matchedParts,
      channels: [...channels],
      sharedWithCookies: [...shared].slice(0, 8),
    });
    if (out.length >= RECORD_CAP) break;
  }
  return out;
};

function hostFrom(u) {
  if (!u) return null;
  try { return new URL(u).hostname; } catch { return null; }
}
