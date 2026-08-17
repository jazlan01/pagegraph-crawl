// tcf-rules.mjs — Stage 3: a deterministic, behavior-only prior over the three
// axes. Fully reproducible and auditable (no model, no network, no name lookup):
// every emitted label is backed by an observed-behavior `signal` string.
//
// Deliberate scope limit: with NO vendor knowledge base, the rules cannot cleanly
// split advertising vs. analytics vs. content-personalisation once a value is
// seen leaving to a third party. They therefore emit the safe measurement lower
// bound + BOTH ad/analytics candidates at moderate probability and set
// `flags.needsHostKnowledge`, leaving the destination-host → purpose resolution
// to the LLM head (Stage 4). In --rules-only mode this prior IS the verdict.

import { iabLabel, mkLabel, confidenceRank } from "./tcf-taxonomy.mjs";

const ICC = { NEC: "Necessary", FUNC: "Functional", ANALYTICS: "Analytics", ADV: "Advertising" };
const US = {
  SALE: "Sale of Personal Information",
  SHARE: "Sharing for Cross-Context Behavioral Advertising",
  TARGET: "Targeted Advertising",
  PERF: "Analytics / Performance",
  NEC: "Strictly Necessary / Exempt",
};

// merge duplicate labels: keep the strongest confidence, first reasoning wins;
// then sort strongest-first.
const mergeAxis = (labels) => {
  const by = new Map();
  for (const l of labels) {
    const prev = by.get(l.label);
    if (!prev || confidenceRank(l.confidence) > confidenceRank(prev.confidence)) {
      by.set(l.label, { ...l, reasoning: prev?.reasoning || l.reasoning });
    }
  }
  return [...by.values()].sort((a, b) => confidenceRank(b.confidence) - confidenceRank(a.confidence));
};

export const rulePrior = (f, ev) => {
  const iab = [];
  const icc = [];
  const us = [];
  const signals = [];

  // ---- 1. Definitional: anything stored exercises Purpose 1 -----------------
  iab.push(mkLabel(iabLabel("P1"), 0.98, "cookie is stored on and later accessible from the device"));
  signals.push("Stored on device → Purpose 1 (definitional).");

  // ---- USED: was the stored value actually exercised? -----------------------
  // Party-AGNOSTIC by design. A cookie's purpose is determined by whether it is
  // set and then USED — read back by script, carried on requests, or consumed by
  // a JS sink. Whether the recipient is a different registrable domain is NOT a
  // precondition: modern server-side / CNAME-cloaked tagging keeps every flow
  // first-party while doing exactly the same processing. Party is retained only
  // on the US-state axis, where "cross-context" is legally load-bearing.
  const transmitted = (ev.httpTransmission || []).length > 0 || f.cookieHeaderRequests > 0;
  const consumedByJs = Object.keys(f.consumerMethods || {}).length > 0 || f.jsExfilFired;
  const used = f.readByJs || transmitted || consumedByJs || f.headerLeak;
  const usageChannels = [
    f.readByJs ? `read by script (${f.readerHosts.length || "?"} reader host(s))` : null,
    transmitted ? `carried on ${(ev.httpTransmission || []).length || f.cookieHeaderRequests} request(s)` : null,
    consumedByJs ? "value passed to a JS sink" : null,
    f.headerLeak ? `value copied into ${f.headerLeakChannels.join("/")} sent to ${f.headerLeakHosts.join(", ")}` : null,
  ].filter(Boolean);
  if (used) signals.push(`Used after being set: ${usageChannels.join("; ")}.`);
  else signals.push("Set but no read/transmission/consumption observed in this crawl.");

  // ---- 2. Strictly-necessary / security shape -------------------------------
  // Server-only + unread by script + short-lived. Transmission does NOT disqualify
  // (a session/security token is supposed to ride requests); persistence does.
  const shortLived = f.session || (f.expiryDays != null && f.expiryDays <= 1);
  const necessaryShape = f.httpOnly && !f.readByJs && !consumedByJs && shortLived;
  if (necessaryShape) {
    icc.push(mkLabel(ICC.NEC, 0.8, "httpOnly, never read by script, short-lived — session/security token"));
    iab.push(mkLabel(iabLabel("SP1"), 0.6, "server-managed token inaccessible to scripts — security/session shape"));
    us.push(mkLabel(US.NEC, 0.7, "server-only short-lived token, not a profiling identifier"));
    signals.push("httpOnly + unread by script + short-lived → strictly-necessary/security shape.");
  }

  // ---- 3. Persistent identifier actively used → tracking identifier ---------
  // The core behavioral test, independent of party.
  const activeIdentifier = f.looksLikeIdentifier && f.persistent && !shortLived && !necessaryShape && used;
  if (activeIdentifier) {
    icc.push(mkLabel(ICC.ANALYTICS, 0.6, "persistent high-entropy identifier actively used after being set"));
    iab.push(mkLabel(iabLabel("P8"), 0.5, "stable identifier measures usage across requests/sessions"));
    iab.push(mkLabel(iabLabel("P9"), 0.45, "persistent identifier supports audience statistics"));
    icc.push(mkLabel(ICC.ADV, 0.4, "persistent identifier is also ad-capable; needs vendor knowledge to split"));
    iab.push(mkLabel(iabLabel("P7"), 0.35, "persistent identifier can attribute ad performance"));
    us.push(mkLabel(US.PERF, 0.55, "persistent identifier used for measurement"));
    signals.push(
      `Persistent identifier (${f.valueEntropy} bits/char, ${f.expiryDays ?? "?"}d) actively used → tracking identifier. ` +
        "Party is irrelevant to this determination." +
        (f.headerLeak ? "" : " Ad-vs-analytics not resolvable from these flows; needs vendor knowledge."),
    );
  }

  // ---- 4. Profiling capability: long-lived, high-entropy, re-readable -------
  const profilingShape = activeIdentifier && (f.expiryDays == null || f.expiryDays >= 30);
  if (profilingShape) {
    iab.push(mkLabel(iabLabel("P3"), 0.4, "long-lived stable identifier enables profile building"));
    iab.push(mkLabel(iabLabel("P4"), 0.35, "stable identifier usable to select personalised advertising"));
    iab.push(mkLabel(iabLabel("P2"), 0.35, "identifier usable for basic ad selection"));
    us.push(mkLabel(US.TARGET, 0.45, "long-lived identifier enabling targeted advertising"));
    signals.push(`Long-lived (${f.expiryDays ?? "session-less"}d) reusable identifier → profiling-capable.`);
  }

  // ---- 5. Functional: used by script but not a durable identifier -----------
  if (used && !activeIdentifier && !necessaryShape) {
    icc.push(mkLabel(ICC.FUNC, 0.5, "value used by the page but not a persistent high-entropy identifier"));
    iab.push(mkLabel(iabLabel("P10"), 0.4, "used to operate/improve the service"));
    signals.push("Used, but value shape is not a durable identifier → functional/service use.");
  }

  // ---- 4b. Value deliberately COPIED into a URL/header --------------------------
  // The strongest exfiltration evidence available: automatic `Cookie:` carriage is
  // passive browser behavior, but a value re-encoded into a query string or a custom
  // header means a script deliberately harvested and shipped the identifier. When the
  // recipient is another registrable domain this is unambiguous cross-domain tracking.
  if (f.headerLeak) {
    const leakHosts = f.headerLeakDetail;
    const toThird = leakHosts.filter((d) => d.party === "third");
    signals.push(
      `Value deliberately copied into ${f.headerLeakChannels.join("/")} and sent to: ` +
        `${leakHosts.map((d) => `${d.host}(${d.party}${d.matchType === "fragment" ? ", prefix-stripped" : ""})`).join(", ")}.`,
    );
    // The harvesting act itself is the tracking behaviour. A script that lifts a
    // stored identifier out of the jar and re-encodes it into an outbound request is
    // doing the same thing whether the collector is adtech.example.com or
    // data.first-party.com — server-side and CNAME-cloaked endpoints exist precisely
    // to make that distinction invisible. Destination party therefore does NOT gate
    // the TCF or ICC labels; it modulates only the US-state labels below, where
    // "cross-context" is defined across businesses as a matter of statute.
    const host0 = leakHosts[0]?.host || "a collection endpoint";
    iab.push(mkLabel(iabLabel("P9"), 0.6, "identifier actively harvested and shipped to a collection endpoint"));
    iab.push(mkLabel(iabLabel("P7"), 0.6, `identifier re-encoded into a request to ${host0}`));
    iab.push(mkLabel(iabLabel("P3"), 0.5, "harvested persistent identifier enables profile building"));
    iab.push(mkLabel(iabLabel("P4"), 0.45, "harvested identifier usable to select personalised ads"));
    iab.push(mkLabel(iabLabel("P2"), 0.45, "harvested identifier usable for ad selection"));
    icc.push(mkLabel(ICC.ADV, 0.7, `script harvested the identifier into a request to ${host0}`));
    icc.push(mkLabel(ICC.ANALYTICS, 0.65, "identifier shipped to a collection endpoint"));
    if (toThird.length > 0) {
      // party is legally load-bearing here, and only here
      us.push(mkLabel(US.SHARE, 0.7, `identifier disclosed cross-context to ${toThird.map((d) => d.host).join(", ")}`));
      us.push(mkLabel(US.TARGET, 0.6, "cross-domain identifier enabling targeted advertising"));
      us.push(mkLabel(US.SALE, 0.5, "identifier disclosed to a separate business for commercial benefit"));
    } else {
      us.push(mkLabel(US.TARGET, 0.5, "harvested persistent identifier enabling targeted advertising"));
      us.push(mkLabel(US.PERF, 0.6, "identifier actively transmitted for measurement"));
    }
  }

  // ---- 6. US-state axis: cross-context sharing IS party-dependent -----------
  // The only place party still gates a label, because CCPA/VCDPA "sharing for
  // cross-context behavioral advertising" is defined across business contexts.
  const thirdPartyExfil = f.thirdPartyDestinations.length > 0;
  const httpToThirdParty = (ev.httpTransmission || []).some((t) => t.party === "third");
  const trackingObserved = activeIdentifier || thirdPartyExfil || httpToThirdParty;
  if (thirdPartyExfil || httpToThirdParty) {
    const dests = [...new Set([...f.thirdPartyDestinations, ...(ev.httpTransmission || []).filter((t) => t.party === "third").map((t) => t.host)])].filter(Boolean);
    us.push(mkLabel(US.SHARE, 0.55, `value disclosed to a different registrable domain: ${dests.slice(0, 3).join(", ")}`));
    us.push(mkLabel(US.SALE, 0.35, "identifier disclosed to a separate business context"));
    signals.push(`Value crosses a registrable-domain boundary to: ${dests.join(", ")}.`);
  }

  // ---- 6. Guarantee each axis is non-empty ----------------------------------
  if (icc.length === 0) {
    icc.push(mkLabel(ICC.FUNC, 0.4, "stored but never read, transmitted or consumed in this crawl"));
  }
  if (us.length === 0) {
    us.push(mkLabel(US.NEC, 0.4, "no sale/share/targeting behavior observed in this crawl"));
  }

  const needsHostKnowledge = activeIdentifier || profilingShape || trackingObserved;

  return {
    prior: {
      iab_purposes: mergeAxis(iab),
      icc_uk_categories: mergeAxis(icc),
      us_state_privacy_categories: mergeAxis(us),
    },
    signals,
    flags: {
      used, usageChannels, trackingObserved, activeIdentifier, necessaryShape, profilingShape,
      crossSiteReach: f.crossSiteReach, needsVendorKnowledge: needsHostKnowledge,
    },
  };
};
