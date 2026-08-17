#!/usr/bin/env node
// label-from-flows.mjs — assign privacy labels from observed behaviour.
//
//   node analysis/label-from-flows.mjs <flowdir> [--sidecar <base>.cookies.json] [--json]
//
// This is the classification step. It consumes the behaviour produced by
// extract-cookie-flows + resolve-script-origins + describe-flows, and emits three
// multi-label axes per stored item:
//   iab_purposes                 the IAB TCF purposes
//   icc_uk_categories            Necessary / Functional / Analytics / Advertising
//   us_state_privacy_categories  CCPA/VCDPA-style
//
// Every label carries the observed behaviour that produced it. Rules are deterministic
// and read only what was measured: where the value came from, whose script read it,
// whether a script deliberately harvested it, and where it went.
//
// Not used as input, deliberately: the item's NAME, how often anything happened, whether
// a flow was first- or third-party (party gates only the US-state sharing labels, where
// statute defines it), and — importantly — the item's DECLARED ATTRIBUTES. An earlier
// version gated labels on httpOnly, Max-Age and value entropy. Those are properties the
// site asserts about a cookie, not things it was observed doing: a 400-day Max-Age on a
// value nothing ever reads is not tracking, and a session cookie read by four vendors
// is. Every rule below fires on observed behaviour only. Attributes are still loaded,
// but purely to print alongside a verdict as context.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { roleOf, snapshotInfo } from "./lib/host-role.mjs";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const asJson = argv.includes("--json");
const sidecarPath = flag("--sidecar", null);
const DIR = argv.find(a => !a.startsWith("--") && a !== sidecarPath);
if (!DIR || !existsSync(join(DIR, "_summary.json"))) {
  process.stderr.write("usage: node analysis/label-from-flows.mjs <flowdir> [--sidecar <base>.cookies.json] [--json]\n");
  process.exit(1);
}

const P = {
  1:"Purpose 1 - Store and/or access information on a device",
  2:"Purpose 2 - Use limited data to select advertising",
  3:"Purpose 3 - Create profiles for personalised advertising",
  4:"Purpose 4 - Use profiles to select personalised advertising",
  5:"Purpose 5 - Create profiles to personalise content",
  6:"Purpose 6 - Use profiles to select personalised content",
  7:"Purpose 7 - Measure advertising performance",
  8:"Purpose 8 - Measure content performance",
  9:"Purpose 9 - Understand audiences through statistics or combinations of data from different sources",
  10:"Purpose 10 - Develop and improve services",
  11:"Purpose 11 - Use limited data to select content",
  SP1:"Special Purpose 1 - Ensure security, prevent and detect fraud, and fix errors",
};
const ICC = { NEC:"Necessary", FUN:"Functional", ANA:"Analytics", ADV:"Advertising" };
const US = { SALE:"Sale of Personal Information", SHARE:"Sharing for Cross-Context Behavioral Advertising",
  TARGET:"Targeted Advertising", PERF:"Analytics / Performance", NEC:"Strictly Necessary / Exempt" };

// A destination host is OBSERVED evidence, unlike a cookie name. But resolving what that host
// IS remains outside knowledge. That resolution used to be a hand-written regex table grounded
// in nothing; it is now DuckDuckGo Tracker Radar (a maintained public dataset), read from a
// committed offline snapshot so labelling stays deterministic. `roleOf` returns the full
// record — mapped roles, the verbatim DDG categories, and the owner — so a verdict cites the
// evidence rather than just our re-label. A host absent from the dataset, or present with no
// mapped category, resolves to no role: the caller reports that as recipient-unresolved and
// must not guess a category from it.
// A value sent to the FIRST PARTY is not "harvested to a third-party vendor", even if Tracker
// Radar categorises that domain as a tracker — that categorisation describes the domain's
// behaviour as a third party ON OTHER SITES, not first-party collection on its own home. So
// the page's own registrable domain is excluded from role resolution; a first-party send still
// records carriage (P9) but is never assigned a vendor role from Tracker Radar.
const trLookup = h => (firstParty(h) ? null : roleOf(h));
const hostRole = h => {
  const r = trLookup(h);
  return r && r.roles.length ? r : null;
};
const roleSet = hosts => new Set(hosts.flatMap(h => (hostRole(h)?.roles) || []));
// A compact "Tracker Radar: <owner>, [cat, cat]" phrase for evidence strings.
const SRC_LABEL = { "tracker-radar": "Tracker Radar", "infrastructure-supplement": "infrastructure list" };
const trEvidence = hosts => {
  const seen = [];
  for (const h of [...new Set(hosts.filter(Boolean))]) {
    const r = trLookup(h);
    if (r) seen.push(`${r.matchedDomain} → ${r.owner || "?"} [${r.categories.join(", ") || "uncategorised"}] (${SRC_LABEL[r.source] || r.source})`);
  }
  return seen.join("; ");
};

const summary = JSON.parse(readFileSync(join(DIR, "_summary.json"), "utf8"));
// The page's own registrable domain, used to exclude first-party sends from role resolution.
// Minimal multi-part-suffix handling covers the client set (e.g. fidelity.co.uk).
const MULTI_SUFFIX = new Set(["co.uk", "com.au", "co.jp", "co.nz", "com.br", "co.in", "org.uk", "gov.uk"]);
const registrable = host => {
  if (!host) return null;
  const p = String(host).toLowerCase().replace(/\.$/, "").split(".");
  if (p.length <= 2) return p.join(".");
  const last2 = p.slice(-2).join(".");
  return MULTI_SUFFIX.has(last2) ? p.slice(-3).join(".") : last2;
};
const pageReg = (() => { try { return registrable(new URL(summary.pageUrl).hostname); } catch { return null; } })();
const firstParty = host => {
  if (!host || !pageReg) return false;
  const h = String(host).toLowerCase();
  return h === pageReg || h.endsWith("." + pageReg);
};
// The identifying-value floor, reused from the extractor rather than invented here. If the
// summary records the value it ran with, honour it; otherwise fall back to the extractor default.
const MIN_BITS = summary.minBits ?? 30;
// Per-site Google-ads signal (detect-google-ads.mjs). Decides whether the Google Analytics
// deployment shares with Google advertising, from observed client-side behaviour (the
// DoubleClick collect mirror, Google Ads cookies/endpoints, AW-/DC- gtag tags). Absent the file
// or the signal, GA is treated as analytics-only on the cookie — the server-side account-linking
// that could still make it advertising is not observable in a logged-out crawl and is carried by
// a report caveat, not a per-cookie label.
const gaAds = (() => { try { return JSON.parse(readFileSync(join(DIR, "_google-ads.json"), "utf8")); } catch { return { gaAdvertising: false, evidence: [] }; } })();
// The Google-measurement family. Names route an item to the GA rule (scope selection only); the
// advertising verdict still comes from observed behaviour, never from the name.
const GA_FAMILY = /^(_ga($|_)|_gid$|_gat|_gcl_|_gac_|__gads$|__gpi$)/;
// Site-level advertising pathway (detect-ad-pathway.mjs): did this page contact any pure ad/RTB
// endpoint at all? Generalises the Google-signals idea to every dual-use vendor.
const adPath = (() => { try { return JSON.parse(readFileSync(join(DIR, "_ad-pathway.json"), "utf8")); } catch { return { adPathway: false, adOnlyHosts: [] }; } })();

// Many measurement platforms are DUAL-USE: Tracker Radar lists them as advertising AND analytics
// (Optimizely, Qualtrics, Tealium, GTM, Contentsquare). Calling their identifiers "advertising"
// merely because the vendor is capable of it is the error the blanket `_ga` label made. But some
// vendors' tracking exists TO serve advertising — DDG marks those `Ad Motivated Tracking` (and
// pixel vendors `Action Pixels`): Meta, Twitter, Lotame, Ensighten. Those are advertising
// unconditionally. The distinction comes from the dataset, not a hand-written vendor list.
const AD_MOTIVATED = /^(Ad Motivated Tracking|Action Pixels|Ad Fraud)$/;
const isAdMotivated = h => { const r = hostRole(h); return !!r && (r.categories || []).some(c => AD_MOTIVATED.test(c)); };
const isDualUse = h => { const r = hostRole(h); return !!r && r.roles.includes("advertising") && r.roles.includes("analytics"); };
// May this host's advertising role be asserted? Always for ad-motivated vendors and for
// single-role advertising vendors; for dual-use vendors only when an ad pathway was observed
// (site-level) or the Google-specific signal fired.
const adAssertable = hosts => {
  const list = (hosts || []).filter(Boolean);
  if (list.some(isAdMotivated)) return { ok: true, why: `vendor categorised “Ad Motivated Tracking”/“Action Pixels” by Tracker Radar — tracking that exists to serve advertising` };
  const dual = list.filter(isDualUse);
  const singleAd = list.filter(h => { const r = hostRole(h); return r && r.roles.includes("advertising") && !r.roles.includes("analytics"); });
  if (singleAd.length) return { ok: true, why: `${singleAd.join(", ")} is an advertising-only endpoint` };
  if (!dual.length) return { ok: false, why: "" };
  if (gaAds.gaAdvertising) return { ok: true, why: `the Google deployment shares with Google advertising — observed ${gaAds.evidence?.[0] ? gaAds.evidence[0].signal : "ads signal"}` };
  if (adPath.adPathway) return { ok: true, why: `an advertising pathway is active on this page — ad endpoints contacted: ${(adPath.adOnlyHosts || []).slice(0, 3).join(", ")}` };
  return { ok: false, why: `dual-use vendor (${dual.join(", ")}) with no advertising pathway observed on this page` };
};
const attrs = new Map();
if (sidecarPath && existsSync(sidecarPath)) {
  for (const c of JSON.parse(readFileSync(sidecarPath, "utf8"))) attrs.set(c.name, c);
}
const refEpoch = (() => { const m = String(sidecarPath || "").match(/_(\d{9,11})\./); return m ? Number(m[1]) : null; })();

const bits = s => { if (!s) return 0; const f = new Map();
  for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let h = 0; for (const c of f.values()) { const p = c / s.length; h -= p * Math.log2(p); } return h * s.length; };

// No probabilities. Earlier versions attached hand-written numbers (0.85, 0.65, 0.4 …)
// and filtered on an invented 0.5 cutoff. Nothing calibrated those numbers: 0.65 did not
// mean "right 65% of the time", and 0.65-vs-0.55 asserted a distinction that could not be
// justified. They dressed a guess as a measurement.
//
// What IS derivable is how the label was arrived at — which follows mechanically from the
// rule that fired and the data it had:
//   observed    the value was seen reaching a named endpoint, or a named vendor's script
//               read it. Directly measured, no outside knowledge needed.
//   inferred    the behaviour was observed, but one link required knowing what a host IS
//               (resolving bat.bing.com to advertising).
//   unresolved  the behaviour is consistent with the label but does not settle it — the
//               recipient's role is unknown, or the page rewrites its own URLs.
const TIER = { observed: 3, inferred: 2, unresolved: 1 };
const label = (l, tier, why) => ({ label: l, basis: tier, evidence: why });
const merge = a => { const m = new Map();
  for (const x of a) { const prev = m.get(x.label);
    if (!prev || TIER[x.basis] > TIER[prev.basis]) m.set(x.label, x); }
  return [...m.values()].sort((x, y) => TIER[y.basis] - TIER[x.basis]); };

export const classify = (d) => {
  const iab = [], icc = [], us = [], basis = [];
  const A = attrs.get(d.item) || {};
  const val = (d.values || [])[0] || "";
  const b = bits(val);
  // context only — printed beside a verdict, never used to decide one
  const lifeDays = (A.expires != null && A.expires > 0 && refEpoch) ? (A.expires - refEpoch) / 86400 : null;

  const beh = d.behaviours || [];
  const has = k => beh.some(x => x.kind === k);
  const sent = beh.filter(x => x.kind === "exfil");
  const sentHosts = [...new Set(sent.map(x => x.detail?.host).filter(Boolean))];
  // Two different questions about a third-party reader, kept separate:
  //  - DISCLOSURE: did someone receive data they did not set? A vendor reading back a cookie it
  //    itself wrote (AWS WAF its challenge token; Meta its own _fbp) is operating its own state,
  //    not a cross-vendor disclosure — so it must NOT trigger the disclosure labels.
  //  - ROLE: what kind of vendor is this value exposed to? A self-reading vendor still answers
  //    this — Meta reading its own advertising cookie is still advertising. So role detection
  //    uses ALL readers, disclosure uses only those that did not write it.
  // Behavioural throughout: it turns on who wrote vs who read, never on the item's name.
  const writerVendors = new Set(
    beh.filter(x => x.kind === "origin").map(x => x.detail?.vendor).filter(Boolean));
  const readers = [...new Set((d.thirdPartyReaders || []))];                        // all — for role
  const disclosureReaders = readers.filter(v => !writerVendors.has(v));             // received data they didn't set
  // Roles now come from Tracker Radar (see hostRole above), not a hand-written table. A role
  // is present only when the dataset actually categorises the host; unknown hosts contribute
  // nothing and drive the recipient-unresolved path.
  const sentRoles = roleSet(sentHosts);
  const readerRoles = roleSet(readers);
  const roles = new Set([...sentRoles, ...readerRoles]);
  const hostsByRole = (hosts, role) => hosts.filter(h => (hostRole(h)?.roles || []).includes(role));
  const sentResolved = sentHosts.some(h => hostRole(h));
  // DYNAMIC signals — each is something that was observed happening, not asserted.
  // Distinct reading call sites, not a count of reads: several different functions
  // wanting the same value is a fact about how it is used; the same function running
  // repeatedly is not.
  const reads = beh.filter(x => x.kind === "read");
  const distinctReaders = new Set(reads.map(x => x.detail?.fn || x.text)).size;
  const transformed = beh.filter(x => x.kind === "transform");
  const consumed = beh.filter(x => x.kind === "consume");
  const serverIssued = beh.some(x => x.kind === "origin" && /Set-Cookie/i.test(x.text));
  // A value that is read back and then DOES something — transformed, passed onward, or
  // shipped — is being used to recognise or act on the visitor. Read-and-discard is not.
  const readThenUsed = reads.length > 0 && (transformed.length || consumed.length || sent.length);

  // Distinctiveness gate. A value can only carry an IDENTIFIER-based label (profiling,
  // targeting, "shared key") if it is actually capable of identifying someone — i.e. it clears
  // the same entropy floor the extractor already uses to decide a value is worth tracking
  // through the graph (`--min-bits`, default 30). "Logged Out", "true", "Chegg Study Web" are
  // constants: they can prove carriage (the value did travel) but not identification. This is
  // entropy of the OBSERVED value, not a declared attribute, and it reuses an existing
  // threshold rather than inventing one. `recipientUnresolved` is set when a value was
  // harvested to a host Tracker Radar does not categorise — reported as its own state, never
  // as a guessed category.
  const identifying = b >= MIN_BITS;
  let recipientUnresolved = false;

  // 1. definitional
  iab.push(label(P[1], "observed", "a storage write for this item was recorded"));
  basis.push("stored on the device");

  // 2. never used / probe — used, but not about the user
  if (d.isProbe) {
    icc.push(label(ICC.NEC, "observed", "written, read straight back and discarded — a storage availability probe"));
    iab.push(label(P.SP1, "observed", "technical capability check, no user data involved"));
    us.push(label(US.NEC, "observed", "no user data processed"));
    basis.push("capability probe");
  return { item: d.item, bucket: d.bucket, basis, recipientUnresolved, identifying,
      iab_purposes: merge(iab), icc_uk_categories: merge(icc), us_state_privacy_categories: merge(us) };
  }
  // A GA identifier belongs to the site's Google deployment whether or not it happened to fire in
  // this single load, so an ad-enabled deployment still makes it advertising — let it fall through
  // to the GA rule rather than short-circuiting as "not exercised".
  const gaAdEligible = /^(_ga$|_gid$|_gcl_|_gac_|__gads$|__gpi$)/.test(d.item);
  if (d.neverUsed && !(gaAds.gaAdvertising && gaAdEligible)) {
    // Nothing touched it this load. Absence of evidence is not a category: emit P1 (it was
    // stored) and stop. Defaulting the unexercised to Functional was the least-safe bin —
    // exactly where undeclared analytics hides. The report renders unresolved:true as
    // "not exercised", not as a verdict.
    basis.push("no use observed this load — not categorised");
    return { item: d.item, bucket: d.bucket, unresolved: true, basis,
      iab_purposes: merge(iab), icc_uk_categories: [], us_state_privacy_categories: [] };
  }

  // 3. server-managed token: issued by the server and never touched by page code
  if (serverIssued && !reads.length && !sent.length && !readers.length) {
    icc.push(label(ICC.NEC, "observed", "issued by the server and never read, harvested or disclosed by any script"));
    iab.push(label(P.SP1, "observed", "no page code ever accessed it — consistent with a server-side session or security token"));
    us.push(label(US.NEC, "observed", "no client-side processing observed"));
    basis.push("server-issued, never touched by page code");
  }

  // 4. a third-party script read storage it did not create
  if (readers.length) {
    const cite = trEvidence(readers) ? ` — categorised via ${trEvidence(readers)}` : "";
    // Disclosure labels: only when a vendor received data it did not set.
    if (disclosureReaders.length) {
      const r = disclosureReaders.join(", ");
      iab.push(label(P[9], "observed", `read in-page by ${r}, which receives data it did not set`));
      icc.push(label(ICC.ANA, "observed", `disclosed to ${r} by an in-page read`));
      us.push(label(US.SHARE, "observed", `disclosed to ${r} without a cross-domain request`));
      basis.push(`disclosed to third-party script: ${r}`);
    }
    // Role labels: any reading vendor, including one reading back its own cookie.
    if (readerRoles.has("analytics")) iab.push(label(P[8], "inferred", `read by a vendor categorised as analytics${cite}`));
    const advOkR = adAssertable(readers);
    if (readerRoles.has("advertising") && identifying && advOkR.ok) {
      icc.push(label(ICC.ADV, "inferred", `read by a vendor categorised as advertising — ${advOkR.why}${cite}`));
      iab.push(label(P[7], "inferred", `identifier available to an advertising vendor — ${advOkR.why}`));
    } else if (readerRoles.has("advertising") && identifying) {
      basis.push(advOkR.why || "advertising role not asserted for a dual-use vendor");
    }
  }

  // 5. a script deliberately harvested the value and shipped it
  if (sent.length) {
    const h = sentHosts.join(", ") || "a collection endpoint";
    const cite = trEvidence(sentHosts) ? ` — categorised via ${trEvidence(sentHosts)}` : "";
    basis.push(`harvested into a request to ${h}`);
    // The harvest itself is observed regardless of who received it.
    iab.push(label(P[9], "observed", `value re-encoded into a request to ${h}`));

    const advOkS = adAssertable(sentHosts);
    if (sentRoles.has("advertising") && !advOkS.ok) {
      basis.push(advOkS.why || "advertising role not asserted for a dual-use recipient");
    }
    if (sentRoles.has("advertising") && advOkS.ok) {
      const advH = hostsByRole(sentHosts, "advertising").join(", ");
      icc.push(label(ICC.ADV, "inferred", `harvested to ${advH}, categorised as advertising — ${advOkS.why}`));
      us.push(label(US.TARGET, "inferred", `identifier delivered to an advertising vendor — ${advOkS.why}`));
      // Profile-building / ad-selection require the value to be an identifier.
      if (identifying) {
        iab.push(label(P[7], "inferred", `sent to ${advH}, categorised as advertising${cite}`));
        iab.push(label(P[3], "inferred", "identifier delivered to an advertising vendor"));
        iab.push(label(P[4], "inferred", "identifier usable to select personalised advertising"));
        iab.push(label(P[2], "inferred", "identifier usable for ad selection"));
      }
    }
    if (sentRoles.has("analytics")) {
      iab.push(label(P[8], "inferred", `sent to a vendor categorised as analytics${cite}`));
      icc.push(label(ICC.ANA, "inferred", `harvested to a vendor categorised as analytics${cite}`));
      us.push(label(US.PERF, "inferred", "measurement processing"));
    }
    if (sentRoles.has("security")) {
      iab.push(label(P.SP1, "inferred", `sent to ${hostsByRole(sentHosts, "security").join(", ")}, categorised as fraud-prevention${cite}`));
      icc.push(label(ICC.NEC, "inferred", "delivered to a vendor categorised as security"));
    }
    if (!sentResolved) {
      // Recipient is not in Tracker Radar. Do NOT assert a category — the unknown-ness is
      // itself the finding. The harvest (P9) stands; the report shows "sent to an unclassified
      // endpoint", not Advertising-or-Analytics.
      recipientUnresolved = true;
      basis.push(`recipient not in Tracker Radar (${sentHosts.join(", ")}) — category not asserted`);
    }
  }

  // 6. cross-context disclosure is the one place party is load-bearing
  if (d.offsiteDestinations?.length) {
    us.push(label(US.SHARE, "observed", `value crosses to ${d.offsiteDestinations.join(", ")}`));
    us.push(label(US.SALE, "inferred", "identifier disclosed to a separate business"));
  }

  // 7. a value several distinct parties reach for is a shared key
  if (distinctReaders >= 2 && identifying && (sent.length || readers.length)) {
    iab.push(label(P[3], "observed", `${distinctReaders} distinct pieces of code read this value and it is disclosed onward — it functions as a shared key`));
    us.push(label(US.TARGET, "observed", "a value multiple parties resolve against supports targeting"));
    basis.push(`${distinctReaders} distinct readers plus onward disclosure`);
  }

  // 8. used only by the page itself
  if (!sent.length && !readers.length && has("read")) {
    // A durable, high-entropy value that is read back is a re-identification key
    // regardless of where it goes — and on a page that rewrites its own request URLs,
    // "no destination observed" is what the mechanism is built to produce, so absence of
    // a destination must not pull the label down to merely functional.
    if (readThenUsed) {
      const how = [transformed.length ? `transformed (${transformed.map(x => x.text).join("; ")})` : null,
                   consumed.length ? "passed to further code" : null].filter(Boolean).join(" and ");
      icc.push(label(ICC.ANA, "observed", `read back and then ${how || "acted upon"} — the value is being used to recognise state across the visit`));
      iab.push(label(P[8], "observed", "value read back and acted upon, enabling measurement"));
      iab.push(label(P[9], "observed", "recognition across requests supports audience statistics"));
      basis.push("read back and acted upon; destination not observed");
    } else {
      icc.push(label(ICC.NEC, "observed", "read back by the site\u2019s own code for its own operation, not disclosed or transmitted"));
      basis.push("first-party operational use only — necessary");
    }
  }

  // GA rule: a `_ga` is the analytics client id; it is advertising only when the deployment is
  // observed sharing with Google advertising. google-analytics.com carries BOTH roles in Tracker
  // Radar, so the generic rules above may have leaked an advertising label onto every GA id.
  // Strip that ad-axis, then re-add it only when the site's observed Google-ads signal is present
  // and this specific item was exercised this load.
  if (GA_FAMILY.test(d.item)) {
    // google-analytics.com carries BOTH advertising and analytics roles in Tracker Radar, so the
    // generic rules may have stamped every GA id as advertising. Strip that ad-axis; the GA
    // advertising verdict is decided ONLY by the site's observed Google-ads signal, and it is a
    // property of the deployment, applied to the GA identifiers regardless of per-load exercise.
    const ADV_TCF = new Set([P[2], P[3], P[4], P[6], P[7]]);
    for (let i = icc.length - 1; i >= 0; i--) if (icc[i].label === ICC.ADV) icc.splice(i, 1);
    for (let i = iab.length - 1; i >= 0; i--) if (ADV_TCF.has(iab[i].label)) iab.splice(i, 1);
    for (let i = us.length - 1; i >= 0; i--) if (us[i].label === US.TARGET) us.splice(i, 1);
    if (gaAds.gaAdvertising && gaAdEligible) {
      const e = gaAds.evidence?.[0] ? `${gaAds.evidence[0].signal} (${gaAds.evidence[0].detail})` : "Google ads deployment observed";
      icc.push(label(ICC.ADV, "inferred", `the Google deployment shares with Google advertising \u2014 observed ${e}`));
      iab.push(label(P[7], "inferred", `identifier available to Google advertising \u2014 observed ${e}`));
      iab.push(label(P[3], "inferred", "identifier available to Google for ad profiling"));
      us.push(label(US.TARGET, "inferred", "identifier available to Google advertising"));
      basis.push("Google deployment shares with Google advertising (observed client-side)");
    } else if (!gaAds.gaAdvertising) {
      basis.push("Google Analytics; no client-side ad-sharing observed \u2014 a logged-out crawl cannot observe server-side account linking (see report caveat)");
    }
  }

  if (!icc.length && !recipientUnresolved) icc.push(label(ICC.NEC, "unresolved", "used only by the site\u2019s own code; no disclosure or transmission observed"));
  if (!us.length) us.push(label(US.NEC, "unresolved", "no sale, sharing or targeting behaviour observed"));
  return { item: d.item, bucket: d.bucket, basis, recipientUnresolved, identifying,
    iab_purposes: merge(iab), icc_uk_categories: merge(icc), us_state_privacy_categories: merge(us) };
};

// describe-flows supplies the behaviour view. It is read from a file rather than a
// pipe: its JSON runs to hundreds of kilobytes and a pipe truncates it mid-string.
// Generate with:  node analysis/describe-flows.mjs <flowdir> --json > behaviour.json
const describedPath = flag("--described", join(DIR, "_behaviour.json"));
if (!existsSync(describedPath)) {
  const { execFileSync } = await import("node:child_process");
  const { writeFileSync, openSync, closeSync } = await import("node:fs");
  const fd = openSync(describedPath, "w");
  try {
    execFileSync("node", [new URL("describe-flows.mjs", import.meta.url).pathname, DIR, "--json"],
      { stdio: ["ignore", fd, "inherit"] });
  } finally { closeSync(fd); }
}
const described = JSON.parse(readFileSync(describedPath, "utf8"));

const out = described.items.map(classify);
const rank = x => { const t = x.icc_uk_categories[0]?.label;
  return t === ICC.ADV ? 0 : t === ICC.ANA ? 1 : t === ICC.FUN ? 2 : 3; };
out.sort((a, b) => rank(a) - rank(b) || a.item.localeCompare(b.item));

if (asJson) { process.stdout.write(JSON.stringify({ page: summary.pageUrl, items: out }, null, 2) + "\n"); process.exit(0); }

console.log("═".repeat(86));
console.log(`LABELS — ${summary.pageUrl}`);
console.log("═".repeat(86));
const short = l => l.replace(/^(Special )?Purpose (\d+).*/, (m, s, n) => (s ? "SP" : "P") + n);
for (const it of out) {
  const mark = { observed: "", inferred: " (inferred)", unresolved: " (unresolved)" };
  const icc = it.icc_uk_categories.map(l => l.label + mark[l.basis]).join(" + ") || "—";
  const tcf = it.iab_purposes.map(l => short(l.label) + mark[l.basis].replace(" (inferred)", "~").replace(" (unresolved)", "?")).join(" ");
  console.log(`\n${it.bucket} :: ${it.item}${it.unresolved ? "   (no use observed)" : ""}`);
  console.log(`   ICC  ${icc}`);
  console.log(`   TCF  ${tcf}`);
  console.log(`   US   ${it.us_state_privacy_categories.map(l => l.label + mark[l.basis]).join(" · ") || "—"}`);
  for (const e of it.iab_purposes.slice(0, 4))
    console.log(`        ${short(e.label).padEnd(4)} [${e.basis}] ${e.evidence}`);
}
const c = { Advertising: 0, Analytics: 0, Functional: 0, Necessary: 0 };
// count only labels the evidence actually established; inferred/unresolved reported apart
const ci = { Advertising: 0, Analytics: 0, Functional: 0, Necessary: 0 };
for (const it of out) for (const l of it.icc_uk_categories) {
  if (!(l.label in c)) continue;
  if (l.basis === "observed") c[l.label]++; else ci[l.label]++;
}
console.log(`\n${"═".repeat(86)}`);
console.log(`ICC observed   Advertising ${c.Advertising} · Analytics ${c.Analytics} · Functional ${c.Functional} · Necessary ${c.Necessary}`);
console.log(`   inferred/unresolved   Advertising ${ci.Advertising} · Analytics ${ci.Analytics} · Functional ${ci.Functional} · Necessary ${ci.Necessary}`);
