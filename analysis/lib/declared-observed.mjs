// declared-observed.mjs — the per-cookie join between the site's declaration and our observed
// classification, and the verdict derived from them. Extracted so the per-site report
// (declaration-report.mjs) and the combined per-cookie/per-site report share ONE implementation —
// two reports that must agree on "is this under-declared?" cannot each carry their own copy.
//
// The classifier is never touched here; this is presentation-layer join only.

import { contradictionsIn, isConsentRequiredIcc } from "./category-rules.mjs";

export const RANK = { "low-confidence": 0, "medium-confidence": 1, "high-confidence": 2, "fully-sure": 3 };
export const TRACKING = new Set(["Analytics", "Advertising"]);

// Labels we're willing to stand behind: medium-confidence or better.
export const asserted = (labels) => (labels || []).filter((x) => (RANK[x.confidence] ?? 0) >= 1);

// Declared entry for an observed name: exact, then a declared family prefix (OneTrust lists `_ga`
// to cover `_ga_XXXX`), then a pattern stem. Prefix only for stems ≥ 3 chars, to avoid noise.
export const lookupDeclared = (declaration, name) => {
  const cookies = declaration?.cookies || {};
  if (cookies[name]) return { entry: cookies[name], match: "exact" };
  for (const [dname, entry] of Object.entries(cookies)) {
    if (dname.length >= 3 && !entry.isPattern && name.startsWith(dname)) return { entry, match: `prefix:${dname}` };
    if (entry.isPattern) {
      const stem = dname.replace(/[*[\]].*$/, "");
      if (stem.length >= 3 && name.startsWith(stem)) return { entry, match: `pattern:${dname}` };
    }
  }
  return null;
};

const iccOf = (observedDoc) => observedDoc?.final?.icc_uk_categories || [];

/**
 * Build one comparison row. `observedDoc` is a classify-v2/pass3 result (or null if the cookie was
 * not classified). Returns the declared side, the observed side (with confidence), and the verdict.
 * MCP labels and site are added by the caller — they are not part of the declared-vs-observed logic.
 */
export const buildComparisonRow = ({ name, host, declaration, observedDoc }) => {
  const dec = lookupDeclared(declaration, name);
  const declaredCats = dec?.entry?.declaredCategories || [];
  const obsAsserted = asserted(iccOf(observedDoc));
  const obsLabels = obsAsserted.map((x) => x.label);
  const bestConf = obsAsserted.reduce((m, x) => Math.max(m, RANK[x.confidence] ?? 0), -1);
  const selfContra = contradictionsIn(declaredCats);

  let status, detail = "";
  if (!dec) {
    status = "not-declared";
  } else if (selfContra.length) {
    status = "contradictory-declaration";
    if (!obsLabels.length) detail = "site's declaration is self-contradictory; not observed this load to adjudicate";
    else {
      const obsTracking = obsLabels.filter((l) => TRACKING.has(l));
      detail = obsTracking.length
        ? `behaviour supports ${obsTracking.join("/")} — the Necessary declaration is the false half`
        : `behaviour supports ${obsLabels.join("/")}`;
    }
  } else if (!obsAsserted.length) {
    status = "not-assessable";
    detail = observedDoc ? "our classification was low-confidence; abstaining" : "not classified";
  } else {
    const declaredBenign = declaredCats.length > 0 && declaredCats.every((c) => !isConsentRequiredIcc(c));
    const declaredTracking = declaredCats.some((c) => TRACKING.has(c));
    const obsTracking = obsLabels.some((l) => TRACKING.has(l));
    if (declaredBenign && obsTracking) {
      status = "mismatch-under-declared";
      detail = `declared ${declaredCats.join("/")}, observed ${obsLabels.join("/")}. ${observedDoc?.final?.evidence_summary || ""}`.trim();
    } else if (declaredTracking && !obsTracking) {
      status = "mismatch-over-declared";
      detail = `declared ${declaredCats.join("/")}, observed only ${obsLabels.join("/")} (absence of observed tracking is not proof of none)`;
    } else {
      status = "consistent";
      detail = `declared ${declaredCats.join("/")}, observed ${obsLabels.join("/")}`;
    }
  }

  // Deterministic wire facts: identifier-carrying sends to third parties, stated from the
  // per-destination outbound records (computed from actual request bytes — no LLM involved).
  // Rendered separately from the classifier's prose so the two provenances never blur.
  const outboundFacts = (observedDoc?.outbound || [])
    .filter((o) => o.carriesIdentifier === true && o.party === "third")
    .slice(0, 4)
    .map((o) => {
      const idParts = (o.matchedParts || []).filter((p) => p.isIdentifier).map((p) => `${p.key} (${p.kind})`);
      const what = o.sentForm === "fragment" ? "identifier part"
        : o.sentForm === "derived" ? "derived value incl. identifier"
        : `${o.sentForm === "re-encoded" ? "re-encoded" : "raw"} value incl. persistent id`;
      return `${what}${idParts.length ? ` — ${idParts.join(", ")}` : ""} sent to ${o.host}`;
    });

  return {
    name, host,
    declaredCats, declaredGroups: dec?.entry?.declaredGroupNames || [], declaredDesc: dec?.entry?.description || null,
    match: dec?.match || null,
    outboundFacts,
    observed: obsLabels, observedConf: bestConf >= 0 ? Object.keys(RANK)[bestConf] : null,
    // Per-label evidence, carried through so the report can say WHY each label was assigned rather
    // than showing a bare chip. `reasoning` is the classifier's ≤15-word justification per label.
    observedIcc: obsAsserted.map((x) => ({ label: x.label, confidence: x.confidence, reasoning: x.reasoning || null })),
    observedTcf: (observedDoc?.final?.iab_purposes || []).map((x) => x.label.split(" - ")[0]),
    observedTcfDetail: (observedDoc?.final?.iab_purposes || [])
      .map((x) => ({ label: x.label.split(" - ")[0], confidence: x.confidence, reasoning: x.reasoning || null })),
    evidence: observedDoc?.final?.evidence_summary || null,
    selfContra, status, detail,
  };
};

// The verdict vocabulary, shared for rendering + ordering.
export const STATUS_META = {
  "mismatch-under-declared":   { label: "Under-declared", cls: "bad" },
  "contradictory-declaration": { label: "Contradictory declaration", cls: "bad" },
  "mismatch-over-declared":    { label: "Over-declared", cls: "warn" },
  "not-assessable":            { label: "Not assessable", cls: "muted" },
  "not-declared":              { label: "Not declared", cls: "muted" },
  "consistent":                { label: "Consistent", cls: "ok" },
};
export const STATUS_ORDER = [
  "mismatch-under-declared", "contradictory-declaration", "mismatch-over-declared",
  "not-assessable", "consistent", "not-declared",
];
