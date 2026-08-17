// tcf-taxonomy.mjs — the label vocabularies the classifier emits.
//
// Three parallel MULTI-LABEL axes, mirroring the VaultJS classifier so results
// are directly comparable:
//   - iab_purposes             : the IAB TCF purposes (the axis the user cares about)
//   - icc_uk_categories        : ICC/UK cookie families
//   - us_state_privacy_categories : CCPA/VCDPA-style US-state categories
//
// The literal `iab_purposes` label STRINGS here use the canonical IAB TCF v2.2
// purpose names. VaultJS `get_device_disclosure` emits the same "Purpose N - …"
// shape (verified live) — its GVL feed uses the older v2.0 short names
// ("Select basic ads" etc.); the v2.0 alias is recorded per entry so a caller
// can reconcile either vintage. Everything downstream (rules + LLM head) reads
// the enum from THIS file, so adjusting a label string is a one-line change.

// The 12 entries of the iab_purposes axis: TCF v2.2 Purposes 1–11 plus Special
// Purpose 1 (the "essential / security" anchor that pure purposes 1–11 omit and
// that most strictly-necessary cookies map to).
export const IAB_PURPOSES = [
  { id: "P1", label: "Purpose 1 - Store and/or access information on a device", aliasV20: "Store and/or access information on a device", family: "essential" },
  { id: "P2", label: "Purpose 2 - Use limited data to select advertising", aliasV20: "Select basic ads", family: "advertising" },
  { id: "P3", label: "Purpose 3 - Create profiles for personalised advertising", aliasV20: "Create a personalised ads profile", family: "advertising" },
  { id: "P4", label: "Purpose 4 - Use profiles to select personalised advertising", aliasV20: "Select personalised ads", family: "advertising" },
  { id: "P5", label: "Purpose 5 - Create profiles to personalise content", aliasV20: "Create a personalised content profile", family: "content" },
  { id: "P6", label: "Purpose 6 - Use profiles to select personalised content", aliasV20: "Select personalised content", family: "content" },
  { id: "P7", label: "Purpose 7 - Measure advertising performance", aliasV20: "Measure ad performance", family: "advertising" },
  { id: "P8", label: "Purpose 8 - Measure content performance", aliasV20: "Measure content performance", family: "analytics" },
  { id: "P9", label: "Purpose 9 - Understand audiences through statistics or combinations of data from different sources", aliasV20: "Apply market research to generate audience insights", family: "analytics" },
  { id: "P10", label: "Purpose 10 - Develop and improve services", aliasV20: "Develop and improve products", family: "functional" },
  { id: "P11", label: "Purpose 11 - Use limited data to select content", aliasV20: "Select basic content", family: "content" },
  { id: "SP1", label: "Special Purpose 1 - Ensure security, prevent and detect fraud, and fix errors", aliasV20: "Ensure security, prevent fraud, and debug", family: "essential" },
];

// ICC/UK cookie families (4).
export const ICC_UK_CATEGORIES = ["Necessary", "Functional", "Analytics", "Advertising"];

// CCPA/VCDPA-style US-state privacy categories. "Sharing for Cross-Context
// Behavioral Advertising" and "Sale of Personal Information" are the CCPA opt-out
// triggers; "Targeted Advertising" is the VCDPA/CPA term; the rest are the common
// non-opt-out buckets.
export const US_STATE_PRIVACY_CATEGORIES = [
  "Sale of Personal Information",
  "Sharing for Cross-Context Behavioral Advertising",
  "Targeted Advertising",
  "Analytics / Performance",
  "Strictly Necessary / Exempt",
];

// Convenience lookups.
export const IAB_LABELS = IAB_PURPOSES.map((p) => p.label);
export const iabById = Object.fromEntries(IAB_PURPOSES.map((p) => [p.id, p]));
export const iabLabel = (id) => iabById[id]?.label ?? id;

// Confidence is TEXT, not a number. A 0.86 on a TCF purpose is false precision: nothing in this
// pipeline is calibrated, so a decimal invites a reader to compare values that were never
// comparable. Four levels, ordered, and that is the whole vocabulary.
export const CONFIDENCE_LEVELS = [
  "low-confidence",
  "medium-confidence",
  "high-confidence",
  "fully-sure",
];
export const confidenceRank = (c) => {
  const i = CONFIDENCE_LEVELS.indexOf(c);
  return i === -1 ? -1 : i;
};

// The deterministic rules were written with numeric weights at 32 call sites. Rather than
// hand-translate each (and silently change a rule while doing it), the numbers are mapped here,
// once, on the way out. Callers may pass either form; everything downstream sees text.
export const toConfidence = (x) => {
  if (typeof x === "string") {
    return CONFIDENCE_LEVELS.includes(x) ? x : "low-confidence";
  }
  const n = Number(x);
  if (!Number.isFinite(n)) return "low-confidence";
  if (n >= 0.9) return "fully-sure";
  if (n >= 0.7) return "high-confidence";
  if (n >= 0.45) return "medium-confidence";
  return "low-confidence";
};

// A single label entry on any axis: { label, confidence, reasoning }.
export const mkLabel = (label, confidence, reasoning) => ({
  label,
  confidence: toConfidence(confidence),
  reasoning,
});
