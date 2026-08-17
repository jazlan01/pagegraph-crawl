// verdict-schema.mjs — validate a classification verdict against the taxonomy,
// whichever head produced it (Anthropic API tool-use, or an in-session/external
// classifier fed back via `--verdicts`). Enforces: all three axes present and
// non-empty, every label drawn from the axis enum, probabilities in [0,1],
// reasoning present. Unknown labels are rejected loudly rather than passed
// through — a mislabelled axis would silently corrupt a compliance verdict.

import {
  IAB_LABELS, ICC_UK_CATEGORIES, US_STATE_PRIVACY_CATEGORIES,
  CONFIDENCE_LEVELS, confidenceRank, toConfidence,
} from "./tcf-taxonomy.mjs";

const AXES = {
  iab_purposes: IAB_LABELS,
  icc_uk_categories: ICC_UK_CATEGORIES,
  us_state_privacy_categories: US_STATE_PRIVACY_CATEGORIES,
};

// Accept either the full canonical label or a short "P7" / "Purpose 7" form and
// normalize to canonical, so a head that abbreviates is still usable.
const canonicalize = (axis, label) => {
  const allowed = AXES[axis];
  if (allowed.includes(label)) return label;
  if (axis === "iab_purposes") {
    const m = String(label).match(/^(?:(S)P|P|(?:Special )?Purpose )\s*(\d+)/i);
    if (m) {
      const special = !!m[1] || /special/i.test(label);
      const n = m[2];
      const want = special ? `Special Purpose ${n} -` : `Purpose ${n} -`;
      const hit = allowed.find((l) => l.startsWith(want));
      if (hit) return hit;
    }
    // tolerate v2.0 alias / prefix match
    const pre = allowed.find((l) => l.toLowerCase().startsWith(String(label).toLowerCase().slice(0, 24)));
    if (pre) return pre;
  }
  return null;
};

export const validateVerdict = (name, verdict) => {
  const errors = [];
  const out = {};
  for (const axis of Object.keys(AXES)) {
    const arr = verdict?.[axis];
    if (!Array.isArray(arr) || arr.length === 0) {
      errors.push(`${name}: ${axis} missing or empty`);
      continue;
    }
    const labels = [];
    for (const entry of arr) {
      const canon = canonicalize(axis, entry?.label);
      if (!canon) {
        errors.push(`${name}: ${axis} unknown label ${JSON.stringify(entry?.label)}`);
        continue;
      }
      // Confidence is a word from a fixed list. A head that emits a number (or an older cached
      // verdict) is mapped rather than rejected, so a taxonomy change does not invalidate
      // evidence that is otherwise fine — but anything outside the vocabulary is an error.
      const rawConf = entry.confidence ?? entry.probability;
      const conf = toConfidence(rawConf);
      if (entry.confidence !== undefined && !CONFIDENCE_LEVELS.includes(entry.confidence)) {
        errors.push(`${name}: ${axis} label "${canon}" has confidence ` +
          `${JSON.stringify(entry.confidence)}; expected one of ${CONFIDENCE_LEVELS.join(", ")}`);
      }
      if (!entry.reasoning || typeof entry.reasoning !== "string") {
        errors.push(`${name}: ${axis} label "${canon}" missing reasoning`);
        continue;
      }
      labels.push({ label: canon, confidence: conf, reasoning: entry.reasoning });
    }
    // de-dup by label (keep highest probability), sort desc
    const by = new Map();
    for (const l of labels) {
      const prev = by.get(l.label);
      if (!prev || confidenceRank(l.confidence) > confidenceRank(prev.confidence)) by.set(l.label, l);
    }
    out[axis] = [...by.values()].sort((a, b) => confidenceRank(b.confidence) - confidenceRank(a.confidence));
    if (out[axis].length === 0) errors.push(`${name}: ${axis} had no valid labels`);
  }
  out.evidence_summary = typeof verdict?.evidence_summary === "string" ? verdict.evidence_summary : "";
  if (!out.evidence_summary) errors.push(`${name}: evidence_summary missing`);
  return { ok: errors.length === 0, errors, verdict: out };
};
