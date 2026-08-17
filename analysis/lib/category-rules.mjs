// category-rules.mjs — the consent-basis rules and the contradiction check derived from them.
//
// The rule is one sentence: a cookie cannot be both consent-EXEMPT and consent-REQUIRED. Everything
// here is bookkeeping around that. The contradiction pairs are RE-DERIVED from the per-category
// bases in category-rules.json, not read from the precomputed list — the precomputed list exists
// only so a human can eyeball the data file, and this module asserts the two agree.

import { readFileSync } from "node:fs";

const RULES = JSON.parse(
  readFileSync(new URL("../data/category-rules.json", import.meta.url), "utf8"),
);

const EXEMPT = new Set(["exempt", "legitimate-interest"]);

// Canonicalise a declared category (a CMP group name, or an ICC label in any case) to one of the
// four ICC families. CMP group names vary — "Strictly Necessary Cookies", "Performance Cookies",
// "Targeting Cookies", "Functional Cookies" — so match on substring against the family's keywords.
const ICC_KEYWORDS = [
  ["Necessary", /necess|essential|strict|security|required/i],
  ["Advertising", /target|advertis|market|\bads?\b|social/i],
  ["Analytics", /analyt|perform|statist|measure|audience/i],
  ["Functional", /function|preferen|personali[sz]/i],
];
export const toIcc = (label) => {
  if (!label) return null;
  const s = String(label);
  if (RULES.icc[s]) return s; // already canonical
  for (const [icc, re] of ICC_KEYWORDS) if (re.test(s)) return icc;
  return null; // unknown group — caller records it as unmapped rather than guessing
};

export const iccBasis = (icc) => RULES.icc[icc]?.consentBasis ?? null;
export const isExemptIcc = (icc) => EXEMPT.has(iccBasis(icc));
export const isConsentRequiredIcc = (icc) => iccBasis(icc) === "consent-required";

/**
 * Contradictions within a set of ICC categories: every (exempt, consent-required) pair present.
 * Returns [] for a consistent set. Severity comes from the data file where specified, else "high"
 * for an exempt/consent-required clash by default.
 */
export const contradictionsIn = (iccCategories) => {
  const cats = [...new Set(iccCategories.filter(Boolean))];
  const exempt = cats.filter(isExemptIcc);
  const consentReq = cats.filter(isConsentRequiredIcc);
  const out = [];
  for (const a of exempt) {
    for (const b of consentReq) {
      const pre = (RULES.derivedContradictions.icc || []).find(
        (p) => (p.a === a && p.b === b) || (p.a === b && p.b === a),
      );
      out.push({ exempt: a, consentRequired: b, severity: pre?.severity ?? "high", contested: !!pre?.contested });
    }
  }
  return out;
};

export const rules = RULES;
