// llm-head.mjs — Stage 4: refine the deterministic prior into the final
// three-axis verdict. The LLM's job is the ONE thing the behavior-only rules
// can't do without a knowledge base: resolve each third-party destination host
// to its vendor purpose (ad vs. analytics vs. content) from world knowledge, and
// write the per-label reasoning — grounded strictly in the supplied evidence.
//
// Provider-pluggable; default is the Anthropic Messages API (tool-use forces a
// schema-valid structured result). API key from env — no key means the caller
// falls back to --rules-only. Override the model with CLASSIFIER_MODEL.
//
// NOTE: exact model id / structured-output call should be reconciled against the
// `claude-api` skill; it was unavailable at authoring time. Default below is a
// current model per the session's model roster.

import { IAB_LABELS, ICC_UK_CATEGORIES, US_STATE_PRIVACY_CATEGORIES, CONFIDENCE_LEVELS } from "./tcf-taxonomy.mjs";

const DEFAULT_MODEL = process.env.CLASSIFIER_MODEL || "claude-sonnet-5";
const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";

export const llmAvailable = () => !!process.env.ANTHROPIC_API_KEY;

const axisSchema = (enumVals) => ({
  type: "array",
  minItems: 1,
  items: {
    type: "object",
    required: ["label", "confidence", "reasoning"],
    additionalProperties: false,
    properties: {
      label: { type: "string", enum: enumVals },
      confidence: { type: "string", enum: CONFIDENCE_LEVELS,
        description: "how strongly the supplied evidence supports this label" },
      reasoning: { type: "string", description: "≤15 words, cite the observed evidence" },
    },
  },
});

const OUTPUT_TOOL = {
  name: "emit_classification",
  description: "Emit the multi-label cookie classification across all three axes.",
  input_schema: {
    type: "object",
    required: ["iab_purposes", "icc_uk_categories", "us_state_privacy_categories", "evidence_summary"],
    additionalProperties: false,
    properties: {
      iab_purposes: axisSchema(IAB_LABELS),
      icc_uk_categories: axisSchema(ICC_UK_CATEGORIES),
      us_state_privacy_categories: axisSchema(US_STATE_PRIVACY_CATEGORIES),
      evidence_summary: { type: "string", description: "1-2 sentences summarising the behavioral basis" },
    },
  },
};

const SYSTEM = `You are a privacy compliance officer. You classify a browser cookie into privacy taxonomies using ONLY the observed dynamic behavior supplied to you (from a PageGraph provenance graph of a real page load). Rules:
- Judge behavior, never the cookie's name. The name is context only.
- Every label's reasoning must cite supplied evidence (party, set channel, reads, destinations, persistence, entropy). Do not invent behavior that is not in the evidence.
- Multi-label: emit every purpose the behavior supports, each with a text confidence level — one of: low-confidence, medium-confidence, high-confidence, fully-sure. Never a number: nothing here is calibrated, so a decimal would imply a precision that does not exist.
- Use fully-sure only when the supplied evidence establishes the label on its own; high-confidence when evidence plus well-known host purpose does; medium-confidence when it is consistent and likely; low-confidence when it is possible but the evidence does not carry it.
- Purpose 1 applies to essentially every stored cookie. Special Purpose 1 fits security/fraud/session cookies.
- You MAY use world knowledge of the destination HOSTS to decide advertising vs analytics vs content personalisation (e.g. doubleclick/adnxs → advertising; google-analytics/segment → analytics). This host→purpose judgement is the main value you add over the deterministic prior.
- A deterministic behavior-only prior is provided as a starting point; keep what the evidence supports, drop what it doesn't, add host-informed purposes, and set each confidence level.
- PARTY IS NOT A PRECONDITION for a tracking/advertising determination. The test is whether the cookie was SET and then USED (read back by script, carried on requests, or passed to a JS sink). First-party server-side / CNAME-cloaked tagging keeps every flow same-site while performing identical processing — do not downgrade a purpose merely because nothing crossed a registrable-domain boundary. Party matters only for the US-state "cross-context sharing/sale" labels, where it is legally load-bearing.`;

// The compact evidence object handed to the head. Exported so the API path and
// the `--emit-payloads` path (in-session/external classification) share exactly
// one definition of "what the head gets to see".
export const buildEvidencePayload = (payload) => {
  const { name, domain, pageUrl, features, evidence, prior, signals } = payload;
  const trim = (v, n = 120) => (typeof v === "string" && v.length > n ? v.slice(0, n) + `…(${v.length} chars)` : v);
  return {
    cookie: name,
    domain,
    pageUrl,
    party: features.party,
    valuePreview: trim(evidence.value),
    valueEntropyBitsPerChar: features.valueEntropy,
    valueTotalEntropyBits: features.valueTotalEntropyBits,
    looksLikeStructuredData: features.looksLikeStructuredData,
    looksLikeIdentifier: features.looksLikeIdentifier,
    attributes: {
      httpOnly: features.httpOnly, secure: features.secure, sameSite: features.sameSite,
      session: features.session, persistent: features.persistent, expiryDays: features.expiryDays, lifetime: features.lifetime,
      partitioned: features.partitioned,
    },
    setChannel: features.setChannel,
    setterParties: features.setterParties,
    httpSetters: (evidence.set?.httpSetters || []).map((s) => ({ host: s.host, party: s.party })),
    jsWriteHosts: (evidence.set?.jsWrites || []).map((w) => ({ host: w.host, party: w.party, source: w.source })),
    readByJs: features.readByJs,
    readerHosts: features.readerHosts,
    httpTransmittedTo: (evidence.httpTransmission || []).map((t) => ({ host: t.host, party: t.party, method: t.method })),
    jsExfilFired: features.jsExfilFired,
    jsExfilDestinations: (evidence.jsExfil?.destinations || []).map((d) => ({ host: d.host, party: d.party, method: d.method, transformRound: d.round })),
    consumerMethods: features.consumerMethods,
    thirdPartyDestinations: features.thirdPartyDestinations,
    crossSiteReach: features.crossSiteReach,
    transforms: features.transforms,
    deterministicSignals: signals,
    deterministicPrior: prior,
  };
};

// The instruction block that governs the head, regardless of transport (API or
// in-session). Exported so an in-session classifier is held to the same rules.
export const HEAD_INSTRUCTIONS = SYSTEM;

const buildUserMessage = (payload) =>
  `Classify this cookie. Behavioral evidence (JSON):\n\n${JSON.stringify(buildEvidencePayload(payload), null, 2)}\n\nCall emit_classification with the refined multi-label verdict across all three axes.`;

// Build the exact Anthropic request body (exported for offline validation / dry-run).
export const buildRequestBody = (payload, model = DEFAULT_MODEL) => ({
  model,
  max_tokens: 1500,
  system: SYSTEM,
  tools: [OUTPUT_TOOL],
  tool_choice: { type: "tool", name: "emit_classification" },
  messages: [{ role: "user", content: buildUserMessage(payload) }],
});

export const classifyWithLLM = async (payload, opts = {}) => {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error("ANTHROPIC_API_KEY not set");
  const model = opts.model || DEFAULT_MODEL;

  const res = await fetch(ANTHROPIC_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify(buildRequestBody(payload, model)),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Anthropic API ${res.status}: ${body.slice(0, 300)}`);
  }
  const data = await res.json();
  const toolUse = (data.content || []).find((b) => b.type === "tool_use");
  if (!toolUse) throw new Error("no tool_use block in response");
  return { ...toolUse.input, _model: model };
};
