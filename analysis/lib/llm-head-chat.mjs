// llm-head-chat.mjs — ONE head, two providers, one wire format.
//
// Both OpenAI and Anthropic serve an OpenAI-shaped `/v1/chat/completions` with `Authorization:
// Bearer`, strict `response_format: json_schema`, and the same message shape. So the provider is
// nothing but a base URL, a key and a model — not a second code path. That matters for the
// benchmark this feeds: if the two heads had separate clients, a provider comparison would
// quietly become a comparison of two prompts and two schemas.
//
// Verified live before this was written, not assumed:
//   * Anthropic does NOT serve `/v1/responses` — 404 under both Bearer and x-api-key auth.
//     It does serve `/v1/chat/completions`. That is why this file targets chat/completions.
//   * OpenAI `gpt-5.6-luna` + `service_tier: "flex"` is accepted and echoed back as "flex".
//   * Strict `json_schema` returns a schema-valid object on both.
//
// CONFIDENCE IS TEXT. The head is asked for one of four words, never a probability. A decimal
// implies a calibration nothing here has, and invites readers to compare numbers that were never
// comparable. The four levels are ordered and are the entire vocabulary.

import {
  IAB_LABELS,
  ICC_UK_CATEGORIES,
  US_STATE_PRIVACY_CATEGORIES,
  CONFIDENCE_LEVELS,
} from "./tcf-taxonomy.mjs";
import { HEAD_INSTRUCTIONS, buildEvidencePayload } from "./llm-head.mjs";

const PROVIDERS = {
  openai: {
    url: "https://api.openai.com/v1/chat/completions",
    keys: ["OPENAI_API_KEY", "OPENAI_KEY"],
    defaultModel: "gpt-5.6-luna",
    // Flex: materially cheaper, higher latency, can 429 while waiting for capacity.
    extra: () => ({ service_tier: process.env.CLASSIFIER_SERVICE_TIER || "flex" }),
  },
  anthropic: {
    url: "https://api.anthropic.com/v1/chat/completions",
    keys: ["ANTHROPIC_API_KEY", "ANTHROPIC_KEY"],
    defaultModel: "claude-sonnet-5",
    extra: () => ({}),
  },
};

const keyFor = (p) => {
  const cfg = PROVIDERS[p];
  if (!cfg) return null;
  for (const k of cfg.keys) if (process.env[k]) return process.env[k];
  return null;
};

export const providerNames = () => Object.keys(PROVIDERS);
export const headAvailable = (p) => !!keyFor(p);
export const defaultModelFor = (p) => PROVIDERS[p]?.defaultModel ?? null;

// strict mode requires every property listed in `required` and additionalProperties:false at
// every level; an optional field makes the API reject the schema outright.
const axisSchema = (enumVals) => ({
  type: "array",
  items: {
    type: "object",
    required: ["label", "confidence", "reasoning"],
    additionalProperties: false,
    properties: {
      label: { type: "string", enum: enumVals },
      confidence: {
        type: "string",
        enum: CONFIDENCE_LEVELS,
        description:
          "How strongly the supplied evidence supports this label. " +
          "fully-sure = the evidence establishes it; high-confidence = evidence plus " +
          "well-known host purpose; medium-confidence = consistent and likely; " +
          "low-confidence = possible but the evidence does not carry it.",
      },
      reasoning: { type: "string", description: "≤15 words, cite the observed evidence" },
    },
  },
});

const RESPONSE_FORMAT = {
  type: "json_schema",
  json_schema: {
    name: "cookie_classification",
    strict: true,
    schema: {
      type: "object",
      required: [
        "iab_purposes",
        "icc_uk_categories",
        "us_state_privacy_categories",
        "evidence_summary",
      ],
      additionalProperties: false,
      properties: {
        iab_purposes: axisSchema(IAB_LABELS),
        icc_uk_categories: axisSchema(ICC_UK_CATEGORIES),
        us_state_privacy_categories: axisSchema(US_STATE_PRIVACY_CATEGORIES),
        evidence_summary: {
          type: "string",
          description: "1-2 sentences summarising the behavioral basis",
        },
      },
    },
  },
};

export const buildRequestBodyChat = (payload, provider = "openai", model) => {
  const cfg = PROVIDERS[provider];
  if (!cfg) throw new Error(`unknown provider "${provider}"`);
  return {
    model: model || process.env.CLASSIFIER_MODEL || cfg.defaultModel,
    messages: [
      { role: "system", content: HEAD_INSTRUCTIONS },
      { role: "user", content: JSON.stringify(buildEvidencePayload(payload)) },
    ],
    // Reasoning models can spend the whole budget before emitting the message, which surfaces as
    // an empty choice rather than an error. Headroom is cheaper than a retry.
    max_completion_tokens: 4000,
    response_format: RESPONSE_FORMAT,
    ...cfg.extra(),
  };
};

/**
 * Run the head over an arbitrary system + user message, returning a schema-valid verdict.
 *
 * `classifyWithChat` below always sends the standard evidence payload; the two-pass classifier
 * needs to send something different on each pass (identity only, then features + the pass-1
 * verdict), so the transport is exposed separately rather than duplicated there.
 */
export const runHead = async (system, user, opts = {}) => {
  const provider = opts.provider || "openai";
  const cfg = PROVIDERS[provider];
  if (!cfg) throw new Error(`unknown provider "${provider}"`);
  const apiKey = keyFor(provider);
  if (!apiKey) throw new Error(`no API key for ${provider} (tried ${cfg.keys.join(", ")})`);
  const body = {
    model: opts.model || process.env.CLASSIFIER_MODEL || cfg.defaultModel,
    messages: [
      { role: "system", content: system },
      { role: "user", content: typeof user === "string" ? user : JSON.stringify(user) },
    ],
    max_completion_tokens: 4000,
    response_format: RESPONSE_FORMAT,
    ...cfg.extra(),
  };
  return postAndParse(cfg, apiKey, body, provider);
};

// Shared transport: one patient retry on 429/5xx (flex queues), then surrender so the caller can
// fall back with the reason recorded.
const postAndParse = async (cfg, apiKey, body, provider) => {
  let lastErr = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const res = await fetch(cfg.url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body),
    });
    if (res.status === 429 || res.status >= 500) {
      lastErr = new Error(`${provider} ${res.status}: ${(await res.text()).slice(0, 200)}`);
      if (attempt === 0) { await new Promise(r => setTimeout(r, 20_000)); continue; }
      throw lastErr;
    }
    if (!res.ok) throw new Error(`${provider} ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const data = await res.json();
    if (data.error) throw new Error(`${provider} error: ${JSON.stringify(data.error).slice(0, 300)}`);
    const text = data.choices?.[0]?.message?.content;
    if (!text) {
      throw new Error(`${provider} returned no message content` +
        `${data.choices?.[0]?.finish_reason ? ` (finish_reason: ${data.choices[0].finish_reason})` : ""}`);
    }
    return {
      ...JSON.parse(text),
      _model: data.model ?? body.model,
      _serviceTier: data.service_tier ?? body.service_tier ?? null,
      _provider: provider,
      // Usage is the only way to price a run after the fact; the API returns it and we were
      // throwing it away. Keep the raw block so callers can sum tokens per run.
      _usage: data.usage ?? null,
    };
  }
  throw lastErr ?? new Error(`${provider} request failed`);
};

export const classifyWithChat = async (payload, opts = {}) => {
  const provider = opts.provider || "openai";
  const cfg = PROVIDERS[provider];
  if (!cfg) throw new Error(`unknown provider "${provider}"`);
  const apiKey = keyFor(provider);
  if (!apiKey) throw new Error(`no API key for ${provider} (tried ${cfg.keys.join(", ")})`);

  const body = buildRequestBodyChat(payload, provider, opts.model);
  return postAndParse(cfg, apiKey, body, provider);
};

