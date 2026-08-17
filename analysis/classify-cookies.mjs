#!/usr/bin/env node
// classify-cookies.mjs — independent, behavior-only multi-label cookie classifier.
//
// Reads a crawl's PageGraph .graphml + its cookie sidecars, derives per-cookie
// behavioral evidence (Stage 1), a deterministic feature vector (Stage 2) and an
// auditable rule prior (Stage 3), then (Stage 4) refines each into the final
// three-axis multi-label verdict via an LLM head. Independent of the VaultJS
// classification MCP; classifies from OBSERVED behavior, never the cookie name.
//
//   node analysis/classify-cookies.mjs <graphml> [options]
//
// Options:
//   --rules-only         skip the LLM; emit the deterministic prior as the verdict
//   --cookie <name>      classify a single cookie (fast dev loop)
//   --out <dir>          write per-cookie JSON + _index.json here (default: <base>.classification/)
//   --stdout             also print the full result to stdout
//   --declared <file>    JSON map {cookieName: ["Necessary"|"Advertising"|...]} of vendor-declared
//                        labels; emits a divergence verdict (litigation exposure)
//   --concurrency <n>    parallel LLM calls (default 5)
//   --model <id>         override the LLM model (else CLASSIFIER_MODEL or default)
//
// Env: ANTHROPIC_API_KEY enables the LLM head; without it the tool runs rules-only.

import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { buildEvidence, deriveBase } from "./lib/cookie-evidence.mjs";
import { extractFeatures } from "./lib/cookie-features.mjs";
import { rulePrior } from "./lib/tcf-rules.mjs";
import { buildEvidencePayload, HEAD_INSTRUCTIONS } from "./lib/llm-head.mjs";
import { classifyWithChat, headAvailable as chatHeadAvailable, providerNames, buildRequestBodyChat } from "./lib/llm-head-chat.mjs";
import { confidenceRank } from "./lib/tcf-taxonomy.mjs";

// A label counts as asserted at medium-confidence or better. This is the same judgement the old
// `probability >= 0.5` cut expressed, minus the false precision of a decimal.
const asserted = (l) => confidenceRank(l.confidence) >= confidenceRank("medium-confidence");
import { validateVerdict } from "./lib/verdict-schema.mjs";

// ---- args -------------------------------------------------------------------
const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const has = (n) => argv.includes(n);
const graphmlPath = argv.find((a) => !a.startsWith("--") && (a.endsWith(".graphml")));
if (!graphmlPath) {
  process.stderr.write("usage: node analysis/classify-cookies.mjs <graphml> [--rules-only] [--cookie <name>] [--out <dir>] [--declared <file>] [--concurrency <n>] [--model <id>] [--stdout]\n");
  process.exit(1);
}
const onlyCookie = flag("--cookie", null);
const outDir = flag("--out", `${deriveBase(graphmlPath)}.classification`);
const declaredPath = flag("--declared", null);
const concurrency = Math.max(1, parseInt(flag("--concurrency", "5"), 10));
const model = flag("--model", null);
const dryRun = has("--dry-run"); // build LLM requests, don't send; write them to <out>/requests
// Pluggable head: --emit-payloads writes the evidence bundles for an external or
// in-session classifier; --verdicts ingests that classifier's answers back.
const emitPayloads = has("--emit-payloads") ? flag("--emit-payloads", null) : null;
const verdictsPath = flag("--verdicts", null);
const headTag = flag("--head-tag", "external");
const verdicts = verdictsPath ? JSON.parse(readFileSync(verdictsPath, "utf8")) : null;
// Which head runs. Explicit --provider wins; otherwise pick whichever key is present, so a
// missing key degrades to rules-only loudly (logged below) rather than silently.
const provider = flag("--provider", process.env.CLASSIFIER_PROVIDER
  || (chatHeadAvailable("openai") ? "openai" : "anthropic"));
if (!providerNames().includes(provider)) {
  process.stderr.write(`unknown --provider "${provider}" (expected: ${providerNames().join(", ")})\n`);
  process.exit(1);
}
const hasHead = chatHeadAvailable(provider);
const rulesOnly = has("--rules-only") || (!hasHead && !dryRun && !verdicts);
const log = (m) => process.stderr.write(m + "\n");

if (has("--rules-only")) log("mode: rules-only (LLM disabled by flag)");
else if (rulesOnly && !dryRun && !verdicts) {
  log(`mode: rules-only — no API key found for provider "${provider}" ` +
      `(set OPENAI_API_KEY/OPENAI_KEY or ANTHROPIC_API_KEY). The deterministic prior is NOT an ` +
      `LLM verdict; do not read it as one.`);
} else if (!dryRun && !verdicts) log(`head: ${provider}`);

else log(`mode: hybrid (rules prior + LLM head, model ${model || process.env.CLASSIFIER_MODEL || "default"})`);

const declared = declaredPath ? JSON.parse(readFileSync(declaredPath, "utf8")) : null;

// ---- divergence: does observed behavior exceed the declared label? ----------
const TRACKING_ICC = new Set(["Analytics", "Advertising"]);
const normDeclared = (labels) => new Set((labels || []).map((l) => {
  const s = String(l).toLowerCase();
  if (/necess|essential|strict/.test(s)) return "Necessary";
  if (/function|prefer/.test(s)) return "Functional";
  if (/analyt|perform|statist|measure/.test(s)) return "Analytics";
  if (/advert|market|target|ad\b/.test(s)) return "Advertising";
  return String(l);
}));
const computeDivergence = (name, verdict) => {
  if (!declared || !(name in declared)) return null;
  const decl = normDeclared(declared[name]);
  const observed = new Set(verdict.icc_uk_categories.filter(asserted).map((l) => l.label));
  const observedTracking = [...observed].some((l) => TRACKING_ICC.has(l));
  const declaredTracking = [...decl].some((l) => TRACKING_ICC.has(l));
  let status = "consistent";
  if (observedTracking && !declaredTracking) status = "under-declared"; // behavior exceeds declaration (exposure)
  else if (!observedTracking && declaredTracking) status = "over-declared";
  return {
    declared: [...decl],
    observed: [...observed],
    status,
    detail: status === "under-declared"
      ? "Observed tracking/advertising behavior not covered by the declared label — litigation exposure."
      : status === "over-declared"
        ? "Declared as tracking/advertising but no such behavior observed in this crawl."
        : "Declared label consistent with observed behavior.",
  };
};

// ---- classify one cookie ----------------------------------------------------
const classifyOne = async (ev, ctx) => {
  const features = extractFeatures(ev, ctx);
  const { prior, signals, flags } = rulePrior(features, ev);

  let classification;
  let source;
  const payload = { name: ev.name, domain: ev.domain, pageUrl: ctx.pageUrl, features, evidence: ev, prior, signals };
  if (verdicts) {
    // A head classified this out-of-band (in-session agent, another provider, …).
    const raw = verdicts[ev.name];
    if (!raw) {
      log(`  ! no verdict supplied for ${ev.name} — using rules prior`);
      classification = { ...prior, evidence_summary: signals.join(" ") };
      source = "rules(no-verdict)";
    } else {
      const { ok, errors, verdict } = validateVerdict(ev.name, raw);
      if (!ok) { for (const e of errors) log(`  ! ${e}`); }
      const usable = ok || Object.keys(verdict).some((a) => Array.isArray(verdict[a]) && verdict[a].length);
      if (usable) {
        classification = { ...prior, ...verdict, evidence_summary: verdict.evidence_summary || signals.join(" ") };
        source = `llm:${headTag}${ok ? "" : "(partial)"}`;
      } else {
        classification = { ...prior, evidence_summary: signals.join(" ") };
        source = "rules(verdict-invalid)";
      }
    }
  } else if (dryRun) {
    mkdirSync(join(outDir, "requests"), { recursive: true });
    writeFileSync(join(outDir, "requests", `${ev.name.replace(/[^\w.-]/g, "_")}.request.json`), JSON.stringify(buildRequestBodyChat(payload, provider, model || undefined), null, 2));
    classification = { ...prior, evidence_summary: signals.join(" ") };
    source = "dry-run(rules-prior)";
  } else if (rulesOnly) {
    classification = { ...prior, evidence_summary: signals.join(" ") };
    source = "rules";
  } else {
    try {
      // One client for both providers — they differ only by base URL, key and model.
      const llm = await classifyWithChat(payload, { provider, model });
      classification = {
        iab_purposes: llm.iab_purposes,
        icc_uk_categories: llm.icc_uk_categories,
        us_state_privacy_categories: llm.us_state_privacy_categories,
        evidence_summary: llm.evidence_summary,
      };
      source = `llm:${llm._model}${llm._serviceTier ? `/${llm._serviceTier}` : ""}`;
    } catch (e) {
      log(`  ! LLM failed for ${ev.name}: ${String(e.message).split("\n")[0]} — falling back to rules`);
      classification = { ...prior, evidence_summary: signals.join(" ") };
      source = "rules(fallback)";
    }
  }

  const verdict = {
    cookie: ev.name,
    domain: ev.domain,
    party: features.party,
    pageUrl: ctx.pageUrl,
    source,
    classification,
    flags,
    signals,
    rulePrior: prior,
    evidence: {
      value: ev.value,
      attributes: ev.attributes,
      setChannel: features.setChannel,
      setters: { http: ev.set.httpSetters, js: ev.set.jsWrites },
      readByJs: features.readByJs,
      readerHosts: features.readerHosts,
      httpTransmission: ev.httpTransmission,
      jsExfil: ev.jsExfil,
      thirdPartyDestinations: features.thirdPartyDestinations,
      crossSiteReach: features.crossSiteReach,
      valueEntropy: features.valueEntropy,
      looksLikeIdentifier: features.looksLikeIdentifier,
      transforms: features.transforms,
      deletes: ev.deletes,
    },
    divergence: null,
  };
  verdict.divergence = computeDivergence(ev.name, classification);
  return verdict;
};

// ---- simple concurrency pool ------------------------------------------------
const pool = async (items, n, fn) => {
  const out = new Array(items.length);
  let i = 0;
  const worker = async () => {
    while (i < items.length) {
      const idx = i++;
      // Isolate per item. A single cookie that throws should cost that cookie, not the other 52:
      // Promise.all rejects on the first failure, so an unguarded throw here loses the whole run.
      try {
        out[idx] = await fn(items[idx], idx);
      } catch (e) {
        out[idx] = { __failed: true, index: idx, error: String(e?.message ?? e) };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
};

// ---- main -------------------------------------------------------------------
const { pageUrl, pageRegDomain, referenceEpochSec, cookies, warnings, inventoryCount } = buildEvidence(graphmlPath, { log });
for (const w of warnings) log(`warning: ${w}`);
const ctx = { pageUrl, pageRegDomain, referenceEpochSec };

let names = [...cookies.keys()];
if (onlyCookie) {
  if (!cookies.has(onlyCookie)) { log(`cookie not found in inventory: ${onlyCookie}`); process.exit(2); }
  names = [onlyCookie];
}
// ---- --emit-payloads: dump evidence bundles for an external/in-session head --
if (emitPayloads) {
  mkdirSync(emitPayloads, { recursive: true });
  const bundles = {};
  for (const name of names) {
    const ev = cookies.get(name);
    const features = extractFeatures(ev, ctx);
    const { prior, signals } = rulePrior(features, ev);
    bundles[name] = buildEvidencePayload({ name, domain: ev.domain, pageUrl, features, evidence: ev, prior, signals });
  }
  writeFileSync(join(emitPayloads, "_payloads.json"), JSON.stringify({ pageUrl, pageRegDomain, instructions: HEAD_INSTRUCTIONS, cookies: bundles }, null, 2));
  log(`wrote ${names.length} evidence payload(s) → ${join(emitPayloads, "_payloads.json")}`);
  log(`next: classify them, then re-run with --verdicts <file> --head-tag <name>`);
  process.exit(0);
}

log(`Stage 2-4: classifying ${names.length} cookie(s) (inventory=${inventoryCount}, page=${pageUrl})`);

const rawResults = await pool(names.map((n) => cookies.get(n)), rulesOnly ? 32 : concurrency, (ev) => classifyOne(ev, ctx));
// Per-cookie failures are isolated by the pool. Report them loudly and by name: a cookie missing
// from the output is otherwise indistinguishable from a cookie that was never in the inventory.
const failures = rawResults
  .map((r, i) => (r && r.__failed ? { cookie: names[i], error: r.error } : null))
  .filter(Boolean);
const results = rawResults.filter((r) => r && !r.__failed);
for (const f of failures) log(`  ! FAILED ${f.cookie}: ${f.error}`);
if (failures.length) log(`${failures.length} of ${names.length} cookie(s) failed and are absent from the output`);

// ---- write output -----------------------------------------------------------
mkdirSync(outDir, { recursive: true });
const index = [];
for (const r of results) {
  const safe = r.cookie.replace(/[^\w.-]/g, "_");
  writeFileSync(join(outDir, `${safe}.json`), JSON.stringify(r, null, 2));
  index.push({
    cookie: r.cookie,
    domain: r.domain,
    party: r.party,
    source: r.source,
    iab_top: r.classification.iab_purposes.slice(0, 4).map((l) => `${l.label.replace(/ -.*/, "")}(${l.confidence})`),
    icc: r.classification.icc_uk_categories.filter(asserted).map((l) => l.label),
    tracking: r.flags.trackingObserved,
    crossSiteReach: r.flags.crossSiteReach,
    divergence: r.divergence?.status || null,
  });
}
const summary = { pageUrl, pageRegDomain, cookieCount: results.length, mode: rulesOnly ? "rules-only" : "hybrid", warnings, index };
writeFileSync(join(outDir, "_index.json"), JSON.stringify(summary, null, 2));

// ---- console summary --------------------------------------------------------
log("");
log(`=== classification summary (${results.length} cookies) → ${outDir} ===`);
for (const e of index) {
  const flags = [e.party === "third" ? "3P" : "1P", e.tracking ? "TRACK" : "", e.crossSiteReach ? `x-site:${e.crossSiteReach}` : "", e.divergence === "under-declared" ? "⚠UNDER-DECLARED" : ""].filter(Boolean).join(" ");
  log(`  ${e.cookie.padEnd(26)} ${flags.padEnd(24)} icc=[${e.icc.join(",")}]  iab=${e.iab_top.join(" ")}`);
}
if (has("--stdout")) process.stdout.write(JSON.stringify(onlyCookie ? results[0] : summary, null, 2) + "\n");
