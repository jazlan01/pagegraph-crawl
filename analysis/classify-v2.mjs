#!/usr/bin/env node
// classify-v2.mjs — two-pass classification: identity first, then behaviour.
//
//   node analysis/classify-v2.mjs <graphml> [--provider openai|anthropic] [--out <dir>]
//                                 [--cookie <name>] [--concurrency N]
//
// WHY TWO PASSES
// The two questions a cookie audit has to answer are different, and conflating them is what
// produced every wrong label so far:
//
//   Pass A — INFERRED purpose. What is this cookie *for*, judged from its identity (name, domain,
//     value shape, attributes)? This is the question a name-corpus answers, and it is what the
//     VaultJS MCP does well. It is available even when nothing happened during the load.
//   Pass B — EXERCISED purpose. What did it actually *do* here? The head sees ONLY the name-free
//     behaviour subgraph (write/read/transmission edges, the JS taint path, redirect hops) and
//     classifies it cold. It is NOT shown the cookie name and NOT shown Pass A's verdict.
//
// The DELTA between them is the deliverable. A cookie whose inferred purpose is analytics but whose
// observed behaviour shows nothing is a different finding from one that quietly exfiltrated; the
// single-verdict design could express neither.
//
// Independence is the point: Pass A sees only identity, Pass B sees only behaviour, and neither sees
// the other. Only Pass C (pass3.mjs) — the designated reconciler — is given both, because combining
// them is its whole job. Pass A sees the cookie NAME; Pass B's subgraph never does. That is not a
// contradiction of the no-content-features rule — that rule is about what a *behavioural* classifier
// may key on. Pass A is the inference baseline, labelled as such, so a name-derived claim can never
// be mistaken for an observed one.

import { mkdirSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

import { buildEvidence } from "./lib/cookie-evidence.mjs";
import { buildGraphFeatures } from "./lib/graph-features.mjs";
import { buildBehaviourSubgraph } from "./lib/behaviour-subgraph.mjs";
import { runHead, headAvailable, providerNames } from "./lib/llm-head-chat.mjs";
import { validateVerdict } from "./lib/verdict-schema.mjs";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const graphmlPath = argv.find((a) => !a.startsWith("--") && a.endsWith(".graphml"));
if (!graphmlPath || !existsSync(graphmlPath)) {
  process.stderr.write("usage: node analysis/classify-v2.mjs <graphml> [--provider p] [--out dir]\n");
  process.exit(1);
}
const provider = flag("--provider", process.env.CLASSIFIER_PROVIDER || "openai");
if (!providerNames().includes(provider)) {
  process.stderr.write(`unknown --provider "${provider}"\n`); process.exit(1);
}
if (!headAvailable(provider)) {
  process.stderr.write(`no API key for ${provider}. This tool is head-driven; there is no ` +
    `rules-only fallback, because a two-pass run with no head is just the feature vector.\n`);
  process.exit(1);
}
const outDir = flag("--out", graphmlPath.replace(/(\.pruned)?\.graphml$/, "") + ".v2");
const onlyCookie = flag("--cookie", null);
const concurrency = Math.max(1, parseInt(flag("--concurrency", "8"), 10));
const log = (m) => process.stderr.write(m + "\n");

const SYSTEM_A = `You are a privacy compliance officer. Classify a browser cookie into privacy taxonomies from its IDENTITY ALONE — the name, the domain that holds it, the shape of its value, and its attributes. You have NOT been shown what the cookie did on the page.

- This is an INFERENCE about what the cookie is FOR, from what you know about cookie families, vendors and domains. Say what the name and domain imply.
- You may and should use world knowledge of the vendor (e.g. a cookie on doubleclick.net, a _ga* family member, an Akamai bot-management token).
- Confidence must reflect that you are working from identity only: use fully-sure sparingly, and low-confidence when the name is opaque or unfamiliar.
- If the name tells you nothing, say so with low confidence rather than inventing a purpose.`;

const SYSTEM_B = `You are a privacy compliance officer. You are shown what a single browser cookie actually did during one real page load: a name-free behaviour subgraph extracted from a provenance graph. There is no cookie name, no vendor name, and no literal cookie value in the input, by design. Never guess a name or vendor. Classify the cookie from its observed behaviour alone.

The input is a JSON object \`observedBehaviour\`. \`writeSites\` shows who set the cookie and how: \`channel\` is "js" (a JavaScript document.cookie write, with the writing \`script\`) or "set-cookie-header" (an HTTP response header). \`readers\` lists scripts that read the cookie jar — but read attribution is jar-wide: counts are shared across every cookie on the domain, so a high reader count is NOT evidence of interest in this cookie. \`transmissions\` shows requests that carried the value off the page; \`channel\` is "auto-cookie-header" (the browser attached it automatically) or "js-initiated" (page code deliberately put the value into a request). \`taintPaths\` traces value flows; \`transformRound\` > 0 means JS read and transformed the value before sending. \`redirectChains\` records hop sequences — the cookie-syncing signature. \`bodyExfil\`/\`bodyInfil\` count value appearances in request/response bodies. \`signals\` are derived flags; \`attributes\` describe shape only (party, persistence, flags, value length).

Critical rule: the browser automatically attaches a first-party cookie to every same-origin request. A transmission to a first-party host via "auto-cookie-header" — even to an analytics or measurement subdomain — only proves the PAGE made that request; every cookie on the domain rode along. Purpose evidence from a transmission requires either a THIRD-party destination (any channel) or a "js-initiated" send. When the only transmission evidence is auto-cookie-header to a same-party host, treat it as weak: assign at most low-confidence and never let it drive the verdict — but do not zero it, since one page load cannot prove a cookie harmless.

Apply these signatures. First-party set-cookie-header origin, no JS writes, no value churn, broad jar-wide reads: first-party server infrastructure (security, bot management, load balancing, session plumbing) — typically Necessary, regardless of incidental auto-attached requests. Third-party JS writes with a mutating value and an advancing embedded timestamp: client-side measurement/analytics session state, even with zero transmissions — modern analytics keeps state locally. Third-party setters or destinations, or multi-host redirect chains: cross-site tracking or cookie-syncing — typically Advertising. For transformed-then-sent values, weigh the destination host and its party, not the transform itself. Resolving setter and destination hosts to a purpose is the core of your job: a value genuinely reaching a third-party ad network is Advertising; a value the page's JS deliberately sends to a measurement endpoint is Analytics; a value that never meaningfully leaves and only supports page operation is Functional or Necessary.

Output labels on three axes: ICC/UK categories from {Necessary, Functional, Analytics, Advertising}, plus IAB TCF purposes and US state privacy categories per the fixed schema you are given. Every label carries a confidence that is TEXT, never a number — exactly one of: low-confidence, medium-confidence, high-confidence, fully-sure — and a short reasoning citing the observed behaviour. One page load is a small observation window: absence of a behaviour is not proof of absence of purpose, so lower confidence rather than silently dropping a plausible label.`;

// ---- run -------------------------------------------------------------------
log(`Stage 1: evidence (${graphmlPath})`);
const evidence = buildEvidence(graphmlPath, { log });
for (const w of evidence.warnings) log(`warning: ${w}`);
log("Stage 2: graph features");
const features = buildGraphFeatures(evidence);

let names = [...evidence.cookies.keys()];
if (onlyCookie) {
  // Accept a single name or a comma-separated slice, so a whole validation slice runs off ONE
  // evidence build instead of re-streaming a multi-GB graph per cookie.
  const wanted = onlyCookie.split(",").map((s) => s.trim()).filter(Boolean);
  const missing = wanted.filter((n) => !features.has(n));
  if (missing.length) log(`  (not in inventory, skipped: ${missing.join(", ")})`);
  names = wanted.filter((n) => features.has(n));
  if (!names.length) { log(`none of the requested cookies are in inventory`); process.exit(2); }
}
log(`Stage 3: two-pass head over ${names.length} cookie(s) via ${provider}`);

const pool = async (items, n, fn) => {
  const out = new Array(items.length);
  let i = 0;
  const worker = async () => {
    while (i < items.length) {
      const idx = i++;
      // Isolate per item: one cookie's failure must not cost the rest of the site.
      try { out[idx] = await fn(items[idx], idx); }
      catch (e) { out[idx] = { __failed: true, name: items[idx], error: String(e?.message ?? e) }; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
};

const labelSet = (v) => new Set((v?.icc_uk_categories || []).map((x) => x.label));
const same = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));

const classifyOne = async (name) => {
  const ev = evidence.cookies.get(name);
  const f = features.get(name);

  // Pass A: identity only. Deliberately includes the name — this is the inference baseline.
  const a = await runHead(SYSTEM_A, {
    cookie: name,
    domain: ev.domain,
    valuePreview: (ev.value || "").slice(0, 80),
    valueLength: (ev.value || "").length,
    attributes: ev.attributes,
  }, { provider });
  const va = validateVerdict(name, a);

  // Pass B: behaviour ONLY. It is given the name-free behaviour subgraph and NOTHING from Pass A —
  // no prior verdict, no name, no identity. A and B are independent siblings; only Pass C sees both.
  const b = await runHead(SYSTEM_B, {
    observedBehaviour: buildBehaviourSubgraph(ev, f),
  }, { provider });
  const vb = validateVerdict(name, b);

  const A = labelSet(va.ok ? va.verdict : a);
  const B = labelSet(vb.ok ? vb.verdict : b);
  return {
    cookie: name,
    domain: ev.domain,
    provider,
    model: b._model,
    serviceTier: b._serviceTier ?? null,
    inferred: { ...(va.ok ? va.verdict : a), _valid: va.ok, _errors: va.errors },
    exercised: { ...(vb.ok ? vb.verdict : b), _valid: vb.ok, _errors: vb.errors },
    delta: {
      changed: !same(A, B),
      inferredOnly: [...A].filter((x) => !B.has(x)),
      exercisedOnly: [...B].filter((x) => !A.has(x)),
    },
    usage: { passA: a._usage ?? null, passB: b._usage ?? null },
    features: f,
    // The exact name-free payload Pass B received. Persisted so the report can render the real graph
    // edges (channel/party per transmission) as evidence without re-streaming the graph.
    behaviourSubgraph: buildBehaviourSubgraph(ev, f),
  };
};

const sumUsage = (records, pick) => {
  const t = { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0, calls: 0 };
  for (const r of records) {
    const u = pick(r);
    if (!u) continue;
    t.prompt_tokens += u.prompt_tokens ?? 0;
    t.completion_tokens += u.completion_tokens ?? 0;
    t.total_tokens += u.total_tokens ?? 0;
    t.calls += 1;
  }
  return t;
};

const results = await pool(names, concurrency, classifyOne);
const failures = results.filter((r) => r?.__failed);
const ok = results.filter((r) => r && !r.__failed);
for (const f of failures) log(`  ! FAILED ${f.name}: ${f.error}`);

mkdirSync(outDir, { recursive: true });
for (const r of ok) {
  writeFileSync(join(outDir, `${r.cookie.replace(/[^\w.-]/g, "_")}.json`), JSON.stringify(r, null, 2));
}
const changed = ok.filter((r) => r.delta.changed);
writeFileSync(join(outDir, "_index.json"), JSON.stringify({
  pageUrl: evidence.pageUrl,
  generated: new Date().toISOString().slice(0, 10),
  provider, model: ok[0]?.model ?? null,
  counts: { cookies: ok.length, failed: failures.length, changedByBehaviour: changed.length },
  usage: {
    passA: sumUsage(ok, (r) => r.usage?.passA),
    passB: sumUsage(ok, (r) => r.usage?.passB),
  },
  warnings: evidence.warnings,
  items: ok.map((r) => ({
    cookie: r.cookie,
    inferred: [...labelSet(r.inferred)],
    exercised: [...labelSet(r.exercised)],
    changed: r.delta.changed,
  })),
}, null, 2));

log(`\n=== ${ok.length} cookie(s) → ${outDir}`);
log(`behaviour changed the verdict on ${changed.length} of ${ok.length}`);
for (const r of changed.slice(0, 15)) {
  log(`  ${r.cookie.slice(0, 28).padEnd(29)} ${[...labelSet(r.inferred)].join("+") || "(none)"}` +
      `  ->  ${[...labelSet(r.exercised)].join("+") || "(none)"}`);
}
