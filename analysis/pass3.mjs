#!/usr/bin/env node
// pass3.mjs — the reconciliation pass: identity AND behaviour, together.
//
//   node analysis/pass3.mjs <classify-v2 dir>... [--provider openai] [--concurrency 8]
//
// WHY A THIRD PASS
// Measured over 246 cookies on 8 sites, Pass B (behaviour, name-blind) scored 52.0% against the
// name-corpus bar while Pass A (identity) scored 58.1%. The deficit was entirely in the categories
// where meaning is SEMANTIC rather than behavioural:
//
//     consent record   A 77.8%  ->  B 44.4%
//     auth / session   A 55.6%  ->  B 38.9%
//     bot-defence/WAF  A 97.9%  ->  B 83.3%
//     other            A 44.4%  ->  B 45.1%   (behaviour neither helps nor hurts)
//
// A store-locator cookie is Necessary because of what it MEANS; `STORELOCATION`, `C_LOC` and
// `WAREHOUSEDELIVERY_WHS` all got demoted to Functional because behaviour cannot see intent. A WAF
// token looks exactly like a tracker — high entropy, rewritten 11 times a load, sent on every
// request — and is Necessary for a reason no feature vector contains.
//
// But Pass B is not useless: on 4 cookies it asserted Advertising the name-corpus missed, each
// backed by an OBSERVED transmission to an ad host (`_ga` reaching ad endpoints is the textbook
// case a name corpus structurally cannot catch).
//
// So the passes have asymmetric authority, and this pass encodes that rather than asking a model
// to re-decide from scratch a third time:
//   * identity is authoritative for SEMANTIC categories (security, consent, auth, infrastructure);
//   * behaviour is authoritative for ADDING a purpose it observed;
//   * behaviour may NOT remove a purpose merely because one page load showed nothing.
//
// Reuses the stored Pass A and Pass B verdicts so those are byte-identical to the run they were
// measured in — re-running them would confound the comparison with model nondeterminism.

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { isGraphPath } from "./lib/graph-source.mjs";
import { basename, join } from "node:path";

import { runHead, headAvailable, providerNames } from "./lib/llm-head-chat.mjs";
import { validateVerdict } from "./lib/verdict-schema.mjs";
import { buildEvidence } from "./lib/cookie-evidence.mjs";
import { buildGraphFeatures } from "./lib/graph-features.mjs";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const dirs = argv.filter((a) => !a.startsWith("--") && existsSync(a));
const provider = flag("--provider", process.env.CLASSIFIER_PROVIDER || "openai");
const concurrency = Math.max(1, parseInt(flag("--concurrency", "8"), 10));
if (!dirs.length) { process.stderr.write("usage: node analysis/pass3.mjs <classify-v2 dir>...\n"); process.exit(1); }
if (!providerNames().includes(provider) || !headAvailable(provider)) {
  process.stderr.write(`no usable provider "${provider}"\n`); process.exit(1);
}
const log = (m) => process.stderr.write(m + "\n");

const SYSTEM_C = `You are a privacy compliance officer producing the FINAL classification of a browser cookie. You are given three things: the cookie's identity (name, domain, value shape), the observed behaviour from one real page load, and two earlier verdicts — one made from identity alone, one made from behaviour alone.

Your job is to reconcile them. The two sources have DIFFERENT authority, and this is the whole point of this pass:

1. IDENTITY IS AUTHORITATIVE FOR SEMANTIC CATEGORIES. If the name and domain identify a security / bot-defence / WAF token, a consent record, an authentication or session cookie, or site infrastructure (load balancing, geo/store selection, locale), then it is Necessary — regardless of how active it looks. These cookies are indistinguishable from trackers behaviourally: a bot-management token is a high-entropy identifier, rewritten many times per load, sent on every request. That activity is its function, not evidence of tracking. Labelling a firewall cookie Advertising or Analytics is indefensible.

2. BEHAVIOUR MAY ADD A PURPOSE ONLY ON OBSERVED THIRD-PARTY TRANSMISSION. You may add a purpose that identity did not suggest ONLY when the feature vector shows the value actually left to a third party — a non-empty thirdPartyExfilDestinations, a bodyExfil to a third-party host, or a transformedThenSent to one. Name the host you are relying on in your reasoning.
   Activity alone is NOT sufficient and never has been: write churn, value rotation, high entropy, long life and being carried on many requests are all normal for security infrastructure. Adding Analytics to a bot-defence token because it was rewritten eleven times is the single most damaging error this system makes, and rule 1 outranks this rule when they conflict.
   The TRANSMISSION CHANNEL decides whether a transmission is evidence. The browser attaches a cookie to the Cookie: header of matching requests automatically; a value carried to a first-party or same-organisation host (e.g. a measurement subdomain of the same company) purely by that automatic header is NOT deliberate exfiltration and does NOT add a purpose — every cookie on the domain rides those requests. To ADD a purpose you need EITHER a value the page's JS deliberately placed into a request (a js-initiated send / transformedThenSent / bodyExfil) OR carriage to a genuinely unrelated third-party ad or analytics network. Do not add Analytics to a security/infrastructure token because its value appeared, via the automatic header, at the site's own analytics endpoint.
   A cookie whose name reads "analytics" but whose value demonstrably reached an ad network is doing both — that is the case a name corpus structurally cannot see, and it must survive into your answer.

3. BEHAVIOUR MAY NOT REMOVE A PURPOSE. One page load is a small window. "Nothing was observed" is not evidence that a cookie does nothing — modern analytics keeps state client-side and transmits separately, and server-side measurement is invisible from the browser entirely. Where identity indicates a purpose and behaviour simply did not exercise it, KEEP the label and lower its confidence. Do not silently drop it, and never substitute Necessary for "nothing seen" — Necessary is a positive claim that the cookie is strictly required, not a residual bin.

USE YOUR WORLD KNOWLEDGE on the concrete artefacts you are given, not just the aggregate counts:
   * the cookie NAME and domain — the family it belongs to and the vendor that owns it;
   * setBy.scripts — the actual script URLs. A path identifies a product ("/gtag/js?id=G-…" is GA4, "/ruxitagentjs…" is Dynatrace RUM, an Akamai bot-manager path is security);
   * networkChain.redirectChain — a hop sequence like "dpm.demdex.net(302) -> match.adsrvr.org(200)" is a cookie-sync partnership between two ad platforms;
   * networkChain.exfilDestinations / thirdPartyExfilDestinations — who actually received the value.
   Resolving these to vendors and purposes is the judgement you add that neither the feature vector nor a name lookup can supply alone.

State in evidence_summary which source decided each label, and name any conflict you resolved. Confidence is text, never a number.`;

const pool = async (items, n, fn) => {
  const out = new Array(items.length);
  let i = 0;
  const worker = async () => {
    while (i < items.length) {
      const idx = i++;
      try { out[idx] = await fn(items[idx], idx); }
      catch (e) { out[idx] = { __failed: true, item: items[idx], error: String(e?.message ?? e) }; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
};

// Optionally re-derive the feature vector before reconciling. Features are deterministic, so
// refreshing them is safe and cheap-ish (one graph pass per site); the Pass A and Pass B VERDICTS
// are deliberately left untouched, because re-running a model would confound any comparison with
// its own nondeterminism.
const crawlRoot = flag("--crawl-root", null);
const refreshed = new Map();
const refreshFeatures = (site) => {
  if (!crawlRoot) return null;
  if (refreshed.has(site)) return refreshed.get(site);
  const dir = join(crawlRoot, site);
  let F = null;
  try {
    const g = readdirSync(dir).find((x) => isGraphPath(x));
    if (g) {
      log(`  re-deriving features for ${site}`);
      F = buildGraphFeatures(buildEvidence(join(dir, g), { log: () => {} }));
    }
  } catch (e) { log(`  ! could not refresh ${site}: ${String(e.message).split("\n")[0]}`); }
  refreshed.set(site, F);
  return F;
};

// Gather every stored two-pass result.
const jobs = [];
for (const dir of dirs) {
  const site = basename(dir).replace(/^classify-v2-/, "");
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".json") || f === "_index.json") continue;
    jobs.push({ dir, site, file: join(dir, f) });
  }
}
log(`pass 3 over ${jobs.length} cookie(s) via ${provider}`);

const labels = (v) => new Set((v?.icc_uk_categories || []).map((x) => x.label));
const same = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));

const results = await pool(jobs, concurrency, async (job) => {
  const d = JSON.parse(readFileSync(job.file, "utf8"));
  const F = refreshFeatures(job.site);
  if (F?.has(d.cookie)) d.features = F.get(d.cookie);

  // COMPACT PAYLOAD. Per-cookie cost matters: this runs once per cookie per site, and the naive
  // version measured ~1,094 tokens each (~301k for 275 cookies) — mostly the setBy/networkChain
  // blocks duplicating fields already in the vector, plus per-label reasoning in the two priors
  // that this pass does not need. Sending the labels alone preserves the decision without the prose.
  const slim = (v) => (v?.icc_uk_categories || []).map((x) => `${x.label}:${x.confidence}`);
  const slimTcf = (v) => (v?.iab_purposes || []).map((x) => `${x.label.split(" - ")[0]}:${x.confidence}`);
  const f = d.features || {};
  // Only the fields that carry signal; booleans that are false and counts that are zero say
  // nothing a model needs and cost tokens on every cookie.
  const nz = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) =>
    v !== false && v !== 0 && v !== null && !(Array.isArray(v) && !v.length)));

  const c = await runHead(SYSTEM_C, {
    identity: { cookie: d.cookie, domain: d.domain, valueLength: f.valueLength },
    setBy: nz({ scripts: f.settingScripts, hosts: f.setterHosts, channel: f.setChannels,
                party: f.setterParties, redirected: f.setterRedirected }),
    networkChain: nz({ redirectChain: f.redirectChain, thirdPartyExfil: f.thirdPartyExfilDestinations,
                       exfil: f.exfilDestinations, infilFrom: f.infilSourceHosts }),
    behaviour: nz({
      writes: f.writeCount, deletes: f.deleteCount, distinctValues: f.distinctWriteValues,
      valueMutated: f.valueMutated, refreshedSameValue: f.refreshedWithSameValue,
      clockAdvanced: f.embeddedTimestampAdvanced, httpSets: f.httpSetCount,
      carriedOnRequests: f.cookieHeaderRequests, urlParamExfil: f.urlParamExfil,
      headerExfil: f.requestHeaderExfil, bodyExfil: f.bodyExfil, bodyInfil: f.bodyInfil,
      transformedThenSent: f.transformedThenSent, writers: f.writerCount,
      maxCookiesPerWriter: f.maxCookiesPerWriter, setterCollectsOtherCookies: f.setterAlsoEndpointForOtherCookies,
      readerShareOfPage: f.readerShareOfPage, persistent: f.persistent, httpOnly: f.httpOnly,
      party: f.party,
    }),
    verdictFromIdentityAlone: { icc: slim(d.inferred), tcf: slimTcf(d.inferred) },
    verdictFromBehaviourAlone: { icc: slim(d.exercised), tcf: slimTcf(d.exercised) },
  }, { provider });
  const v = validateVerdict(d.cookie, c);

  d.final = { ...(v.ok ? v.verdict : c), _valid: v.ok, _errors: v.errors };
  d.usage = { ...(d.usage || {}), passC: c._usage ?? null };
  const A = labels(d.inferred), B = labels(d.exercised), C = labels(d.final);
  d.reconciliation = {
    agreedWithIdentity: same(C, A),
    agreedWithBehaviour: same(C, B),
    // Did pass 3 keep a purpose that behaviour alone had dropped? That is rule 3 working.
    restoredFromIdentity: [...A].filter((x) => !B.has(x) && C.has(x)),
    // Did it keep something only behaviour saw? That is rule 2 working.
    keptFromBehaviour: [...B].filter((x) => !A.has(x) && C.has(x)),
  };
  writeFileSync(job.file, JSON.stringify(d, null, 2));
  return { ...job, cookie: d.cookie, A: [...A], B: [...B], C: [...C], rec: d.reconciliation };
});

const ok = results.filter((r) => r && !r.__failed && !r.skipped);
const failed = results.filter((r) => r?.__failed);
for (const f of failed) log(`  ! FAILED ${basename(f.item.file)}: ${f.error}`);

const restored = ok.filter((r) => r.rec.restoredFromIdentity.length);
const kept = ok.filter((r) => r.rec.keptFromBehaviour.length);
log(`\n${ok.length} classified, ${failed.length} failed`);
log(`agreed with identity-only: ${ok.filter((r) => r.rec.agreedWithIdentity).length}`);
log(`agreed with behaviour-only: ${ok.filter((r) => r.rec.agreedWithBehaviour).length}`);
log(`restored a purpose behaviour had dropped (rule 3): ${restored.length}`);
log(`kept a purpose only behaviour saw (rule 2): ${kept.length}`);
for (const r of kept.slice(0, 10)) {
  log(`   ${r.site}/${r.cookie}: behaviour contributed ${r.rec.keptFromBehaviour.join("+")}`);
}
