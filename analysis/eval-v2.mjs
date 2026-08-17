#!/usr/bin/env node
// eval-v2.mjs — score the two-pass classifier against the CMP-derived bar.
//
//   node analysis/eval-v2.mjs <classify-v2 dir>... [--report <report-data.json>] [--out <file>]
//
// WHAT THE BAR IS, AND WHAT IT IS NOT.
// The comparison labels come from the VaultJS cookie-classification MCP, which classifies from a
// cookie's NAME against a corpus of CMP self-declarations aggregated across sites. That is the
// same labelling method CookieBlock trained on, which is why it is usable as a bar at all — but
// it is weak ground truth, not truth:
//   * name-only matches are, in the corpus's own words, "not domain-confirmed; may collide with
//     an unrelated same-name cookie";
//   * the declarations are what site operators told their CMP, not what the code does;
//   * these verdicts were fetched with customer_id 0, so the behavioural warehouse layer
//     contributed nothing — they are a FLOOR on the MCP, not its best.
// So a disagreement is a disagreement, never automatically our error. The point of scoring against
// it is to see MOVEMENT and to find the disputed set worth adjudicating by hand.
//
// Reported per pass so the ablation is explicit:
//   report    — the shipped label-from-flows output (the thing being replaced)
//   Pass A    — inferred purpose, from identity. The name-corpus question.
//   Pass B    — exercised purpose, from the name-free feature vector + its own Pass-A verdict.
// If Pass B does not beat Pass A, the feature layer is not earning its place, and that is the
// number this file exists to expose rather than bury.

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const dirs = argv.filter((a) => !a.startsWith("--") && existsSync(a) && a !== flag("--report") && a !== flag("--out"));
const reportPath = flag("--report", "output/audit-2026-08-02/report-data.json");
const outPath = flag("--out", null);
if (!dirs.length) {
  process.stderr.write("usage: node analysis/eval-v2.mjs <classify-v2 dir>... [--report f] [--out f]\n");
  process.exit(1);
}

const VER = new URL("./data/cookie-verdicts-mcp.json", import.meta.url).pathname;
if (!existsSync(VER)) { process.stderr.write("no data/cookie-verdicts-mcp.json\n"); process.exit(1); }
const mcp = JSON.parse(readFileSync(VER, "utf8"));

// The shipped labels, for the "what are we replacing" column.
const shipped = new Map();
if (existsSync(reportPath)) {
  const rep = JSON.parse(readFileSync(reportPath, "utf8"));
  for (const s of rep.sites) {
    for (const it of s.items) {
      if (it.b === "c") shipped.set(`${s.dir}/${it.n}`, new Set((it.icc || []).map((x) => x.l)));
    }
  }
}

// Behavioural slices. Name-shaped, and that is fine — this is a REPORTING slice, never a label.
// The literature and our own failures both concentrate in these, so an aggregate would hide them.
const SLICES = [
  { id: "bot-defence / WAF", re: /^(_px|pxcts|pxsid|_abck|ak_bmsc|akav|bm_(sz|sv|s|so|lso|mi)$|aws-waf|__cf_bm|TS[0-9a-f]{6,}|dtCookie|dtPC|dtSa|rxVisitor|rxvt)/i },
  { id: "consent record", re: /(Optanon|euconsent|OTGPP|CookieConsent|ENSIGHTEN_PRIVACY|dtm_consent)/i },
  { id: "auth / session", re: /(auth|session|JSESSIONID|csrf|xssid|WC_AUTHENTICATION)/i },
];
const sliceOf = (n) => SLICES.find((s) => s.re.test(n))?.id ?? "other";

const setOf = (arr) => new Set((arr || []).map((x) => x.label));

// TCF labels arrive in two vintages: "Purpose 7 - Measure advertising performance" from the head,
// "P7" from the MCP cache. Reduce both to P7 / SP1 so the axis is comparable at all.
const tcfKey = (label) => {
  const s = String(label ?? "");
  let m = /^Special Purpose\s*(\d+)/i.exec(s) || /^SP\s*(\d+)$/i.exec(s);
  if (m) return `SP${m[1]}`;
  m = /^Purpose\s*(\d+)/i.exec(s) || /^P\s*(\d+)$/i.exec(s);
  return m ? `P${m[1]}` : s;
};
const tcfSetOf = (arr) => new Set((arr || []).map((x) => tcfKey(x.label)));
const eq = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));
const overlaps = (a, b) => [...a].some((x) => b.has(x));

const rows = [];
for (const dir of dirs) {
  const site = basename(dir).replace(/^classify-v2-/, "");
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".json") || f === "_index.json") continue;
    const d = JSON.parse(readFileSync(join(dir, f), "utf8"));
    const rec = mcp.records[d.cookie];
    if (!rec) continue;
    const bar = new Set((rec.icc || []).filter((x) => (x.p ?? 0) >= 0.5).map((x) => x.label));
    if (!bar.size) continue;                       // nothing to score against
    rows.push({
      site, cookie: d.cookie, slice: sliceOf(d.cookie), bar,
      a: setOf(d.inferred?.icc_uk_categories),
      b: setOf(d.exercised?.icc_uk_categories),
      c: d.final ? setOf(d.final.icc_uk_categories) : null,
      tcfBar: new Set((rec.tcf || []).filter((x) => (x.p ?? 0) >= 0.5).map((x) => tcfKey(x.label))),
      tcfA: tcfSetOf(d.inferred?.iab_purposes),
      tcfB: tcfSetOf(d.exercised?.iab_purposes),
      tcfC: d.final ? tcfSetOf(d.final.iab_purposes) : null,
      shipped: shipped.get(`${site}/${d.cookie}`) ?? null,
      changed: !!d.delta?.changed,
    });
  }
}
if (!rows.length) { process.stderr.write("no scorable cookies\n"); process.exit(1); }

const score = (pick, subset = rows) => {
  const scored = subset.filter((r) => pick(r) !== null);
  if (!scored.length) return null;
  const exact = scored.filter((r) => eq(pick(r), r.bar)).length;
  const any = scored.filter((r) => overlaps(pick(r), r.bar)).length;
  const nec = scored.filter((r) => r.bar.has("Necessary") === pick(r).has("Necessary")).length;
  return { n: scored.length, exact, exactPct: +(exact / scored.length * 100).toFixed(1), anyOverlap: any, necessaryAgreement: nec };
};

const pickShipped = (r) => r.shipped, pickA = (r) => r.a, pickB = (r) => r.b, pickC = (r) => r.c;
// The TCF axis is multi-label and P1 applies to essentially every stored cookie, so exact-set
// match is a harsh and not very informative measure there. Jaccard says how much of the purpose
// set the two agree on, which is what a compliance reader actually cares about.
const jac = (a, b) => { if (!a.size && !b.size) return 1; const i = [...a].filter((x) => b.has(x)).length;
  return +(i / (a.size + b.size - i)).toFixed(3); };
const tcfScore = (pick, subset = rows) => {
  const s = subset.filter((r) => pick(r) !== null && r.tcfBar.size);
  if (!s.length) return null;
  const mean = s.reduce((acc, r) => acc + jac(pick(r), r.tcfBar), 0) / s.length;
  const exact = s.filter((r) => eq(pick(r), r.tcfBar)).length;
  return { n: s.length, meanJaccard: +mean.toFixed(3), exact, exactPct: +(exact / s.length * 100).toFixed(1) };
};
const out = {
  generated: new Date().toISOString().slice(0, 10),
  bar: {
    source: mcp.source,
    caveat: mcp.customerIdCaveat,
    warning: "Weak ground truth: name-based CMP self-declarations. A disagreement is not automatically our error.",
  },
  cookiesScored: rows.length,
  sites: [...new Set(rows.map((r) => r.site))],
  overall: {
    shipped: score(pickShipped),
    passA_inferred: score(pickA),
    passB_exercised: score(pickB),
    passC_final: score(pickC),
  },
  tcf: {
    passA_inferred: tcfScore((r) => r.tcfA),
    passB_exercised: tcfScore((r) => r.tcfB),
    passC_final: tcfScore((r) => r.tcfC),
  },
  behaviourChangedVerdict: rows.filter((r) => r.changed).length,
  // The ablation in one number: does behaviour beat identity?
  passBOverPassA: null,
  bySlice: {},
  disputed: [],
};
out.passBOverPassA = +(out.overall.passB_exercised.exactPct - out.overall.passA_inferred.exactPct).toFixed(1);

for (const s of [...new Set(rows.map((r) => r.slice))]) {
  const sub = rows.filter((r) => r.slice === s);
  out.bySlice[s] = {
    n: sub.length,
    shipped: score(pickShipped, sub),
    passA: score(pickA, sub),
    passB: score(pickB, sub),
    passC: score(pickC, sub),
  };
}
out.disputed = rows.filter((r) => !eq(r.b, r.bar)).map((r) => ({
  site: r.site, cookie: r.cookie, slice: r.slice,
  bar: [...r.bar], passA: [...r.a], passB: [...r.b], shipped: r.shipped ? [...r.shipped] : null,
}));

if (outPath) writeFileSync(outPath, JSON.stringify(out, null, 2));

const line = (l, s) => s && console.log(`  ${l.padEnd(26)} exact ${String(s.exact).padStart(3)}/${s.n} (${String(s.exactPct).padStart(5)}%) · any-overlap ${String(s.anyOverlap).padStart(3)} · Necessary-agreement ${s.necessaryAgreement}`);
console.log(`${rows.length} cookies scored across ${out.sites.length} site(s), bar = MCP name-corpus verdicts\n`);
line("report (label-from-flows)", out.overall.shipped);
line("Pass A (inferred, name)", out.overall.passA_inferred);
line("Pass B (exercised, graph)", out.overall.passB_exercised);
line("Pass C (reconciled)", out.overall.passC_final);
console.log("\nIAB TCF purposes (mean Jaccard against the bar; exact-set is harsh on a multi-label axis):");
for (const [k, v] of Object.entries(out.tcf)) {
  if (v) console.log(`  ${k.padEnd(26)} mean-Jaccard ${v.meanJaccard} · exact ${v.exact}/${v.n} (${v.exactPct}%)`);
}
console.log(`\nablation — Pass B minus Pass A: ${out.passBOverPassA > 0 ? "+" : ""}${out.passBOverPassA} points`);
console.log(`behaviour changed the verdict on ${out.behaviourChangedVerdict} of ${rows.length}\n`);
console.log("by slice:");
for (const [s, v] of Object.entries(out.bySlice)) {
  console.log(`  ${s.padEnd(20)} n=${String(v.n).padStart(3)}` +
    `  shipped ${v.shipped ? `${v.shipped.exactPct}%` : "—"}` +
    `  A ${v.passA.exactPct}%  B ${v.passB.exactPct}%  C ${v.passC ? v.passC.exactPct + "%" : "—"}`);
}
if (outPath) console.log(`\nwrote ${outPath} (${out.disputed.length} disputed cookies for adjudication)`);
