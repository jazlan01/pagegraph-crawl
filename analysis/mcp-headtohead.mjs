#!/usr/bin/env node
// mcp-headtohead.mjs — run the benchmark §6 of the eval doc asks for.
//
//   node analysis/mcp-headtohead.mjs <report-dir> [--out <file>]
//
// The eval's charge is that our observed-behaviour classifier is *behind* the cookie-classification
// MCP, for structural reasons (payload bundling, split ICC/TCF axes, Functional as a default bin).
// Several of those were reworked since it was written, so the point of this script is to settle it
// on the current labels rather than argue about architecture.
//
// WHAT THIS MEASURES — and what it does not.
// There is no ground-truth labelled set here, so this reports **agreement**, not accuracy. Where
// the two systems differ, neither column is presumed right; the disagreements are emitted for hand
// adjudication. Saying "we agree with the MCP 80% of the time" is a statement about consistency;
// only the adjudicated disputed set can say who is correct.
//
// Two asymmetries are reported rather than smoothed over, because they decide how the result reads:
//   * COVERAGE. The MCP answers about cookie NAMES. localStorage and sessionStorage are outside
//     its corpus entirely, and they are roughly half of what the audit records. An aggregate
//     agreement score computed over cookies alone would silently hide that.
//   * SCOPE OF EVIDENCE. These verdicts were fetched with customer_id 0, so the MCP's
//     customer-scoped behavioural layer contributed nothing. They are a FLOOR on its performance.
//
// The multi-label probabilities are thresholded at 0.5 to get an asserted set. That cut is
// arbitrary in the way the eval warns about, so it is stated here, applied consistently, and
// reported alongside the counts at 0.3 and 0.7 so the reader can see whether the verdict is
// threshold-sensitive.

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const reportDir = process.argv[2];
const flag = (n, d) => { const i = process.argv.indexOf(n); return i !== -1 ? process.argv[i + 1] : d; };
const outPath = flag("--out", null);
if (!reportDir || !existsSync(reportDir)) {
  process.stderr.write("usage: node analysis/mcp-headtohead.mjs <report-dir> [--out <file>]\n");
  process.exit(1);
}
const report = JSON.parse(readFileSync(join(reportDir, "report-data.json"), "utf8"));
const VCACHE = new URL("./data/cookie-verdicts-mcp.json", import.meta.url).pathname;
if (!existsSync(VCACHE)) {
  process.stderr.write("no data/cookie-verdicts-mcp.json — run merge-mcp-verdicts.mjs first\n");
  process.exit(1);
}
const verdicts = JSON.parse(readFileSync(VCACHE, "utf8"));

const ICC = ["Necessary", "Functional", "Analytics", "Advertising"];
const setOf = xs => new Set(xs);
const eq = (a, b) => a.size === b.size && [...a].every(x => b.has(x));
const inter = (a, b) => [...a].filter(x => b.has(x));

// Behavioural slices the eval demands be broken out, because that is where it says our failures
// concentrate. Matched on name shape only — this is a REPORTING slice, never a label.
const SLICES = [
  { id: "bot-defence / WAF", re: /^(_px|pxcts|pxsid|_abck|ak_bmsc|akav|bm_(sz|sv|s|so|lso|mi)$|aws-waf|__cf_bm|TS[0-9a-f]{6,}|dtCookie|dtPC|dtSa|rxVisitor|rxvt)/i },
  { id: "consent record",    re: /(Optanon|euconsent|OTGPP|CookieConsent|ENSIGHTEN_PRIVACY|dtm_consent|_cq_s$)/i },
  { id: "auth / session state", re: /(auth|session|JSESSIONID|csrf|xssid|_sdsat_authState|WC_AUTHENTICATION)/i },
];
const sliceOf = (name) => SLICES.find(s => s.re.test(name))?.id ?? "other";

const asserted = (arr, t) => setOf((arr ?? []).filter(x => (x.p ?? 0) >= t).map(x => x.label));

const rows = [];
for (const site of report.sites) {
  for (const it of site.items) {
    const kind = it.b === "c" ? "cookie" : it.b === "l" ? "localStorage" : "sessionStorage";
    const rec = it.b === "c" ? verdicts.records[it.n] : undefined;
    // report-data.json uses compacted keys: `l` = label, `t` = evidence tier, `e` = evidence.
    // Reading `x.label` here silently produced an empty set for every item, which made the whole
    // corpus look "disjoint" from the MCP — a total-disagreement result that was pure bug.
    const ours = setOf((it.icc ?? []).map(x => x.l).filter(Boolean));
    const oursObserved = setOf((it.icc ?? []).filter(x => x.t === "observed").map(x => x.l).filter(Boolean));
    const theirs = rec ? asserted(rec.icc, 0.5) : null;
    rows.push({
      site: site.dir, name: it.n, kind, slice: sliceOf(it.n),
      ours: [...ours], oursObserved: [...oursObserved],
      theirs: theirs ? [...theirs] : null,
      theirs03: rec ? [...asserted(rec.icc, 0.3)] : null,
      theirs07: rec ? [...asserted(rec.icc, 0.7)] : null,
      // The assignment: the MCP infers a purpose the crawl never saw exercised.
      execDependent: !!(theirs && theirs.size && oursObserved.size === 0),
      unassessed: !!it.unassessed,
      agreement: !rec ? "no-mcp-record"
        : eq(ours, theirs) ? "identical"
        : inter(ours, theirs).length ? "partial"
        : "disjoint",
    });
  }
}

const tally = (pred) => rows.filter(pred).length;
const comparable = rows.filter(r => r.theirs !== null);
const out = {
  generated: new Date().toISOString().slice(0, 10),
  method: "agreement, not accuracy — no ground-truth labels; disagreements listed for adjudication",
  mcpScope: verdicts.customerIdCaveat,
  threshold: "MCP labels asserted at probability >= 0.5 (0.3 and 0.7 also reported)",
  coverage: {
    items: rows.length,
    cookies: tally(r => r.kind === "cookie"),
    localOrSession: tally(r => r.kind !== "cookie"),
    mcpCouldAnswer: comparable.length,
    mcpNoRecord: tally(r => r.agreement === "no-mcp-record"),
  },
  agreement: {
    identical: tally(r => r.agreement === "identical"),
    partial: tally(r => r.agreement === "partial"),
    disjoint: tally(r => r.agreement === "disjoint"),
  },
  thresholdSensitivity: {
    identicalAt03: comparable.filter(r => eq(setOf(r.ours), setOf(r.theirs03))).length,
    identicalAt05: comparable.filter(r => eq(setOf(r.ours), setOf(r.theirs))).length,
    identicalAt07: comparable.filter(r => eq(setOf(r.ours), setOf(r.theirs07))).length,
  },
  bySlice: Object.fromEntries(["bot-defence / WAF", "consent record", "auth / session state", "other"].map(s => {
    const sub = comparable.filter(r => r.slice === s);
    return [s, {
      n: sub.length,
      identical: sub.filter(r => r.agreement === "identical").length,
      partial: sub.filter(r => r.agreement === "partial").length,
      disjoint: sub.filter(r => r.agreement === "disjoint").length,
      weSayAdvertising: sub.filter(r => r.ours.includes("Advertising")).length,
      theySayAdvertising: sub.filter(r => r.theirs.includes("Advertising")).length,
      weSayNecessary: sub.filter(r => r.ours.includes("Necessary")).length,
      theySayNecessary: sub.filter(r => r.theirs.includes("Necessary")).length,
    }];
  })),
  execDependent: {
    n: tally(r => r.execDependent),
    note: "MCP asserts a purpose from the name family; this crawl observed no behaviour for it. " +
          "This is the gap the eval calls the actual assignment — the overlay's value lives here.",
    examples: rows.filter(r => r.execDependent).slice(0, 25)
      .map(r => ({ site: r.site, name: r.name, mcp: r.theirs, oursAllTiers: r.ours })),
  },
  disagreements: rows.filter(r => r.agreement === "disjoint" || r.agreement === "partial")
    .map(r => ({ site: r.site, name: r.name, slice: r.slice, ours: r.ours, mcp: r.theirs })),
};

if (outPath) writeFileSync(outPath, JSON.stringify(out, null, 2));

const pct = (n, d) => d ? `${((n / d) * 100).toFixed(1)}%` : "—";
console.log(`items ${out.coverage.items} · cookies ${out.coverage.cookies} · ` +
  `local/session ${out.coverage.localOrSession} (MCP cannot answer these)`);
console.log(`MCP had a record for ${comparable.length} of ${out.coverage.cookies} cookies\n`);
console.log(`agreement over the ${comparable.length} comparable:`);
console.log(`  identical ${out.agreement.identical} (${pct(out.agreement.identical, comparable.length)}) · ` +
  `partial ${out.agreement.partial} · disjoint ${out.agreement.disjoint}`);
console.log(`  threshold sensitivity — identical at p>=0.3/0.5/0.7: ` +
  `${out.thresholdSensitivity.identicalAt03}/${out.thresholdSensitivity.identicalAt05}/${out.thresholdSensitivity.identicalAt07}\n`);
console.log("by slice (the eval asked for these explicitly):");
for (const [s, v] of Object.entries(out.bySlice)) {
  if (!v.n) continue;
  console.log(`  ${s.padEnd(21)} n=${String(v.n).padStart(3)} identical=${v.identical} partial=${v.partial} disjoint=${v.disjoint}` +
    `  | Advertising: ours ${v.weSayAdvertising} vs MCP ${v.theySayAdvertising}` +
    `  | Necessary: ours ${v.weSayNecessary} vs MCP ${v.theySayNecessary}`);
}
console.log(`\nexecution-dependent (MCP asserts, we observed nothing): ${out.execDependent.n}`);
if (outPath) console.log(`\nwrote ${outPath}`);
