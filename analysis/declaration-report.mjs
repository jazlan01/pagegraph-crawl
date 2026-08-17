#!/usr/bin/env node
// declaration-report.mjs — declared purpose (the site's CMP) vs observed behaviour (our classifier).
//
//   node analysis/declaration-report.mjs <crawl-dir> --classify <classify-v2 dir> [--out <file>]
//
// The classifier is independent — it never saw the declaration. This report is the join: it places
// what the SITE declares each cookie is for beside what we OBSERVED it do, and flags where they
// part company. Two findings carry the report:
//
//   MISMATCH  — the site declares a cookie benign (Strictly Necessary / Functional) but we observed
//               it doing something that requires consent (transmitting an identifier to an ad host).
//               A Necessary declaration is refuted by the behaviour.
//   CONTRADICTION — the site's OWN declaration is impossible: it lists the cookie under both a
//               consent-exempt group and a consent-requiring one. Our classifier says which holds.
//
// The mutual-exclusivity rule behind both comes from analysis/data/category-rules.json (derived
// from PECR/ICC/TCF consent bases, not hand-picked). We abstain — "not assessable" — when our own
// classification is low-confidence; the report reads confidence, it never manufactures it.

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { contradictionsIn } from "./lib/category-rules.mjs";
import { buildComparisonRow, TRACKING, STATUS_META, STATUS_ORDER } from "./lib/declared-observed.mjs";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const crawlDir = argv.find((a) => !a.startsWith("--"));
const classifyDir = flag("--classify", null);
if (!crawlDir || !existsSync(crawlDir)) {
  process.stderr.write("usage: node analysis/declaration-report.mjs <crawl-dir> --classify <dir> [--out <file>]\n");
  process.exit(1);
}

const pick = (dir, suffix) => { const f = readdirSync(dir).find((x) => x.endsWith(suffix)); return f ? join(dir, f) : null; };
const readJson = (p) => (p && existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null);

const declPath = pick(crawlDir, ".declaration.json");
const declaration = readJson(declPath) || { cmp: null, cookies: {} };
const jarRaw = readJson(pick(crawlDir, ".cookies.json")) || [];
const jar = Array.isArray(jarRaw) ? jarRaw : (jarRaw.cookies || []);
const site = declaration.site || crawlDir.replace(/\/$/, "").split("/").pop();

// our observed classification (pass3 `final`), keyed by cookie name
const observed = new Map();
if (classifyDir && existsSync(classifyDir)) {
  for (const f of readdirSync(classifyDir)) {
    if (!f.endsWith(".json") || f === "_index.json") continue;
    const d = readJson(join(classifyDir, f));
    if (d?.cookie) observed.set(d.cookie, d);
  }
}

// ---- per-cookie verdict (shared logic in lib/declared-observed.mjs) --------
const rows = jar.map((c) =>
  buildComparisonRow({ name: c.name, host: c.domain, declaration, observedDoc: observed.get(c.name) }));

// declared-but-not-observed self-contradictions — the site contradicts itself even where we didn't
// see the cookie; still a finding, just without our adjudication.
const observedNames = new Set(jar.map((c) => c.name));
const declaredOnlyContradictions = Object.entries(declaration.cookies)
  .filter(([n]) => !observedNames.has(n))
  .map(([n, e]) => ({ name: n, declaredCats: e.declaredCategories, contra: contradictionsIn(e.declaredCategories) }))
  .filter((x) => x.contra.length);

const tally = (s) => rows.filter((r) => r.status === s).length;
const summary = {
  cookies: rows.length,
  consistent: tally("consistent"),
  mismatchUnder: tally("mismatch-under-declared"),
  mismatchOver: tally("mismatch-over-declared"),
  contradiction: tally("contradictory-declaration"),
  notAssessable: tally("not-assessable"),
  notDeclared: tally("not-declared"),
  declaredOnlyContradictions: declaredOnlyContradictions.length,
  // the headline
  necessaryButTracking: rows.filter((r) =>
    (r.status === "mismatch-under-declared" || r.status === "contradictory-declaration") &&
    r.declaredCats.includes("Necessary") && r.observed.some((l) => TRACKING.has(l))).length,
};

// ---- render ----------------------------------------------------------------
const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const ORDER = STATUS_ORDER;

const chip = (t, cls) => `<span class="chip ${cls || ""}">${esc(t)}</span>`;
const rowHtml = (r) => {
  const m = STATUS_META[r.status];
  const obs = r.observed.length
    ? r.observed.map((l) => chip(l, TRACKING.has(l) ? "trk" : "ben")).join(" ") + (r.observedConf ? ` <span class="conf">${esc(r.observedConf)}</span>` : "")
    : `<span class="muted">—</span>`;
  const decl = r.declaredCats.length
    ? r.declaredCats.map((l) => chip(l, TRACKING.has(l) ? "trk" : "ben")).join(" ")
    : `<span class="muted">not declared</span>`;
  return `<tr class="st-${m.cls}">
    <td class="ck"><code>${esc(r.name)}</code><div class="hst">${esc(r.host || "")}</div></td>
    <td>${decl}${r.declaredGroups.length ? `<div class="grp">${esc(r.declaredGroups.join(", "))}</div>` : ""}</td>
    <td>${obs}${r.observedTcf.length ? `<div class="grp">${esc(r.observedTcf.slice(0,4).join(" "))}</div>` : ""}</td>
    <td><span class="verdict ${m.cls}">${esc(m.label)}</span><div class="detail">${esc(r.detail)}</div></td>
  </tr>`;
};

const findings = rows.filter((r) => r.status === "mismatch-under-declared" || r.status === "contradictory-declaration");
const sorted = [...rows].sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status) || a.name.localeCompare(b.name));

const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Declared vs observed — ${esc(site)}</title>
<style>
:root{
  --navy:#0E1227; --panel:#161B33; --sky:#6390EE; --pool:#00DBFF; --salmon:#FC7D73;
  --seagreen:#40EBC2; --gold:#F0B53D; --white:#FFFFFF; --muted:#9AA2B8; --line:#2A3150;
  --sans:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--navy);color:var(--white);font-family:var(--sans);
  font-size:1.05rem;line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:1100px;margin:0 auto;padding:3rem 1.5rem 5rem}
h1{font-size:2.2rem;margin:0 0 .3rem;letter-spacing:-.01em}
h2{font-size:1.5rem;margin:2.6rem 0 1rem;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:1rem;margin-bottom:2rem}
.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:.8rem;color:var(--sky);font-weight:600}
.headline{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.6rem 1.8rem;margin:1.5rem 0}
.headline .n{font-size:3rem;font-weight:700;color:var(--salmon);line-height:1}
.headline .n.zero{color:var(--seagreen)}
.headline .cap{color:var(--muted);max-width:60ch}
.tiles{display:flex;flex-wrap:wrap;gap:.75rem;margin:1.5rem 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:.9rem 1.1rem;min-width:8.5rem}
.tile .v{font-size:1.7rem;font-weight:700;font-variant-numeric:tabular-nums}
.tile .k{font-size:.82rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.tile.bad .v{color:var(--salmon)} .tile.warn .v{color:var(--gold)} .tile.ok .v{color:var(--seagreen)}
.note{background:rgba(99,144,238,.08);border-left:3px solid var(--sky);padding:1rem 1.2rem;border-radius:0 8px 8px 0;
  margin:1.2rem 0;color:#C9D2EA;font-size:.95rem}
table{width:100%;border-collapse:collapse;margin-top:.6rem;font-size:.95rem}
th{text-align:left;color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;
  padding:.5rem .6rem;border-bottom:1px solid var(--line)}
td{padding:.7rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}
.ck code{color:var(--pool);font-family:var(--mono);font-size:.9rem}
.hst,.grp{color:var(--muted);font-size:.78rem;margin-top:.15rem}
.detail{color:var(--muted);font-size:.85rem;margin-top:.25rem;max-width:62ch}
.chip{display:inline-block;padding:.08rem .5rem;border-radius:5px;font-size:.82rem;border:1px solid var(--line);margin:.05rem}
.chip.trk{color:var(--salmon);border-color:rgba(252,125,115,.4)}
.chip.ben{color:var(--seagreen);border-color:rgba(64,235,194,.35)}
.conf{color:var(--muted);font-size:.78rem}
.verdict{font-weight:600;font-size:.9rem}
.verdict.bad{color:var(--salmon)} .verdict.warn{color:var(--gold)} .verdict.ok{color:var(--seagreen)} .verdict.muted{color:var(--muted)}
tr.st-bad td{background:rgba(252,125,115,.05)}
.tbl-scroll{overflow-x:auto}
code{font-family:var(--mono)}
footer{margin-top:3rem;padding-top:1.5rem;border-top:1px solid var(--line);color:var(--muted);font-size:.85rem}
</style></head>
<body><div class="wrap">
  <div class="eyebrow">VaultJS · Cookie compliance</div>
  <h1>Declared purpose vs observed behaviour</h1>
  <div class="sub">${esc(site)} · ${summary.cookies} cookies · declaration ${declaration.cmp ? `from ${esc(declaration.cmp)}` : "unavailable"} · observed classification is independent (behaviour only, never sees the declaration)</div>

  <div class="headline">
    <div class="n ${summary.necessaryButTracking ? "" : "zero"}">${summary.necessaryButTracking}</div>
    <div class="cap">cookie(s) the site declares <b>Strictly Necessary</b> that our behavioural classifier observed doing something requiring consent. "Strictly necessary" is consent-exempt and mutually exclusive with tracking — so each of these is a declaration the behaviour refutes.</div>
  </div>

  <div class="tiles">
    <div class="tile bad"><div class="v">${summary.mismatchUnder}</div><div class="k">Under-declared</div></div>
    <div class="tile bad"><div class="v">${summary.contradiction}</div><div class="k">Contradictory decl.</div></div>
    <div class="tile warn"><div class="v">${summary.mismatchOver}</div><div class="k">Over-declared</div></div>
    <div class="tile ok"><div class="v">${summary.consistent}</div><div class="k">Consistent</div></div>
    <div class="tile"><div class="v">${summary.notAssessable}</div><div class="k">Not assessable</div></div>
    <div class="tile"><div class="v">${summary.notDeclared}</div><div class="k">Not declared</div></div>
  </div>

  <div class="note"><b>How to read this.</b> <b>Declared</b> is the site's own CMP category for the cookie. <b>Observed</b> is our classifier's verdict from behaviour alone, with its confidence — it never saw the declaration. A cookie can be <b>consent-exempt</b> (Strictly Necessary) <em>or</em> <b>consent-requiring</b> (Functional / Analytics / Advertising), never both; the mutual-exclusivity rule is derived from PECR/ICC/TCF consent bases. Where our classifier was low-confidence we mark <b>not assessable</b> and decline to judge rather than assert a gap.${declaration.caveat ? ` <br><span class="conf">Declaration ${esc(declaration.caveat)}.</span>` : ""}</div>

  ${findings.length ? `<h2>Findings (${findings.length})</h2>
  <div class="tbl-scroll"><table><thead><tr><th>Cookie</th><th>Declared</th><th>Observed (ours)</th><th>Verdict</th></tr></thead>
  <tbody>${findings.sort((a,b)=>ORDER.indexOf(a.status)-ORDER.indexOf(b.status)).map(rowHtml).join("")}</tbody></table></div>` : ""}

  ${declaredOnlyContradictions.length ? `<h2>Self-contradictory declarations, not observed this load (${declaredOnlyContradictions.length})</h2>
  <div class="note">The site's CMP lists these cookies under mutually-exclusive purposes. They were not set during this crawl, so our classifier cannot adjudicate — but the declaration contradicts itself regardless.</div>
  <div class="tbl-scroll"><table><thead><tr><th>Cookie</th><th>Declared as</th></tr></thead><tbody>
  ${declaredOnlyContradictions.slice(0,50).map((x)=>`<tr><td class="ck"><code>${esc(x.name)}</code></td><td>${x.declaredCats.map((l)=>chip(l,TRACKING.has(l)?"trk":"ben")).join(" ")}</td></tr>`).join("")}
  </tbody></table></div>` : ""}

  <h2>All cookies (${rows.length})</h2>
  <div class="tbl-scroll"><table><thead><tr><th>Cookie</th><th>Declared</th><th>Observed (ours)</th><th>Verdict</th></tr></thead>
  <tbody>${sorted.map(rowHtml).join("")}</tbody></table></div>

  <footer>
    Declaration: ${declaration.source ? `<code>${esc(declaration.source)}</code>` : "none captured"}.
    Observed classification: independent behavioural classifier (classify-v2 / pass3), confidence-gated.
    Mutual-exclusivity from <code>category-rules.json</code> (PECR reg 6 · ICC UK Cookie Guide · IAB TCF v2.2).
    Generated ${new Date().toISOString().slice(0,10)}.
  </footer>
</div></body></html>`;

const outPath = flag("--out", join(crawlDir, `declaration-report-${site}.html`));
writeFileSync(outPath, html);
console.log(`${site}: ${summary.necessaryButTracking} necessary-but-tracking · ` +
  `${summary.mismatchUnder} under-declared · ${summary.contradiction} contradictory · ` +
  `${summary.consistent} consistent · ${summary.notDeclared} not-declared -> ${outPath}`);
