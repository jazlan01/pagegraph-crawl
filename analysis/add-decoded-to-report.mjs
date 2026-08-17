#!/usr/bin/env node
// add-decoded-to-report.mjs — fold value-decoding results into the client report.
//
//   node analysis/add-decoded-to-report.mjs <report-dir> <crawl-root>
//     e.g. node analysis/add-decoded-to-report.mjs output/audit-2026-08-02 output/clients-2026-08-02-fixed
//
// The report says where a value travelled and who touched it, but treated the value itself as
// an opaque blob. `decode-cookie-values.mjs` already answers "what does it CONTAIN" — a mint
// timestamp, a cleartext IP, a consent decision — and that output was never wired in. This is
// the wiring: it runs the decoder per site and attaches the result to the matching item in
// report-data.json, then re-injects the data into the single-file HTML.
//
// Only findings are attached, not raw structure. An item gains a `dec` block when the value
// carries something a reader should act on (a stated flag) or when its structure is itself the
// finding (a decoded kind such as UUID / IP address / consent string). A value that merely
// parsed as, say, a plain integer adds nothing and is left off, so the report does not grow a
// row on every item that says nothing.
//
// Idempotent: re-running replaces the previous `dec` blocks rather than stacking them.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const [reportDir, crawlRoot] = process.argv.slice(2);
if (!reportDir || !crawlRoot || !existsSync(reportDir) || !existsSync(crawlRoot)) {
  process.stderr.write(
    "usage: node analysis/add-decoded-to-report.mjs <report-dir> <crawl-root>\n");
  process.exit(1);
}

const dataPath = join(reportDir, "report-data.json");
const htmlPath = readdirSync(reportDir).find(f => f.endsWith(".html") && f.includes("audit"));
if (!existsSync(dataPath) || !htmlPath) {
  process.stderr.write(`need report-data.json and an audit .html in ${reportDir}\n`);
  process.exit(1);
}
const report = JSON.parse(readFileSync(dataPath, "utf8"));

// ---------- decode each site ----------
const decodedBySite = new Map();
for (const site of report.sites) {
  const dir = join(crawlRoot, site.dir);
  if (!existsSync(dir)) {
    process.stderr.write(`  ${site.dir}: no crawl dir, skipped\n`);
    continue;
  }
  const tmp = join(process.env.TMPDIR || "/tmp", `decode-${site.dir}-${process.pid}.json`);
  execFileSync(process.execPath,
    [join(HERE, "decode-cookie-values.mjs"), dir, "--out", tmp],
    { stdio: ["ignore", "ignore", "inherit"] });
  const byName = new Map();
  for (const c of JSON.parse(readFileSync(tmp, "utf8")).cookies) {
    // A name can appear on more than one domain. Keep the entry that actually says
    // something, so a finding is not lost to an empty duplicate.
    const prev = byName.get(c.name);
    if (!prev || ((c.flags || []).length > (prev.flags || []).length)) byName.set(c.name, c);
  }
  decodedBySite.set(site.dir, byName);
}

// Structural kinds that are themselves worth reporting. Anything else needs a flag to appear.
const NOTABLE = /UUID|IP address|consent|TCF|JSON|timestamp|base64|key=value/i;

// ---------- attach ----------
let attached = 0, withFlags = 0;
for (const site of report.sites) {
  const byName = decodedBySite.get(site.dir);
  if (!byName) continue;
  for (const it of site.items) {
    delete it.dec;                       // idempotent
    if (it.b !== "c") continue;          // cookies only; the decoder reads the cookie jar
    const d = byName.get(it.n);
    if (!d) continue;
    const flags = d.flags || [];
    const kinds = [...new Set((d.parts || []).map(p => p.kind).filter(Boolean))];
    const notable = kinds.some(k => NOTABLE.test(k));
    if (!flags.length && !notable) continue;
    const minted = (d.parts || []).map(p => p.mintedAt).find(Boolean);
    it.dec = {
      v: d.overall,
      k: kinds.slice(0, 4),
      ...(flags.length ? { f: flags } : {}),
      ...(minted ? { m: minted } : {}),
    };
    attached++;
    if (flags.length) withFlags++;
  }
}
report.decodedAdded = new Date().toISOString().slice(0, 10);
report.totals.decodedItems = attached;
report.totals.decodedFindings = withFlags;

writeFileSync(dataPath, JSON.stringify(report));

// ---------- re-inject into the single-file HTML ----------
// The HTML embeds its own copy of the data on a `const DATA = {...}` line; the report is meant
// to work with no network access, so the two must be updated together.
const html = readFileSync(join(reportDir, htmlPath), "utf8");
const start = html.indexOf("const DATA = ");
if (start === -1) { process.stderr.write("could not find `const DATA = ` in the HTML\n"); process.exit(1); }
const eol = html.indexOf("\n", start);
const updated = html.slice(0, start) + "const DATA = " + JSON.stringify(report) + ";" + html.slice(eol);
writeFileSync(join(reportDir, htmlPath), updated);

console.log(`attached decoded values to ${attached} item(s); ${withFlags} carry a stated finding`);
for (const site of report.sites) {
  const f = site.items.filter(i => i.dec?.f);
  if (f.length) console.log(`  ${site.host}: ${f.map(i => i.n).join(", ")}`);
}
