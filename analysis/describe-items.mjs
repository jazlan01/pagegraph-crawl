#!/usr/bin/env node
// describe-items.mjs — a plain-English sentence for every stored item in the report.
//
//   node analysis/describe-items.mjs <report-dir>
//     e.g. node analysis/describe-items.mjs output/audit-2026-08-02
//
// Closes feedback item f2 ("a human-readable description of each cookie would be nice"). The
// per-item detail is complete but reads as engineering output — writers, behaviour kinds, send
// methods — so a non-engineer has to assemble the story themselves. This states it in one
// sentence: what the thing is, who put it there, what happened to it during the page load.
//
// COMPOSED, NOT WRITTEN. Every clause is derived from a recorded field, and a clause is omitted
// when the field is empty rather than softened into a guess. Nothing here infers purpose: the
// labels already carry that, with their own evidence tiers, and repeating them in prose would
// launder an `inferred` label into a flat assertion. So the sentence describes *what happened*
// and stops. Where a value's contents are themselves a finding (a cleartext IP, an identifier
// that records its own creation time) the decoder's own words are quoted verbatim.
//
// Idempotent: re-running replaces `desc` rather than appending.

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const reportDir = process.argv[2];
if (!reportDir || !existsSync(reportDir)) {
  process.stderr.write("usage: node analysis/describe-items.mjs <report-dir>\n");
  process.exit(1);
}
const dataPath = join(reportDir, "report-data.json");
const htmlName = readdirSync(reportDir).find(f => f.endsWith(".html") && f.includes("audit"));
if (!existsSync(dataPath) || !htmlName) {
  process.stderr.write(`need report-data.json and an audit .html in ${reportDir}\n`);
  process.exit(1);
}
const report = JSON.parse(readFileSync(dataPath, "utf8"));

const KIND = { c: "cookie", l: "localStorage entry", s: "sessionStorage entry" };
const list = xs => xs.length === 1 ? xs[0]
  : xs.length === 2 ? `${xs[0]} and ${xs[1]}`
  : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`;

// "written by X (third-party script) in function Y()" -> "X", dropping the function detail that
// only an engineer reads. The `v` field already holds the vendor host when one was resolved.
const writerPhrase = w => {
  if (w.v) return `${w.v} (${w.third ? "a third-party script" : "the site's own script"})`;
  const t = String(w.t || "");
  if (/Set-Cookie/i.test(t)) {
    const m = /response from (\S+)/.exec(t);
    return m ? `${m[1]}'s server, in an HTTP response header` : "the server, in an HTTP response header";
  }
  const bare = t.replace(/\s+in function.*$/, "");
  // The recorded phrases are already full sentences ("written by the page's own inline script",
  // "present in storage but its creation was not observed"). Strip the leading verb so they slot
  // in after "set by" instead of reading "set by written by ...".
  return bare.replace(/^written by\s+/i, "") || "an unresolved source";
};

function describe(it, site) {
  const kind = KIND[it.b] || "stored item";
  const s = [];
  const id = it.ident;
  // A Tier-1 identity is knowledge about the NAME, from a knowledge base or a model — never from
  // this recording. It leads the sentence because it is what a reader wants first ("this is the
  // GA cookie"), but it is only ever stated when a source is attached, and the source is rendered
  // beside it. Tier 2 has no name record and must not imply one.
  const known = id && id.source !== "observed" && (id.knownAs || id.product);

  // 1. what it is and who put it there
  const writers = it.writers || [];
  if (known) {
    // `knownAs` is already a complete sentence from the knowledge base ("Used by the security
    // provider PerimeterX to distinguish between human visitors and automated bots."), so it is
    // quoted as-is rather than re-worded, and the observed writer is stated next to it so a
    // reader can see the claim and the evidence together.
    s.push(id.knownAs
      ? String(id.knownAs).replace(/\s*$/, "").replace(/\.$/, "")
      : `The ${kind} used by ${id.product}`);
  } else if (!writers.length) {
    s.push(`A ${kind} on ${site.host} whose origin the recording did not capture`);
  } else {
    const who = [...new Set(writers.map(writerPhrase))];
    s.push(`A ${kind} set by ${list(who.slice(0, 3))}`);
  }

  let first = s.join(", ") + ".";
  if (known && writers.length) {
    const who = [...new Set(writers.map(writerPhrase))];
    first += ` Here it was set by ${list(who.slice(0, 2))}.`;
  }
  if (it.dec?.f?.length) {
    // a flag that already starts with "value ..." would read "its value: value states a date"
    const fl = it.dec.f.slice(0, 2).map(x => x.replace(/^value\s+/i, ""));
    first += ` Notable in its value: ${fl.join("; ")}.`;
  }

  // 3. what happened to it during the load — the part a reader actually wants
  const after = [];
  const reads = (it.beh || []).filter(b => b.k === "read").length;
  const times = reads === 1 ? "once" : reads === 2 ? "twice" : `${reads} times`;
  if (reads) after.push(`It was read back ${times} during the page load`);
  if ((it.beh || []).some(b => b.k === "transform")) {
    // Always its own sentence: the clauses are joined with ". ", so a leading "and" produced
    // "read back once during the page load. and its value was transformed".
    after.push("Its value was transformed before being used further");
  }

  const sends = (it.sends || []).map(x => x.h).filter(h => h && h !== "(unresolved)");
  const uniqSends = [...new Set(sends)];
  if (uniqSends.length) {
    after.push(`${after.length ? "T" : "Its contents were sent onward — t"}he value reached ${list(uniqSends.slice(0, 3))}` +
      (uniqSends.length > 3 ? ` and ${uniqSends.length - 3} other host${uniqSends.length - 3 === 1 ? "" : "s"}` : ""));
  }
  if ((it.bodyHits || []).length) {
    const hosts = [...new Set(it.bodyHits.map(h => { try { return new URL(h.u).hostname; } catch { return h.u; } }))];
    after.push(`The value was located inside the body of a request to ${list(hosts.slice(0, 2))}`);
  }

  // 4. the honest negative — an item nothing touched must say so, or an empty description
  //    reads as "unremarkable" when it actually means "unobserved".
  if (!after.length) {
    after.push(it.unassessed || it.probe
      ? "Nothing read, transformed or transmitted it while the page was open, so this load shows only that it exists"
      : "Nothing further happened to it during this page load");
  }

  // 5. Tier 2 only: infer the FUNCTION from what was observed, since no knowledge base could say
  //    what this cookie is. Hedged on purpose — "functions as" reports the role the recording
  //    shows it playing, and never claims intent ("tracks", "targets") the recording cannot see.
  //    Suppressed for Tier 1, where the knowledge base already stated the function.
  if (!known) {
    const outbound = [...new Set([
      ...(it.sends || []).map(x => x.h).filter(h => h && h !== "(unresolved)"),
      ...(it.bodyHits || []).map(h => { try { return new URL(h.u).hostname; } catch { return null; } }),
    ].filter(Boolean))];
    const reread = (it.beh || []).some(b => b.k === "read");
    if (outbound.length) {
      after.push(`On the evidence of this load it functions as an identifier shared with ` +
        `${list(outbound.slice(0, 2))}`);
    } else if (reread) {
      after.push("On the evidence of this load it functions as state the site reads back " +
        "across the visit, with no onward transmission observed");
    }
  }

  return `${first} ${after.join(". ")}.`.replace(/\.\./g, ".").replace(/\s+/g, " ").trim();
}

let n = 0;
for (const site of report.sites) {
  for (const it of site.items) {
    delete it.desc;
    it.desc = describe(it, site);
    n++;
  }
}
report.describedAdded = new Date().toISOString().slice(0, 10);
writeFileSync(dataPath, JSON.stringify(report));

// keep the single-file HTML's embedded copy in step
const htmlPath = join(reportDir, htmlName);
const html = readFileSync(htmlPath, "utf8");
const start = html.indexOf("const DATA = ");
if (start === -1) { process.stderr.write("could not find `const DATA = ` in the HTML\n"); process.exit(1); }
const eol = html.indexOf("\n", start);
writeFileSync(htmlPath,
  html.slice(0, start) + "const DATA = " + JSON.stringify(report) + ";" + html.slice(eol));

console.log(`described ${n} items`);
for (const site of report.sites.slice(0, 2)) {
  for (const it of site.items.slice(0, 2)) console.log(`  [${site.dir}/${it.n}] ${it.desc}`);
}
