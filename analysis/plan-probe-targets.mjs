#!/usr/bin/env node
// plan-probe-targets.mjs — turn a pass-1 crawl into a pass-2 probe plan.
//
//   node analysis/plan-probe-targets.mjs <crawl-dir> [--out <file>] [--src <dumped-scripts-dir>]
//                                        [--max-per-cookie 2] [--include-partial]
//
// WHY THIS EXISTS
// `decode-cookie-values.mjs` reports a value as "opaque — contents not determinable"
// whenever the site hashed or encrypted it before it reached any recorded boundary. That
// is the honest answer, and it is where the graph alone runs out. But the graph also says
// exactly WHERE the transform happened — the `script position` on the cookie's write edge —
// so a second pass can pause at that site and read what the page held a moment earlier.
//
// This script produces that pass's target list. It derives targets from evidence rather
// than hand-written offsets, and it states its own exclusions.
//
// WHAT IT WILL NOT DO
// It never attacks a transform. The probe pauses BEFORE one and reads a value the page
// already has in a local variable. Two consequences are encoded here:
//
//  1. **Server-issued tokens are excluded, not pursued.** If the opaque value — or a
//     delimited part of it — already appeared in an earlier response body, it is a
//     challenge token the server minted, not user data the page is hashing. Those are the
//     bot-defence cookies (`_px3`, `__cf_bm`, `ak_bmsc`, `aws-waf-token` and friends);
//     they are emitted with `skipped: "server-issued token"` so the exclusion is visible
//     rather than silent. No vendor is named anywhere in the rule — it is behavioural.
//  2. **A miss is not a clearance.** `.bodies.ndjson` truncates bodies (default 64 KB) and
//     stores only textual MIME types, so "value not found in any response body" is weaker
//     evidence than "found". Targets carry `serverTokenCheck` saying which it was.
//
// SCRIPT IDENTITY
// An offset is only meaningful against the exact bytes it was computed from. Two hash
// sources, deliberately kept apart:
//   * `expectedSha256`  — from `--src`, a dump of the LOADED source (what the renderer
//     parsed). Authoritative, and the probe ENFORCES it: a mismatch leaves the target
//     unarmed and recorded.
//   * `pass1ResponseSha256` — from the crawl's `.bodies.ndjson` response hash. Advisory
//     only. A response body and a parsed source can legitimately differ, so enforcing it
//     would skip good targets; the probe records the hash it actually armed against and
//     the comparison is made afterwards.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createInterface } from "node:readline";
import { createReadStream, existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const dir = argv.filter(a => !a.startsWith("--"))[0];
const outPath = flag("--out", null);
const srcDir = flag("--src", null);
const maxPerCookie = Number(flag("--max-per-cookie", 2));
const includePartial = argv.includes("--include-partial");
// Force specific cookies into the candidate set regardless of decode verdict. Repeatable.
const forced = new Set(argv.reduce((a, v, i) => (argv[i - 1] === "--cookie" ? [...a, v] : a), []));

if (!dir || !existsSync(dir)) {
  process.stderr.write("usage: node analysis/plan-probe-targets.mjs <crawl-dir> [--out <file>] [--src <dir>]\n");
  process.exit(1);
}

const pick = suffix => {
  const f = readdirSync(dir).find(f => f.endsWith(suffix));
  return f ? join(dir, f) : null;
};
const graphml = pick(".graphml");
const bodies = pick(".bodies.ndjson");
const jar = pick(".cookies.json");
if (!graphml) { process.stderr.write(`no .graphml in ${dir}\n`); process.exit(1); }
if (!jar) { process.stderr.write(`no .cookies.json in ${dir}\n`); process.exit(1); }

// ---------- pass-1 inputs ----------
// Both are delegated to the existing tools rather than reimplemented: the decode rules and
// the write-site resolution each live in exactly one place, and this stays a planner.
const node = process.execPath;
const runJSON = (script, args) =>
  JSON.parse(execFileSync(node, [join(HERE, script), ...args], {
    maxBuffer: 1 << 30, encoding: "utf8",
  }));

process.stderr.write("reading write sites from the graph (streaming)…\n");
const writes = runJSON("cookie-writes.mjs", [graphml, "--json"]);

process.stderr.write("decoding cookie values…\n");
const decodedOut = join(process.env.TMPDIR || "/tmp", `probe-decoded-${process.pid}.json`);
execFileSync(node, [join(HERE, "decode-cookie-values.mjs"), dir, "--out", decodedOut],
  { stdio: ["ignore", "ignore", "inherit"] });
const decoded = JSON.parse(readFileSync(decodedOut, "utf8"));

const cookieJar = (() => {
  const raw = JSON.parse(readFileSync(jar, "utf8"));
  return Array.isArray(raw) ? raw : (raw.cookies || []);
})();
const valueOf = new Map(cookieJar.map(c => [c.name, c.value ?? ""]));

// ---------- which cookies are worth probing ----------
// Only values the graph could NOT explain. A cookie already decoded needs no breakpoint,
// and probing it would pause a live page for evidence we already hold.
const wanted = decoded.cookies.filter(d =>
  forced.has(d.name) || d.overall === "opaque" || (includePartial && d.overall === "partial"));

// ---------- server-issued-token exclusion ----------
// Split the value on the delimiters trackers actually use, and look for any substantial
// part in a response body. A part echoed by the server was issued by it.
const escapeRegex = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const MIN_PART = 12;
const partsOf = v => {
  const parts = new Set();
  if (v && v.length >= MIN_PART) parts.add(v);
  for (const p of String(v).split(/[:;,|~&=\/.+\-_]+/)) {
    if (p.length >= MIN_PART) parts.add(p);
  }
  // trackers URL-encode as often as not
  try { const d = decodeURIComponent(v); if (d !== v && d.length >= MIN_PART) parts.add(d); }
  catch { /* not URL-encoded */ }
  return [...parts];
};

// The scan runs over EVERY cookie, not just the probe candidates. A bot-defence token
// that the decoder happens to read as structured (PerimeterX's `_px3` splits on colons and
// looks "literal") would otherwise never reach this check and would be absent from the plan
// silently — indistinguishable from a cookie nobody thought about. Being echoed by the
// server is a fact about the cookie, so it is recorded for all of them.
const needles = new Map();       // part -> [cookie names]
for (const c of cookieJar) {
  for (const part of partsOf(c.value ?? "")) {
    if (!needles.has(part)) needles.set(part, []);
    needles.get(part).push(c.name);
  }
}

const echoedBy = new Map();      // cookie name -> {url, part}
let bodiesScanned = 0, bodiesTruncated = 0, bodiesDropped = 0;
// Responses WITH a stored body, per origin. The server-issued-token check can only speak
// about an origin it actually saw bodies from: PerimeterX's collector XHRs, for instance,
// were not captured on walmart, so "the token was not echoed" says nothing there. Without
// this, an uninformative check reads exactly like a clean one.
const bodiesByOrigin = new Map();
if (bodies && needles.size) {
  process.stderr.write(`scanning response bodies for ${needles.size} value part(s)…\n`);
  const rl = createInterface({ input: createReadStream(bodies), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line) continue;
    let rec;
    try { rec = JSON.parse(line); } catch { continue; }
    if (rec.kind !== "response") continue;
    bodiesScanned++;
    if (rec.dropped) { bodiesDropped++; continue; }
    if (rec.truncated) bodiesTruncated++;
    try { const o = new URL(rec.url).origin; bodiesByOrigin.set(o, (bodiesByOrigin.get(o) ?? 0) + 1); }
    catch { /* non-absolute url */ }
    if (typeof rec.body !== "string" || !rec.body) continue;
    for (const [part, names] of needles) {
      if (!rec.body.includes(part)) continue;
      for (const n of names) if (!echoedBy.has(n)) echoedBy.set(n, { url: rec.url, part });
    }
  }
}

// ---------- script identity ----------
// Mirrors DebugStackTracker#maybeSaveScript's filename sanitisation so a dump written by a
// previous run is found by URL.
const dumpNameFor = url => `script_${url.replace(/[^A-Za-z0-9._-]/g, "_").slice(-150)}.loaded.js`;
const loadedHash = new Map();
if (srcDir && existsSync(srcDir)) {
  for (const f of readdirSync(srcDir)) {
    if (!f.endsWith(".loaded.js")) continue;
    loadedHash.set(f, createHash("sha256").update(readFileSync(join(srcDir, f))).digest("hex"));
  }
}

// Response-body hash per script URL, straight from the crawl sidecar (advisory).
const responseHash = new Map();
if (bodies) {
  const rl2 = createInterface({ input: createReadStream(bodies), crlfDelay: Infinity });
  for await (const line of rl2) {
    if (!line) continue;
    let rec; try { rec = JSON.parse(line); } catch { continue; }
    if (rec.kind === "response" && rec.sha256 && !responseHash.has(rec.url)) {
      responseHash.set(rec.url, rec.sha256);
    }
  }
}

// ---------- build the plan ----------
const targets = [], skipped = [];
for (const d of wanted) {
  const name = d.name;
  const echo = echoedBy.get(name);
  if (echo) {
    const w = writes.cookies?.[name]?.writes ?? [];
    const jsSites = w.filter(x => x.source === "js" && x.scriptUrl && x.offset != null);
    skipped.push({
      cookie: name,
      setChannel: w.length ? [...new Set(w.map(x => x.source))].join("+") : "not recorded",
      valueEchoedByServer: true,
      // Whether this cookie would ALSO have been ineligible. Without it, a cookie excluded here
      // looks like a distinct category when it may simply have been checked by this test first.
      wouldAlsoFailJsWriteTest: jsSites.length === 0,
      skipped: "excluded — value was issued by the server",
      why: `the value (or a ${echo.part.length}-char part of it) was already present in a ` +
           `response from ${echo.url} — the server issued it, so pausing the page would not ` +
           `reveal user data being transformed`,
    });
    continue;
  }
  const rec = writes.cookies?.[name];
  const allWrites = rec?.writes ?? [];
  // An inline write has no script URL to build a spec from — every inline script in a document
  // shares the document's URL — but it is NOT unreachable: the offset is relative to the inline
  // script's own source, and the source preceding it identifies which script is meant. So inline
  // writes are targets too, carrying that discriminator.
  const jsWrites = allWrites.filter(w => w.source === "js" && w.scriptUrl && w.offset != null);
  if (!jsWrites.length) {
    skipped.push({
      cookie: name,
      // Two independent facts, always both reported. The old single reason was whichever test
      // happened to run first, which made two overlapping conditions look mutually exclusive.
      setChannel: allWrites.length
        ? [...new Set(allWrites.map(w => w.source))].join("+")
        : "not recorded",
      valueEchoedByServer: false,
      skipped: "not eligible — no usable JS write site",
      why: allWrites.length
        ? `written over: ${[...new Set(allWrites.map(w => w.source))].join(", ")}. ` +
          "A Set-Cookie header has no script position to pause at; a JS write with no resolvable " +
          "offset cannot be located in the source."
        : "the graph records no write for this cookie at all — commonly a third-party cookie set " +
          "in a context whose write the graph did not capture",
    });
    continue;
  }
  // Distinct sites, most-recent first: the last write before the value settled is the one
  // whose inputs matter, and duplicates of one site add nothing.
  const seen = new Set();
  const sites = [];
  for (const w of [...jsWrites].reverse()) {
    const key = `${w.scriptUrl}#${w.offset}`;   // spec is null for inline writes
    if (seen.has(key)) continue;
    seen.add(key);
    sites.push(w);
    if (sites.length >= maxPerCookie) break;
  }
  for (const w of sites) {
    const dump = dumpNameFor(w.scriptUrl);
    let writerOrigin = w.scriptUrl;
    try { writerOrigin = new URL(w.scriptUrl).origin; } catch { /* keep raw */ }
    const writerOriginBodies = bodiesByOrigin.get(writerOrigin) ?? 0;
    targets.push({
      cookie: name,
      urlRegex: w.spec
        ? w.spec.slice(0, w.spec.lastIndexOf("#"))
        : escapeRegex(w.scriptUrl),
      offset: w.offset,
      inline: w.inline === true,
      // For an inline write the URL alone is ambiguous, so the target asserts what must sit
      // immediately before the offset. Verified at arm time against the parsed source.
      ...(w.inline === true ? { requirePrecedingSource: "document.cookie" } : {}),
      label: `${name}@${w.scriptUrl.split("/").pop()}#${w.offset}`,
      scriptUrl: w.scriptUrl,
      expectedSha256: loadedHash.get(dump),
      pass1ResponseSha256: responseHash.get(w.scriptUrl),
      why: `${name} decoded as ${d.overall}; this is the JS site that wrote it, so the ` +
           `pre-transform inputs are in scope there`,
      // The server-issued-token check is positive-evidence only: finding the value in a
      // response proves the server issued it; not finding it proves nothing, because
      // bodies are truncated, textual-only, and some XHR responses are never captured at
      // all (PerimeterX's collector on walmart is one). So no target is marked "cleared" —
      // the list is short by design and is meant to be read before it is run.
      serverTokenCheck: !bodies
        ? "not checked (no .bodies.ndjson in the crawl dir)"
        : `value not found in the ${bodiesScanned} stored response(s) — ${writerOriginBodies} ` +
          `of them from ${writerOrigin}. This is not a clearance: absence of an echo cannot ` +
          `distinguish a page-computed value from a token whose response was never stored`,
      reviewBeforeProbing: true,
    });
  }
}

const plan = {
  crawlDir: dir,
  pageUrl: writes.pageUrl ?? null,
  generatedFrom: { graphml, bodies, cookies: jar, loadedScriptDumps: srcDir ?? null },
  // Travels with the plan because it governs how the results may be read.
  caveat:
    "Pass 2 is a separate page load from the graph that located these sites. A value " +
    "embedding a timestamp or fresh randomness will not be the same one pass 1 recorded, " +
    "so a capture is A pre-transform value, not THE one in the graph.",
  bodyScan: bodies
    ? { responsesScanned: bodiesScanned, truncated: bodiesTruncated, droppedNoBody: bodiesDropped }
    : null,
  serverTokenCheckIsPositiveOnly:
    "A cookie listed in serverIssuedTokens was proven server-issued: its value was found in " +
    "a response the server sent. The converse does not hold — bodies are truncated and " +
    "textual-only and some XHR responses are never captured — so every target carries " +
    "reviewBeforeProbing and the list is meant to be read before pass 2 is run.",
  hashEnforcement: srcDir
    ? "expectedSha256 present where a loaded-source dump existed; the probe enforces it"
    : "no --src given, so no enforced hash. pass1ResponseSha256 is advisory; the probe " +
      "records the hash it armed against for after-the-fact reconciliation",
  counts: { probed: targets.length, cookiesTargeted: new Set(targets.map(t => t.cookie)).size,
            skipped: skipped.length, candidates: wanted.length },
  // Every cookie whose value the server had already sent, candidate or not. This is the
  // bot-defence exclusion made auditable: the probe pauses a page to read what the page
  // computed, and a challenge token is not that.
  serverIssuedTokens: [...echoedBy.entries()].map(([cookie, e]) => ({
    cookie,
    echoedFrom: e.url,
    matchedPartLength: e.part.length,
    wasProbeCandidate: wanted.some(d => d.name === cookie),
  })),
  targets,
  skipped,
};

if (outPath) writeFileSync(outPath, JSON.stringify(plan, null, 2));

// ---------- report ----------
const site = dir.replace(/\/$/, "").split("/").pop();
console.log(`${site}: ${wanted.length} opaque value(s) → ${targets.length} target(s) across ` +
            `${plan.counts.cookiesTargeted} cookie(s), ${skipped.length} skipped`);
for (const s of skipped.slice(0, 12)) console.log(`   skip ${s.cookie}: ${s.skipped}`);
const tok = plan.serverIssuedTokens.filter(t => !t.wasProbeCandidate);
if (tok.length) console.log(`   server-issued (not probed): ${tok.map(t => t.cookie).join(", ")}`);
for (const t of targets.slice(0, 12)) {
  console.log(`   probe ${t.cookie}: ${t.scriptUrl}#${t.offset}` +
              (t.inline ? "  [inline script — matched by source context]" : ""));
}
if (!srcDir) console.log("   (no --src: hashes advisory only — see hashEnforcement)");
if (targets.length) {
  console.log("   READ THE TARGETS BEFORE RUNNING THEM: the server-issued-token check only " +
              "confirms tokens it finds echoed; it cannot clear the ones it does not.");
}
if (outPath) {
  console.log(`\nwrote ${outPath}\nrun pass 2 on a STOCK Brave/Chromium:\n` +
    `  npm run crawl -- --probe --shields down -u ${plan.pageUrl ?? "<url>"} ` +
    `-o <outdir> --probe-targets ${outPath}`);
}
