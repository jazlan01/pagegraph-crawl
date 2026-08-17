#!/usr/bin/env node
// merge-mcp-identity.mjs — fold a VaultJS `classify_cookies` batch result into the identity cache.
//
//   node analysis/merge-mcp-identity.mjs <poll-result-file> [...]
//
// The MCP is reachable from an agent session, not from a shell script, so the calls are made
// out-of-band and their raw results merged here. That is the same shape as the existing
// `--emit-payloads` / `--verdicts` split in `analysis/classify-cookies.mjs`: the knowledge source
// stays swappable, and the exact bytes that produced every description remain on disk to be
// re-read, diffed, or challenged.
//
// The cache records ONLY the identity prose plus its provenance. The classification axes the MCP
// also returns (`icc_uk_categories`, `iab_purposes`, `us_state_privacy_categories`) are
// deliberately NOT merged: this report's labels are derived from observed behaviour, and quietly
// importing a name-based verdict alongside them would blur exactly the line the pipeline exists
// to hold.

import { existsSync, readFileSync, writeFileSync } from "node:fs";

const CACHE = new URL("./data/cookie-identity-mcp.json", import.meta.url).pathname;
const files = process.argv.slice(2);
if (!files.length) {
  process.stderr.write("usage: node analysis/merge-mcp-identity.mjs <poll-result-file> [...]\n");
  process.exit(1);
}

const cache = existsSync(CACHE)
  ? JSON.parse(readFileSync(CACHE, "utf8"))
  : {
      source: "VaultJS Internal MCP · cookie_classification.classify_cookies",
      caveat:
        "Name-based, not observed. The MCP's own wording: a name-only match is 'not " +
        "domain-confirmed; may collide with an unrelated same-name cookie'. The corpus is " +
        "third-party CMP self-declaration aggregated across sites, not ground truth, and the " +
        "description itself is model-written. Treated as CONTEXT for a reader; never used to " +
        "derive a label, and dropped whenever it contradicts what this crawl recorded.",
      customerId: "0 (no customer scope — behavioural warehouse evidence deliberately not used; " +
        "only the name/CMP layer contributes to these descriptions)",
      records: {},
    };

let added = 0, skipped = 0;
for (const f of files) {
  const raw = readFileSync(f, "utf8").trim();
  let inner;
  try {
    // Envelope: {job_id,status,result:{result:{content:[{text:"<json>"}]}}}
    const outer = JSON.parse(raw);
    const text = outer?.result?.result?.content?.[0]?.text;
    inner = JSON.parse(text ?? raw);
  } catch (err) {
    process.stderr.write(`  ${f}: could not parse (${String(err)})\n`);
    continue;
  }
  const model = inner.model ?? null;
  for (const r of inner.results ?? []) {
    // A group's verdict covers every name it absorbed, so record each of them.
    const names = r.grouped_cookie_names?.length ? r.grouped_cookie_names : [r.cookie_name];
    for (const n of names) {
      if (!r.table_description) { skipped++; continue; }
      cache.records[n] = {
        knownAs: r.table_description,
        domain: r.domain ?? null,
        source: "mcp",
        model,
        ...(r.grouped_by ? { groupedBy: r.grouped_by } : {}),
        ...(r.cookie_name !== n ? { classifiedAs: r.cookie_name } : {}),
      };
      added++;
    }
  }
}

cache.updated = new Date().toISOString().slice(0, 10);
cache.count = Object.keys(cache.records).length;
writeFileSync(CACHE, JSON.stringify(cache, null, 1));
console.log(`merged ${added} record(s)${skipped ? `, ${skipped} without a description` : ""}; cache now holds ${cache.count}`);
