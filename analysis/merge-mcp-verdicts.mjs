#!/usr/bin/env node
// merge-mcp-verdicts.mjs — build the MCP side of the head-to-head from raw batch responses.
//
//   node analysis/merge-mcp-verdicts.mjs <poll-result-file> [...]
//
// Sibling of `merge-mcp-identity.mjs`, and deliberately separate from it. That one keeps ONLY the
// prose, because identity is context for a reader and must never touch a label. This one keeps
// ONLY the labels, because the benchmark compares classifier against classifier. Same source
// files, two disjoint extracts, so neither use can quietly acquire the other's authority.
//
// Writes `data/cookie-verdicts-mcp.json`: per cookie name, the MCP's ICC categories and IAB TCF
// purposes with their probabilities and one-line reasoning.

import { existsSync, readFileSync, writeFileSync } from "node:fs";

const CACHE = new URL("./data/cookie-verdicts-mcp.json", import.meta.url).pathname;
const files = process.argv.slice(2);
if (!files.length) {
  process.stderr.write("usage: node analysis/merge-mcp-verdicts.mjs <poll-result-file> [...]\n");
  process.exit(1);
}

const cache = existsSync(CACHE)
  ? JSON.parse(readFileSync(CACHE, "utf8"))
  : {
      source: "VaultJS Internal MCP · cookie_classification.classify_cookies",
      customerId: "0",
      customerIdCaveat:
        "customer_id 0 returns behavioral_observation_count 0 — the CMP/name-pattern layer " +
        "answers but the customer-scoped warehouse contributes nothing. These verdicts are " +
        "therefore a FLOOR on the MCP's performance, not its best. Re-run with a real customer " +
        "id before treating any margin as settled.",
      records: {},
    };

// TCF labels come back as "Purpose 1 - Store and/or access information on a device"; the audit
// uses "P1". Normalise so the two can be compared at all.
const tcfShort = (label) => {
  const m = /^Purpose\s+(\d+)/i.exec(String(label ?? ""));
  return m ? `P${m[1]}` : String(label ?? "");
};

let added = 0;
for (const f of files) {
  let inner;
  try {
    const outer = JSON.parse(readFileSync(f, "utf8").trim());
    inner = JSON.parse(outer?.result?.result?.content?.[0]?.text ?? "");
  } catch (err) {
    process.stderr.write(`  ${f}: could not parse (${String(err)})\n`);
    continue;
  }
  for (const r of inner.results ?? []) {
    const names = r.grouped_cookie_names?.length ? r.grouped_cookie_names : [r.cookie_name];
    for (const n of names) {
      cache.records[n] = {
        icc: (r.icc_uk_categories ?? []).map(x => ({
          label: x.label, p: x.probability, why: x.reasoning })),
        tcf: (r.iab_purposes ?? []).map(x => ({
          label: tcfShort(x.label), p: x.probability, why: x.reasoning })),
        us: (r.us_state_privacy_categories ?? []).map(x => ({ label: x.label, p: x.probability })),
        model: inner.model ?? null,
      };
      added++;
    }
  }
}

cache.updated = new Date().toISOString().slice(0, 10);
cache.count = Object.keys(cache.records).length;
writeFileSync(CACHE, JSON.stringify(cache, null, 1));
console.log(`merged ${added} verdict(s); cache holds ${cache.count}`);
