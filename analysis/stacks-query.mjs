#!/usr/bin/env node
// stacks-query.mjs — condense a debug-stacks sidecar so an agent can reason
// about it without ingesting the raw (multi-MB) JSON.
//
//   node analysis/stacks-query.mjs <stacks.json> [options]
//     --grep STR      flag/locate variables whose value contains STR (e.g. a
//                     cookie value fragment) across ALL frames.
//     --frames N      detail the innermost N frames per record (default 3).
//     --record R      limit output to record index R.
//     --frame K       deep-dump ALL scopes/vars of frame index K (full values).
//     --json          emit structured JSON instead of text.
//
// Default output: per record, the full call chain plus the innermost frames'
// local/block variables (truncated). Defensive parser salvages valid records
// if a sidecar was ever truncated.

import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith("--"));
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] !== undefined ? args[i + 1] : dflt;
};
const has = (name) => args.includes(name);

if (!file) {
  process.stderr.write(
    "usage: node analysis/stacks-query.mjs <stacks.json> [--grep STR] [--frames N] [--record R] [--frame K] [--json]\n",
  );
  process.exit(1);
}

const grep = opt("--grep", null);
const nFrames = Number(opt("--frames", "3"));
const onlyRecord = opt("--record", null);
const deepFrame = opt("--frame", null);
const asJson = has("--json");

const TRUNC = 160;
const TRANSFORM_MARKERS =
  /btoa|atob|encrypt|decrypt|cipher|hmac|sha|digest|JSON\.(parse|stringify)|TextEncoder|TextDecoder|base64/i;

// Robust parse: salvage top-level array objects if the file is truncated.
const parseRecords = (raw) => {
  try {
    return JSON.parse(raw);
  } catch {
    // fall through to salvage
  }
  const recs = [];
  let i = raw.indexOf("[") + 1;
  while (i < raw.length) {
    while (i < raw.length && (raw[i] === " " || raw[i] === "\n" || raw[i] === "\r" || raw[i] === "\t" || raw[i] === ",")) {
      i++;
    }
    if (raw[i] !== "{") break;
    let depth = 0;
    let inStr = false;
    let esc = false;
    let j = i;
    for (; j < raw.length; j++) {
      const c = raw[j];
      if (inStr) {
        if (esc) esc = false;
        else if (c === "\\") esc = true;
        else if (c === '"') inStr = false;
      } else if (c === '"') inStr = true;
      else if (c === "{") depth++;
      else if (c === "}") {
        depth--;
        if (depth === 0) {
          j++;
          break;
        }
      }
    }
    try {
      recs.push(JSON.parse(raw.slice(i, j)));
    } catch {
      break;
    }
    i = j;
  }
  return recs;
};

let records = parseRecords(readFileSync(file, "utf8"));
if (onlyRecord !== null) {
  records = records.filter((r) => String(r.seq) === String(onlyRecord));
}

const shortUrl = (u) => {
  if (!u) return "?";
  if (!u.startsWith("http")) return "inline";
  const path = u.split("?")[0];
  return path.split("/").pop() || u;
};
const trunc = (s, n = TRUNC) =>
  typeof s === "string" && s.length > n ? s.slice(0, n) + "…" : String(s);

const detailScopes = (frame) => {
  const lines = [];
  for (const sc of frame.scopes ?? []) {
    if (sc.shared) {
      lines.push(`    [${sc.type}] (shared — captured in an inner frame)`);
      continue;
    }
    if (!["local", "block", "catch"].includes(sc.type) && deepFrame === null) {
      // Non-local scopes are huge; only show in deep-dump mode.
      lines.push(`    [${sc.type}] ${(sc.variables ?? []).length} vars (use --frame to expand)`);
      continue;
    }
    for (const v of sc.variables ?? []) {
      const mark = grep && typeof v.value === "string" && v.value.includes(grep) ? " *" : "";
      const xform = TRANSFORM_MARKERS.test(String(v.value)) ? " ⟨xform⟩" : "";
      lines.push(`    [${sc.type}] ${v.name} = ${trunc(v.value)}${mark}${xform}`);
    }
  }
  return lines;
};

// --grep: locate matches across ALL frames/scopes (not just detailed ones).
const grepMatches = (rec) => {
  const hits = [];
  rec.frames?.forEach((fr, fi) => {
    for (const sc of fr.scopes ?? []) {
      for (const v of sc.variables ?? []) {
        if (typeof v.value === "string" && grep && v.value.includes(grep)) {
          hits.push(`    @frame${fi} ${fr.functionName} [${sc.type}] ${v.name} = ${trunc(v.value)}`);
        }
      }
    }
  });
  return hits;
};

if (asJson) {
  const out = records.map((r) => ({
    target: r.target,
    seq: r.seq,
    chain: (r.frames ?? []).map(
      (f) => `${f.functionName} @ ${shortUrl(f.url)}:${f.lineNumber}:${f.columnNumber}`,
    ),
    matches: grep ? grepMatches(r) : undefined,
  }));
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  process.exit(0);
}

const lines = [];
lines.push(`${records.length} record(s) in ${file}`);
for (const r of records) {
  const frames = r.frames ?? [];
  lines.push("");
  lines.push(`record ${r.seq} [${r.target}]`);
  lines.push(
    "  chain: " +
      frames
        .map((f) => `${f.functionName}@${shortUrl(f.url)}:${f.lineNumber}:${f.columnNumber}`)
        .join(" <- "),
  );

  if (deepFrame !== null) {
    const k = Number(deepFrame);
    const fr = frames[k];
    if (fr) {
      lines.push(`  -- frame ${k} ${fr.functionName} (all scopes) --`);
      lines.push(...detailScopes(fr));
    }
    continue;
  }

  const detail = frames.slice(0, nFrames);
  detail.forEach((fr, fi) => {
    lines.push(`  frame${fi} ${fr.functionName} @ ${shortUrl(fr.url)}:${fr.lineNumber}:${fr.columnNumber}`);
    lines.push(...detailScopes(fr));
  });

  if (grep) {
    const hits = grepMatches(r);
    if (hits.length) {
      lines.push(`  grep "${grep}" matches:`);
      lines.push(...hits);
    }
  }
}
process.stdout.write(lines.join("\n") + "\n");
