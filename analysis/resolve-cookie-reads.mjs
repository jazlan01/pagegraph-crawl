#!/usr/bin/env node
// resolve-cookie-reads.mjs — turn jar-wide document.cookie reads into per-cookie INFERRED read sites.
//
//   node analysis/resolve-cookie-reads.mjs <code-sites.json> <out.json> [--provider openai] [--cache <file>]
//
// PageGraph records a JS read as a `read storage call` on the whole cookie JAR — document.cookie
// returns every cookie as one string, so the graph cannot say which cookie a read wanted. But the
// read SITE (script + offset) and its call stack are recorded, and the code around them names the
// cookie in the two resolvable cases: an inline `name=` literal, or a `getCookie(name)` argument one
// frame up. We let the smallest model READ that code and name the cookie(s) — the only approach that
// generalises across the long tail of getter shapes (a regex never would).
//
// This is INFERENCE, not graph truth. It is stored/rendered as an inferred read, kept separate from
// the structural jar-wide reads — the same separation as Pass A (name inference) vs observed behaviour.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { runHead, headAvailable } from "./lib/llm-head-chat.mjs";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const [inPath, outPath] = argv.filter((a) => !a.startsWith("--"));
const provider = flag("--provider", process.env.CLASSIFIER_PROVIDER || "openai");
const cachePath = flag("--cache", null);
const log = (m) => process.stderr.write(m + "\n");
if (!inPath || !outPath) { log("usage: resolve-cookie-reads.mjs <code-sites.json> <out.json> [--provider p] [--cache f]"); process.exit(1); }
if (!headAvailable(provider)) { log(`no API key for ${provider}`); process.exit(1); }

const SYSTEM = `You are shown a JavaScript site where document.cookie is read, plus the call stack above the read (each frame carries its own source). document.cookie returns EVERY cookie on the domain as one "name=value; name=value" string, so the code almost always then matches, splits, or looks up ONE specific cookie. Determine which cookie NAME(S) this code extracts.

- A cookie name counts ONLY as a QUOTED STRING LITERAL — 'OptanonConsent', "_ga", or the literal inside a regex like /_ga=/. The actual bytes of the cookie key.
- scope "named": the specific cookie name appears as a quoted string literal — at the read site (document.cookie.match(/_ga=/), split(';').find(c=>c.startsWith('_ga='))) OR as a quoted argument at a caller frame up the stack (getCookie('_ga')). Put the literal string(s) in "reads".
- CRITICAL: a bare identifier / variable / constant is NOT a name. If the argument is getCookie(ALERT_BOX_CLOSED) or getCookie(name) or an obfuscated key like G(39), and the STRING VALUE of that identifier is not shown in the provided code, the scope is "unknown" — do NOT report the identifier's spelling as the cookie name. Only report the identifier's value if its assignment to a string literal is visible in the code shown.
- scope "all": the code enumerates or uses the WHOLE jar without selecting one — a consent platform, analytics fingerprinter, or a loop over every cookie. "reads" is empty.
- scope "unknown": the target name is a variable/computed value you cannot resolve to a visible string literal. "reads" is empty.
- If several distinct string literals are read here, list them all.
- confidence is TEXT (low-confidence / medium-confidence / high-confidence / fully-sure), never a number.`;

const SCHEMA = {
  type: "json_schema",
  json_schema: {
    name: "cookie_read_resolution", strict: true,
    schema: {
      type: "object", additionalProperties: false,
      required: ["reads", "scope", "confidence", "reasoning"],
      properties: {
        reads: { type: "array", items: { type: "string" }, description: "cookie names, empty unless scope=named" },
        scope: { type: "string", enum: ["named", "all", "unknown"] },
        confidence: { type: "string", enum: ["low-confidence", "medium-confidence", "high-confidence", "fully-sure"] },
        reasoning: { type: "string", description: "<=15 words citing the code" },
      },
    },
  },
};

const { pageUrl, cookies, readSites } = JSON.parse(readFileSync(inPath, "utf8"));
const cache = cachePath && existsSync(cachePath) ? JSON.parse(readFileSync(cachePath, "utf8")) : {};

// Content hash so the cache survives across crawls (node ids are not stable; code is).
const siteHash = (rs) => createHash("sha256").update(`${rs.scriptUrl}|${rs.line}|${rs.before}|${rs.after}`).digest("hex").slice(0, 16);
const codeStr = (s) => s.hasSource ? `${s.before ?? ""}⟨HERE⟩${s.after ?? ""}` : "(source not recorded)";
const payloadFor = (rs) => ({
  readSite: { script: rs.scriptUrl, line: rs.line, code: codeStr(rs) },
  callStack: (rs.stack || []).map((f) => ({ fn: f.fn, script: f.scriptUrl, line: f.line, code: f.hasSource ? `${f.before ?? ""}⟨HERE⟩${f.after ?? ""}` : null })),
});

let calls = 0, cached = 0, usage = { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
const resolveOne = async (rs) => {
  if (!rs.hasSource) return { reads: [], scope: "unknown", confidence: "low-confidence", reasoning: "source not recorded for this script" };
  const h = siteHash(rs);
  if (cache[h]) { cached++; return cache[h]; }
  const r = await runHead(SYSTEM, payloadFor(rs), { provider, responseFormat: SCHEMA, maxTokens: 700 });
  calls++;
  if (r._usage) { usage.prompt_tokens += r._usage.prompt_tokens || 0; usage.completion_tokens += r._usage.completion_tokens || 0; usage.total_tokens += r._usage.total_tokens || 0; }
  const out = { reads: r.reads || [], scope: r.scope || "unknown", confidence: r.confidence || "low-confidence", reasoning: r.reasoning || "" };
  cache[h] = out;
  return out;
};

// Resolve every distinct read site (bounded concurrency).
const pool = async (items, n, fn) => { const out = new Array(items.length); let i = 0; const w = async () => { while (i < items.length) { const k = i++; try { out[k] = await fn(items[k], k); } catch (e) { out[k] = { __error: String(e?.message ?? e) }; } } }; await Promise.all(Array.from({ length: Math.min(n, items.length) }, w)); return out; };

log(`resolving ${readSites.length} read site(s) via ${provider}`);
const resolutions = await pool(readSites, 8, resolveOne);

// Attribute: build per-cookie inferred read sites. A resolved site names cookie(s) → attach to each.
// scope "all" attaches to every requested cookie (as a jar-enumeration note); "unknown" attaches to none.
const cookieNames = Object.keys(cookies);
const byCookie = Object.fromEntries(cookieNames.map((c) => [c, []]));
const sites = [];
readSites.forEach((rs, idx) => {
  const res = resolutions[idx] || {};
  const site = { scriptUrl: rs.scriptUrl, inline: rs.inline, line: rs.line, col: rs.col, before: rs.before, after: rs.after, hasSource: rs.hasSource,
    reads: res.reads || [], scope: res.scope || "unknown", confidence: res.confidence, reasoning: res.reasoning, stack: rs.stack };
  sites.push(site);
  if (res.scope === "named") for (const name of res.reads) if (byCookie[name]) byCookie[name].push(site);
  else if (res.scope === "all") for (const c of cookieNames) byCookie[c].push({ ...site, jarWide: true });
});

if (cachePath) writeFileSync(cachePath, JSON.stringify(cache, null, 2));
writeFileSync(outPath, JSON.stringify({ pageUrl, cookies, readSites: sites, resolvedReadsByCookie: byCookie,
  stats: { sites: readSites.length, llmCalls: calls, cacheHits: cached, usage,
    named: sites.filter((s) => s.scope === "named").length, all: sites.filter((s) => s.scope === "all").length, unknown: sites.filter((s) => s.scope === "unknown").length } }, null, 2));
log(`  ${calls} LLM call(s), ${cached} cache hit(s); named=${sites.filter((s) => s.scope === "named").length} all=${sites.filter((s) => s.scope === "all").length} unknown=${sites.filter((s) => s.scope === "unknown").length}`);
log(`  tokens: ${usage.total_tokens} -> ${outPath}`);
