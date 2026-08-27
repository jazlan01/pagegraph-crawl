#!/usr/bin/env node
// combined-cookie-report.mjs — one report, a row per cookie per website, three views side by side:
//   OBSERVED (our independent behavioural classifier)  |  DECLARED (the site's own CMP)  |  MCP
//   (the VaultJS name-corpus classifier), plus the declared-vs-observed VERDICT.
//
//   node analysis/combined-cookie-report.mjs --crawl-root output/clients-2026-08-02-fixed \
//        --classify-root output --out output/combined-cookie-report.html
//
// The three columns have different provenance and the report keeps them visibly distinct:
//   - Observed is ours, from behaviour, independent of the other two.
//   - Declared is the site's own claim (its OneTrust/CMP ruleset).
//   - MCP is a name-corpus verdict, shown as an EXTERNAL reference only — never the yardstick, and
//     name-keyed, so it is identical for a given cookie name across sites (stated in the report).
// The VERDICT is strictly declared-vs-observed (the MCP does not feed it).

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { isGraphPath } from "./lib/graph-source.mjs";
import { join } from "node:path";

import { buildComparisonRow, TRACKING, STATUS_META, STATUS_ORDER } from "./lib/declared-observed.mjs";

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i !== -1 ? argv[i + 1] : d; };
const crawlRoot = flag("--crawl-root", "output/clients-2026-08-02-fixed");
const classifyRoot = flag("--classify-root", "output");
const outPath = flag("--out", "output/combined-cookie-report.html");
const only = argv.filter((a) => !a.startsWith("--") && a !== crawlRoot && a !== classifyRoot && a !== outPath);

const readJson = (p) => (p && existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null);
const pick = (dir, suffix) => { const f = existsSync(dir) && readdirSync(dir).find((x) => x.endsWith(suffix)); return f ? join(dir, f) : null; };

const mcp = readJson(new URL("./data/cookie-verdicts-mcp.json", import.meta.url).pathname) || { records: {} };
const mcpIcc = (name) => {
  const r = mcp.records[name];
  // Carry the corpus's per-label reasoning (`why`) so the MCP column can show evidence too.
  return r ? (r.icc || []).filter((x) => (x.p ?? 0) >= 0.5).map((x) => ({ label: x.label, why: x.why || null })) : null;
};

const sites = (only.length ? only : readdirSync(crawlRoot))
  .filter((s) => { try { return readdirSync(join(crawlRoot, s)).some((f) => isGraphPath(f)); } catch { return false; } })
  .sort();

const perSite = [];
for (const site of sites) {
  const crawlDir = join(crawlRoot, site);
  const declaration = readJson(pick(crawlDir, ".declaration.json")) || { cmp: null, cookies: {} };
  const jarRaw = readJson(pick(crawlDir, ".cookies.json")) || [];
  const jar = Array.isArray(jarRaw) ? jarRaw : (jarRaw.cookies || []);
  const clsDir = join(classifyRoot, `classify-v2-${site}`);
  const observed = new Map();
  if (existsSync(clsDir)) for (const f of readdirSync(clsDir)) {
    if (f.endsWith(".json") && f !== "_index.json") { const d = readJson(join(clsDir, f)); if (d?.cookie) observed.set(d.cookie, d); }
  }
  const rows = jar.map((c) => {
    const od = observed.get(c.name);
    const row = buildComparisonRow({ name: c.name, host: c.domain, declaration, observedDoc: od });
    row.mcp = mcpIcc(c.name); // null = MCP has no record for this name
    // The graph-distilled feature vector the classifier actually saw — the "parts of the graph"
    // behind the labels. Carried so the report can trace each verdict back to concrete edges.
    row.features = od?.features || null;
    // The exact name-free behaviour subgraph Pass B saw — the real graph edges (channel/party per
    // transmission), rendered as the evidence section. Falls back to `features` text facts if absent.
    row.subgraph = od?.behaviourSubgraph || null;
    // The exact source that wrote/read the cookie (extracted for tracking-labelled cookies) — the
    // "where to fix it" layer for developers reading this report.
    row.codeSites = od?.codeSites || null;
    // Per-destination outbound records: what part of the value left, to whom, with the actual
    // request bytes and highlight offsets. The "what was sent" evidence boxes render from this.
    row.outbound = od?.outbound || null;
    // The classifier's own prose: the holistic "why this verdict" (final evidence_summary) plus
    // the three-pass decision trace (name → behaviour → reconciliation), so a surprising label can
    // be understood rather than just seen.
    const passSummary = (v) => ({ icc: (v?.icc_uk_categories || []).map((x) => x.label), summary: v?.evidence_summary || null });
    row.passes = od ? { inferred: passSummary(od.inferred), exercised: passSummary(od.exercised), final: passSummary(od.final) } : null;
    return row;
  }).sort((a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || a.name.localeCompare(b.name));
  perSite.push({ site, cmp: declaration.cmp, rows });
}

// ---- rollup ----------------------------------------------------------------
const all = perSite.flatMap((s) => s.rows);
const count = (pred, rows = all) => rows.filter(pred).length;

// What did pass 3 (reconciliation) DO to each cookie, relative to pass A (identity, from the name)
// and pass B (behaviour, name-blind)? Computed from the three passes' ICC label sets.
const setEq = (a, b) => { const A = new Set(a || []), B = new Set(b || []); return A.size === B.size && [...A].every((x) => B.has(x)); };
const pass3Action = (p) => {
  if (!p || !p.final) return null;
  const A = p.inferred?.icc, B = p.exercised?.icc, C = p.final?.icc;
  if (setEq(C, A) && setEq(C, B)) return { key: "unchanged", label: "A = B = C · nothing to reconcile", cls: "p3-none" };
  if (setEq(C, A)) return { key: "tookA", label: "kept identity (A), overrode behaviour (B)", cls: "p3-a" };
  if (setEq(C, B)) return { key: "tookB", label: "kept behaviour (B), overrode identity (A)", cls: "p3-b" };
  return { key: "blend", label: "new blend · differs from both A and B", cls: "p3-blend" };
};
for (const r of all) r.p3 = pass3Action(r.passes);

const roll = {
  sites: perSite.length, cookies: all.length,
  underDeclared: count((r) => r.status === "mismatch-under-declared"),
  contradictory: count((r) => r.status === "contradictory-declaration"),
  necessaryButTracking: count((r) => (r.status === "mismatch-under-declared" || r.status === "contradictory-declaration") && r.declaredCats.includes("Necessary") && r.observed.some((l) => TRACKING.has(l))),
  mcpAgreesObserved: count((r) => r.mcp && r.observed.length && r.mcp.map((x) => x.label).sort().join() === r.observed.slice().sort().join()),
  mcpScorable: count((r) => r.mcp && r.observed.length),
  p3Unchanged: count((r) => r.p3?.key === "unchanged"),
  p3TookA: count((r) => r.p3?.key === "tookA"),
  p3TookB: count((r) => r.p3?.key === "tookB"),
  p3Blend: count((r) => r.p3?.key === "blend"),
};

// ---- render ----------------------------------------------------------------
const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
// CMP descriptions are HTML with entities (Google&#39;s) and tags (<a href>). Decode entities and
// strip tags to plain text before we re-escape, or the reader sees the raw &#39; / &amp;.
const deHtml = (s) => String(s ?? "")
  .replace(/<[^>]*>/g, "")
  .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n))
  .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
  .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
// Attribute-safe: a title= value must also escape quotes, or the attribute terminates early.
const escAttr = (s) => esc(deHtml(s)).replace(/"/g, "&quot;");
const chip = (t, cls, title) => `<span class="chip ${cls || ""}"${title ? ` title="${escAttr(title)}"` : ""}>${esc(t)}</span>`;
const cls = (label) => (TRACKING.has(label) ? "trk" : "ben");

// A cell of labels WITH per-label evidence. `entries` is [{label, reasoning|why|...}]. Each label
// is a chip (hover shows its justification) and, below, a short "label — evidence" line so the
// reason is visible without hovering and survives printing. `extra` is a trailing muted line
// (confidence, TCF purposes, CMP group names).
const labelCell = (entries, evidenceKey, extra) => {
  if (!entries || !entries.length) return `<span class="muted">—</span>`;
  const chips = entries.map((e) => chip(e.label, cls(e.label), e[evidenceKey])).join(" ");
  const ev = entries.filter((e) => e[evidenceKey]).map((e) =>
    `<div class="ev"><span class="ev-l ${cls(e.label)}">${esc(e.label)}</span> ${esc(e[evidenceKey])}</div>`).join("");
  return `${chips}${extra ? ` ${extra}` : ""}${ev}`;
};

// The concrete graph facts the classifier saw — the "parts of the graph" behind the labels — as a
// collapsible block, each fact tagged with the graph structure (edge type) it came from. Only the
// features with signal are emitted, so a quiet cookie shows a short block and a busy one a long one.
const gList = (xs, n = 6) => (xs || []).slice(0, n).map(esc).join(", ") + ((xs || []).length > n ? ` +${xs.length - n} more` : "");
const graphEvidenceLegacy = (f) => {
  if (!f) return "";
  const groups = [];
  const push = (edge, facts) => { const kept = facts.filter(Boolean); if (kept.length) groups.push([edge, kept]); };

  push("storage-set edges — who wrote it", [
    f.settingScripts?.length && `written by JS: ${gList(f.settingScripts)}`,
    f.setterHosts?.length && `setter host(s): ${gList(f.setterHosts)}`,
    (f.setChannels?.length || f.setterParties?.length) &&
      `channel: ${esc((f.setChannels || []).join("+") || "?")}, party: ${esc((f.setterParties || []).join("+") || "?")}`,
    f.writeCount && `written ${f.writeCount}× this load${f.distinctWriteValues ? `, ${f.distinctWriteValues} distinct value(s)` : ""}` +
      `${f.valueMutated ? " — value mutated" : f.refreshedWithSameValue ? " — same value re-set" : ""}${f.embeddedTimestampAdvanced ? ", embedded timestamp advanced" : ""}`,
    f.httpSetCount && `Set-Cookie response headers: ${f.httpSetCount}`,
  ]);
  push("network / request edges — where the value went", [
    f.thirdPartyExfilDestinations?.length ? `value reached third-party host(s): ${gList(f.thirdPartyExfilDestinations)}`
      : f.exfilDestinations?.length && `value reached: ${gList(f.exfilDestinations)}`,
    f.cookieHeaderRequests && `carried on ${f.cookieHeaderRequests} outgoing request(s) in the Cookie header`,
    f.bodyExfil && `found in ${f.bodyExfil} request body/ies`,
    f.urlParamExfil && `found in ${f.urlParamExfil} URL parameter(s)`,
    f.requestHeaderExfil && `found in ${f.requestHeaderExfil} request header(s)`,
    f.transformedThenSent && `value transformed by JS then sent${f.transformedThenSentCount ? ` to ${f.transformedThenSentCount} destination(s)` : ""} (js-call → js-result taint)`,
  ]);
  push("response edges — where it came from", [
    f.bodyInfil && `value arrived in ${f.bodyInfil} response body/ies${f.infilSourceHosts?.length ? ` from ${gList(f.infilSourceHosts)}` : ""}${f.bodyInfilLowConfidence ? " (short value — low-confidence match)" : ""}`,
  ]);
  push("redirect / sync edges", [
    f.redirectChain?.length && `setter appeared in a redirect chain: ${f.redirectChain.map(esc).join("  ;  ")}`,
    f.setterAlsoEndpointForOtherCookies && `setter domain also collected ${f.setterAlsoEndpointForOtherCookies} other cookie(s)`,
  ]);
  push("script ↔ cookie structure", [
    (f.writerCount > 1 || f.maxCookiesPerWriter > 1) && `${f.writerCount} writer script(s); one writer set up to ${f.maxCookiesPerWriter} cookies`,
    f.writerSetMaxJaccard && `writer-set overlap with another cookie: ${f.writerSetMaxJaccard} (same code planted both)`,
  ]);
  push("cookie attributes", [
    `${esc(f.party || "?")}-party${f.persistent ? ", persistent" : ""}${f.httpOnly ? ", httpOnly" : ""}${f.sameSite ? `, SameSite=${esc(f.sameSite)}` : ""}${f.valueLength ? `, ${f.valueLength}-char value` : ""}`,
  ]);

  if (!groups.length) return "";
  return `<details class="gev"><summary>graph evidence</summary>${groups.map(([edge, facts]) =>
    `<div class="gev-g"><span class="gev-h">${esc(edge)}</span><ul>${facts.map((x) => `<li>${x}</li>`).join("")}</ul></div>`).join("")}</details>`;
};

// The graph portions the classifier actually reasoned over — the deduped behaviour SUBGRAPH edges,
// not counts. Each transmission carries its CHANNEL (auto-cookie-header vs js-initiated) and PARTY,
// because that distinction is what decides purpose: a value auto-attached to a same-party request is
// not evidence, a deliberate JS send to a third party is. Falls back to the legacy text facts when a
// record predates subgraph persistence.
const HOSTCAP = 8;
const eHost = (h) => `<code class="eh">${esc(h || "?")}</code>`;
const eCount = (n) => (n > 1 ? `<span class="ecnt">&times;${n}</span>` : "");
const ePartyTag = (p) => `<span class="etag et-${p === "third" ? "third" : "first"}">${p === "third" ? "3rd-party" : p === "first" ? "1st-party" : esc(p || "?")}</span>`;
const eChanTag = (c) => {
  const k = c === "auto-cookie-header" ? "auto" : (c === "js-initiated" || c === "js") ? "js" : c === "set-cookie-header" ? "http" : "mut";
  return `<span class="etag et-${k}">${esc(c)}</span>`;
};
const eCapNote = (arr) => (arr.length > HOSTCAP ? `<li class="emore">+${arr.length - HOSTCAP} more</li>` : "");
const graphEvidence = (sg, f) => {
  if (!sg) return graphEvidenceLegacy(f);
  const groups = [];
  const g = (edge, lis) => { const kept = lis.filter(Boolean); if (kept.length) groups.push([edge, kept]); };

  g("set edges — who wrote it, and how", (sg.writeSites || []).slice(0, HOSTCAP).map((w) =>
    `<li>${eHost(w.host)} ${eChanTag(w.channel)} ${ePartyTag(w.party)}${eCount(w.count)}` +
    `${w.script ? `<div class="escript">${esc(w.script)}</div>` : ""}</li>`).concat(eCapNote(sg.writeSites || [])));

  g("transmission edges — where the value went", (sg.transmissions || []).slice(0, HOSTCAP).map((t) =>
    `<li>${eHost(t.host)} <span class="emeth">${esc(t.method || "")}</span> ${eChanTag(t.channel)} ${ePartyTag(t.party)}` +
    // Outbound characterisation, when the record carries it (older records render as before).
    `${t.sentForm ? ` <span class="etag et-form">${esc(t.sentForm)}</span>` : ""}` +
    `${t.carriesIdentifier === true ? ` <span class="etag et-id">carries identifier</span>` : t.carriesIdentifier === false ? ` <span class="etag et-noid">no identifier</span>` : ""}` +
    `${eCount(t.count)}</li>`)
    .concat(eCapNote(sg.transmissions || [])));

  g("taint path — value read, transformed by JS, then sent", (sg.taintPaths || []).slice(0, HOSTCAP).map((t) =>
    `<li>${eHost(t.consumerScriptHost)} <span class="earr">&rarr;</span> ${eHost(t.destinationHost)} ${ePartyTag(t.party)} ` +
    `<span class="emut">transform round ${t.transformRound}</span>${eCount(t.count)}</li>`).concat(eCapNote(sg.taintPaths || [])));

  g(`read edges — ${(sg.readers || []).length} reader script(s), attribution is jar-wide`, (sg.readers || []).slice(0, HOSTCAP).map((r) =>
    `<li>${eHost(r.host)} ${ePartyTag(r.party)}${eCount(r.count)}</li>`).concat(eCapNote(sg.readers || [])));

  g("redirect / sync edges", (sg.redirectChains || []).slice(0, 6).map((c) => `<li><code class="echain">${esc(c)}</code></li>`));

  const be = sg.bodyExfil, bi = sg.bodyInfil;
  g("body edges", [
    be?.count ? `<li>value in ${be.count} request body/ies${be.toHosts?.length ? ` &rarr; ${be.toHosts.slice(0, 4).map(esc).join(", ")}` : ""}</li>` : null,
    bi?.count ? `<li>value arrived in ${bi.count} response body/ies${bi.fromHosts?.length ? ` from ${bi.fromHosts.slice(0, 4).map(esc).join(", ")}` : ""}${bi.lowConfidence ? " (low-confidence match)" : ""}</li>` : null,
  ]);

  const s = sg.signals || {};
  const flags = [
    s.valueMutated ? `value mutated across writes (${s.distinctWriteValues ?? "?"} distinct)` : s.refreshedWithSameValue ? "re-set with the same value" : null,
    s.embeddedTimestampAdvanced ? "embedded timestamp advanced" : null,
    s.setterInRedirectChain || s.setterRedirected ? "setter appeared in a redirect chain" : null,
    // "transformed" was a misnomer (any JS-initiated send set it); say what is actually known.
    s.derivedValueSent ? "value derived by JS, then sent"
      : (s.jsInitiatedSend ?? s.transformedThenSent) ? "value deliberately sent by page JS" : null,
    s.setterAlsoEndpointForOtherCookies ? `setter also collected ${s.setterAlsoEndpointForOtherCookies} other cookie(s)` : null,
  ].filter(Boolean);
  g("signals", flags.length ? [`<li>${flags.join("; ")}</li>`] : []);

  const at = sg.attributes || {};
  g("cookie attributes", [`<li>${esc(at.party || "?")}-party${at.persistent ? ", persistent" : ""}${at.httpOnly ? ", httpOnly" : ""}${at.secure ? ", secure" : ""}${at.sameSite ? `, SameSite=${esc(at.sameSite)}` : ""}${at.valueLength ? `, ${at.valueLength}-char value` : ""}</li>`]);

  if (!groups.length) return "";
  return `<details class="gev"><summary>graph evidence</summary>${groups.map(([edge, facts]) =>
    `<div class="gev-g"><span class="gev-h">${esc(edge)}</span><ul>${facts.join("")}</ul></div>`).join("")}</details>`;
};

// ---- what was sent, per destination -----------------------------------------------------------
// The evidence box this report exists for: the actual request bytes that carried the cookie value
// (or a part of it) to each destination, with the matched part highlighted. Answers "which part
// of this cookie was exfiltrated, and to whom" without anyone re-running the analysis by hand.
//
// Highlighting is escape-aware: the excerpt is split at range boundaries, each SEGMENT is
// HTML-escaped, and only then are the matched segments wrapped in <mark> — escaping after
// marking would corrupt offsets and print literal tags.
const markExcerpt = (excerpt, ranges) => {
  const ex = String(excerpt ?? "");
  if (!ex) return "";
  // sort + merge overlapping ranges, clip to the excerpt
  const merged = [];
  for (const [s, e] of (ranges || []).map(([s, e]) => [Math.max(0, s), Math.min(e, ex.length)])
    .filter(([s, e]) => e > s).sort((a, b) => a[0] - b[0])) {
    const last = merged[merged.length - 1];
    if (last && s <= last[1]) last[1] = Math.max(last[1], e);
    else merged.push([s, e]);
  }
  let html = "", pos = 0;
  for (const [s, e] of merged) {
    html += esc(ex.slice(pos, s)) + `<mark class="ob-mark">${esc(ex.slice(s, e))}</mark>`;
    pos = e;
  }
  html += esc(ex.slice(pos));
  return html;
};

const FORM_LABEL = { raw: "raw value", "re-encoded": "re-encoded value", fragment: "value fragment", derived: "derived value" };
const obBadge = (o) => {
  if (o.carriesIdentifier === true) {
    return `<span class="ob-badge ${o.party === "third" ? "ob-bad" : "ob-warn"}">identifier ${o.party === "third" ? "→ 3rd party" : "sent"}</span>`;
  }
  if (o.carriesIdentifier === false) return `<span class="ob-badge ob-ok">no identifier in what was sent</span>`;
  return `<span class="ob-badge ob-unk">identifier: unknown</span>`;
};
const obBox = (o) => {
  const idParts = (o.matchedParts || []).filter((p) => p.isIdentifier);
  const partsLine = idParts.length
    ? `<div class="ob-parts">identifier part(s) in the request: ${idParts.map((p) => `<code>${esc(p.key)}</code> <span class="ob-kind">${esc(p.kind)}</span>`).join(", ")}</div>`
    : o.coverage === "full-value" ? `<div class="ob-parts muted">entire stored value left${o.valueSnapshot === "earlier" ? " (an earlier snapshot of it)" : ""}; no identifier-grade part recognised inside it</div>` : "";
  const shared = o.sharedWithCookies?.length
    ? `<div class="ob-shared">same identifier also stored in: ${o.sharedWithCookies.map((n) => `<code>${esc(n)}</code>`).join(", ")}</div>` : "";
  const excerpt = o.excerpt
    ? `<pre class="ob-excerpt">${markExcerpt(o.excerpt, o.matchRanges)}</pre>`
    : `<div class="ob-noexcerpt">sent via the automatic <code>Cookie:</code> request header — the browser attaches the whole cookie; header bytes are not captured</div>`;
  return `<div class="ob-box ${o.carriesIdentifier === true && o.party === "third" ? "ob-hot" : ""}">
    <div class="ob-hd">
      <span class="ob-host">${esc(o.host)}</span>${o.url ? `<span class="ob-path">${esc(String(o.url).replace(/^https?:\/\/[^/]+/, ""))}</span>` : ""}
      ${ePartyTag(o.party)} ${(o.channels || []).map((c) => eChanTag(c === "js-body" || c === "js-url" ? "js-initiated" : c)).join(" ")}
      <span class="etag et-form">${esc(FORM_LABEL[o.sentForm] || o.sentForm)}</span>
      ${o.valueSnapshot === "earlier" ? `<span class="etag et-snap" title="The bytes match an earlier write of this cookie, not its final value — its stable identifier parts are unchanged.">earlier snapshot</span>` : ""}
      ${obBadge(o)}
    </div>
    ${partsLine}${shared}${excerpt}
  </div>`;
};
const outboundEvidence = (outbound) => {
  if (!outbound?.length) return "";
  // Third-party identifier carriage first — that is the finding; benign propagation after.
  const rank = (o) => (o.carriesIdentifier === true ? 2 : o.carriesIdentifier === "unknown" ? 1 : 0) + (o.party === "third" ? 4 : 0);
  const rows = outbound.slice().sort((a, b) => rank(b) - rank(a)).slice(0, 10);
  const hot = rows.some((o) => o.carriesIdentifier === true && o.party === "third");
  return `<details class="gev ob"${hot ? " open" : ""}><summary>what was sent — per destination</summary>${rows.map(obBox).join("")}</details>`;
};

// The specific SOURCE that touched the cookie — the exact script + line that WROTE or READ it, with
// a code excerpt and the call stack. This is the "where do I fix it" layer: a dev reads the label,
// opens the named script at the named line, and sees the write. Only present for cookies we ran the
// code extractor over (the tracking-labelled set).
const shortUrl = (u) => {
  if (!u) return "?";
  try { const x = new URL(u); const base = x.pathname.split("/").filter(Boolean).pop() || x.hostname; return `${x.hostname}/…/${base}`; }
  catch { return String(u).slice(0, 60); }
};
const codeExcerpt = (s) => {
  if (!s.hasSource) return `<div class="cs-nosrc">(source not recorded for this script)</div>`;
  return `<pre class="cs-code">${esc(s.before || "")}<mark class="cs-mark">◤</mark>${esc(s.after || "")}</pre>`;
};
const codeStack = (stack) => {
  if (!stack?.length) return "";
  return `<div class="cs-stack">${stack.map((f) => `${esc(f.fn)}<span class="cs-fl"> ${esc(shortUrl(f.url))}:${f.line ?? "?"}</span>`).join(' <span class="cs-arr">&larr;</span> ')}</div>`;
};
const codeSite = (s, what) => `<div class="cs-site">` +
  `<div class="cs-hd"><span class="cs-what cs-${what}">${what}</span> ` +
  `<a class="cs-url" href="${escAttr(s.scriptUrl)}" title="${escAttr(s.scriptUrl)}" target="_blank" rel="noopener">${esc(shortUrl(s.scriptUrl))}</a>` +
  `<span class="cs-loc">:${s.line ?? "?"}:${s.col ?? "?"}</span>${s.inline ? ` <span class="cs-inline">inline</span>` : ""}` +
  `${s.channel ? ` <span class="cs-chan">${esc(s.channel)}</span>` : ""}</div>` +
  codeExcerpt(s) + codeStack(s.stack) + `</div>`;
// A SEND is where the value was read and put into a request — the exfiltration site. It leads with the
// DESTINATION (that is the finding); the script:line shows the code that did it.
const sendSite = (s, obByHost) => {
  // Join the outbound characterisation by destination host, so the send site states WHAT it sent.
  let sentLine = "";
  try {
    const o = obByHost?.get(new URL(s.destUrl).hostname);
    if (o) {
      const idParts = (o.matchedParts || []).filter((p) => p.isIdentifier).map((p) => p.key);
      sentLine = `<div class="cs-sent">sent: <b>${esc(FORM_LABEL[o.sentForm] || o.sentForm)}</b>` +
        (o.carriesIdentifier === true ? ` · carries identifier${idParts.length ? ` (${esc(idParts.join(", "))})` : ""}`
          : o.carriesIdentifier === false ? " · no identifier in the bytes" : " · identifier unknown") +
        ` — see <i>what was sent</i> above</div>`;
    }
  } catch { /* unparsable destUrl */ }
  return `<div class="cs-site cs-sendsite">` +
  `<div class="cs-hd"><span class="cs-what cs-sends">sends&nbsp;&rarr;</span> ` +
  `<span class="cs-dest">${esc(s.destUrl ? shortUrl(s.destUrl) : "(request)")}</span> ` +
  `<span class="cs-method">${esc(s.method || "")}</span></div>` + sentLine +
  `<div class="cs-hd cs-sub"><span class="cs-from">from</span> ` +
  `<a class="cs-url" href="${escAttr(s.scriptUrl)}" title="${escAttr(s.scriptUrl)}" target="_blank" rel="noopener">${esc(shortUrl(s.scriptUrl))}</a>` +
  `<span class="cs-loc">:${s.line ?? "?"}:${s.col ?? "?"}</span>${s.inline ? ` <span class="cs-inline">inline</span>` : ""}</div>` +
  codeExcerpt(s) + codeStack(s.stack) + `</div>`;
};
// An INFERRED read site — the cookie name was recovered by an LLM reading the code at a jar read, not
// from a structural graph edge. Styled distinctly (dashed) and labelled "inferred" so it is never
// mistaken for observed truth.
const readSite = (s) => `<div class="cs-site cs-readsite">` +
  `<div class="cs-hd"><span class="cs-what cs-reads">reads</span> ` +
  `<a class="cs-url" href="${escAttr(s.scriptUrl)}" title="${escAttr(s.scriptUrl)}" target="_blank" rel="noopener">${esc(shortUrl(s.scriptUrl))}</a>` +
  `<span class="cs-loc">:${s.line ?? "?"}:${s.col ?? "?"}</span>${s.inline ? ` <span class="cs-inline">inline</span>` : ""} ` +
  `<span class="cs-inferred" title="Recovered by reading the code at the read site — inference, not a graph edge.">inferred${s.confidence ? ` · ${esc(s.confidence)}` : ""}</span></div>` +
  codeExcerpt(s) + (s.reasoning ? `<div class="cs-reason">${esc(s.reasoning)}</div>` : "") + `</div>`;
const codeEvidence = (cs, outbound) => {
  if (!cs) return "";
  const obByHost = new Map((outbound || []).map((o) => [o.host, o]));
  const w = (cs.writes || []).slice(0, 4).map((s) => codeSite(s, "writes"));
  const sends = (cs.sends || []).filter((s) => s.isNetworkSink && s.destUrl);
  // Dedup sends by destination + line so a wrapped fetch does not repeat.
  const seen = new Set();
  const sh = sends.filter((s) => { const k = `${s.destUrl}|${s.scriptUrl}|${s.line}`; if (seen.has(k)) return false; seen.add(k); return true; })
    .slice(0, 4).map((s) => sendSite(s, obByHost));
  const resolved = cs.resolvedReads || [];
  const namedReads = resolved.filter((s) => s.scope === "named" && !s.jarWide);
  const rseen = new Set();
  const rd = namedReads.filter((s) => { const k = `${s.scriptUrl}|${s.line}`; if (rseen.has(k)) return false; rseen.add(k); return true; }).slice(0, 4).map(readSite);
  const d = (cs.deletes || []).slice(0, 2).map((s) => codeSite(s, "deletes"));
  const all = [...w, ...rd, ...sh, ...d];
  if (!all.length && !resolved.length) return "";
  // If no read site resolved to a literal cookie name, explain why: document.cookie returns the whole
  // jar, and this cookie is read via a variable / obfuscated key an LLM could not tie to a literal.
  const jarWide = resolved.some((s) => s.jarWide || s.scope === "all");
  const readNote = !rd.length
    ? `<div class="cs-note">No read site named this cookie by a string literal: <code>document.cookie</code> returns the whole jar and ${jarWide ? "a jar-enumerating script reads every cookie" : "this cookie is read via a variable / obfuscated key"}. Reader scripts are under <b>graph evidence &rarr; read edges</b>.</div>`
    : "";
  return `<details class="gev code"><summary>source — where it's set, read &amp; sent</summary>${all.join("")}${readNote}</details>`;
};

// The classifier's own reasoning: the final "why" sentence (always shown) and the three-pass
// decision trace (collapsible) — name-based inference, then name-blind behaviour, then the
// reconciliation that produced the final label. Makes a surprising verdict inspectable.
const classifierReasoning = (p, action) => {
  if (!p) return "";
  const p3 = action ? `<div class="p3 ${action.cls}"><span class="p3-t">pass 3</span> ${esc(action.label)}</div>` : "";
  const why = p.final?.summary ? `<div class="why"><span class="why-h">Why this verdict:</span> ${esc(p.final.summary)}</div>` : "";
  const pass = (h, x) => x && (x.icc?.length || x.summary)
    ? `<div class="gev-g"><span class="gev-h">${esc(h)}</span><div class="pass-l">${(x.icc || []).map((l) => esc(l)).join(" + ") || "—"}</div>${x.summary ? `<div class="pass-s">${esc(x.summary)}</div>` : ""}</div>` : "";
  const trace = `<details class="gev llm"><summary>classifier reasoning</summary>${
    pass("Pass A · inferred from the name", p.inferred)}${
    pass("Pass B · from behaviour, name-blind", p.exercised)}${
    pass("Pass C · reconciled (final)", p.final)}</details>`;
  return p3 + why + trace;
};

const rowHtml = (r) => {
  const m = STATUS_META[r.status];
  // Observed: per-label reasoning, the holistic "why", the 3-pass trace, WHAT WAS SENT (the
  // per-destination request bytes with the matched part highlighted), then graph + code facts.
  const obs = labelCell(r.observedIcc, "reasoning",
    r.observedConf ? `<span class="conf">${esc(r.observedConf)}</span>` : "") +
    (r.observedTcf.length ? `<div class="grp">TCF ${esc(r.observedTcf.slice(0, 4).join(" "))}</div>` : "") +
    classifierReasoning(r.passes, r.p3) +
    outboundEvidence(r.outbound) +
    graphEvidence(r.subgraph, r.features) +
    codeEvidence(r.codeSites, r.outbound);
  const declChips = r.declaredCats.length
    ? r.declaredCats.map((l) => chip(l, cls(l), r.declaredDesc)).join(" ")
    : `<span class="muted">not declared</span>`;
  const decl = `${declChips}${r.declaredGroups.length ? `<div class="grp">${esc(r.declaredGroups.join(", "))}</div>` : ""}` +
    (r.declaredDesc ? (() => { const t = deHtml(r.declaredDesc); return `<div class="ev">${esc(t.slice(0, 220))}${t.length > 220 ? "…" : ""}</div>`; })() : "");
  const mcpCell = r.mcp === null ? `<span class="muted">no record</span>` : labelCell(r.mcp, "why");
  return `<tr class="st-${m.cls}">
    <td class="ck"><code>${esc(r.name)}</code><div class="hst">${esc(r.host || "")}</div></td>
    <td>${obs}</td>
    <td>${decl}</td>
    <td>${mcpCell}</td>
    <td><span class="verdict ${m.cls}">${esc(m.label)}</span>${r.detail ? `<div class="detail">${esc(r.detail)}</div>` : ""}` +
    // Deterministic outbound facts — computed from the request bytes, never LLM prose, and
    // labelled as such so the two provenances stay visibly distinct.
    `${(r.outboundFacts || []).length ? `<div class="ob-facts"><span class="ob-facts-h">observed on the wire:</span> ${r.outboundFacts.map(esc).join("; ")}</div>` : ""}</td>
  </tr>`;
};

// One PAGE per site inside a single HTML file: sections toggled by a hash router, so the report
// stays one self-contained artifact while each site reads as its own page.
const slugOf = (site) => String(site).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

const siteCounts = (s) => ({
  u: s.rows.filter((r) => r.status === "mismatch-under-declared").length,
  c: s.rows.filter((r) => r.status === "contradictory-declaration").length,
  idSends: s.rows.filter((r) => (r.outbound || []).some((o) => o.carriesIdentifier === true && o.party === "third")).length,
});

const sitePage = (s) => {
  const { u, c, idSends } = siteCounts(s);
  return `<section class="page" id="site-${slugOf(s.site)}" hidden>
  <h1>${esc(s.site)} <span class="badge">${esc(s.cmp || "no CMP")}</span></h1>
  <div class="sitesum">${s.rows.length} cookies · <span class="${u ? "bad" : "ok"}">${u} under-declared</span> · <span class="${c ? "bad" : "ok"}">${c} contradictory</span> · <span class="${idSends ? "bad" : "ok"}">${idSends} cookie(s) whose identifier reached a third party</span></div>
  <div class="tbl-scroll"><table><thead><tr>
    <th>Cookie</th><th>Observed (ours, behaviour)</th><th>Declared (site CMP)</th><th>MCP (name corpus)</th><th>Verdict — declared vs observed</th>
  </tr></thead><tbody>${s.rows.map(rowHtml).join("")}</tbody></table></div>
</section>`;
};

// ---- overview page -----------------------------------------------------------
const siteIndexRow = (s) => {
  const { u, c, idSends } = siteCounts(s);
  return `<tr>
    <td><a class="site-link" href="#site-${slugOf(s.site)}">${esc(s.site)}</a><div class="hst">${esc(s.cmp || "no CMP")}</div></td>
    <td class="num">${s.rows.length}</td>
    <td class="num ${u ? "bad" : ""}">${u}</td>
    <td class="num ${c ? "bad" : ""}">${c}</td>
    <td class="num ${idSends ? "bad" : ""}">${idSends}</td>
  </tr>`;
};

const overviewPage = `<section class="page" id="overview">
  <h1>Observed vs declared vs MCP — per cookie, per site</h1>
  <div class="sub">${roll.cookies} cookies across ${roll.sites} sites. Three independent views side by side; the verdict compares only <b>our observed</b> classification against the <b>site's declaration</b>.</div>

  <div class="headline"><div class="n ${roll.necessaryButTracking ? "" : "zero"}">${roll.necessaryButTracking}</div>
    <div class="cap">cookie(s) the site declares <b>Strictly Necessary</b> that our behavioural classifier observed doing something requiring consent — a consent-exempt declaration the behaviour refutes.</div></div>

  <div class="tiles">
    <div class="tile bad"><div class="v">${roll.underDeclared}</div><div class="k">Under-declared</div></div>
    <div class="tile bad"><div class="v">${roll.contradictory}</div><div class="k">Contradictory decl.</div></div>
    <div class="tile"><div class="v">${roll.mcpScorable ? Math.round(100 * roll.mcpAgreesObserved / roll.mcpScorable) + "%" : "—"}</div><div class="k">MCP ↔ ours agree</div></div>
  </div>

  <div class="note"><b>Three columns, three provenances.</b> <b>Observed</b> is ours, from behaviour, and never saw the other two. <b>Declared</b> is the site's own CMP claim. <b>MCP</b> is a name-corpus classifier shown for reference only — it is <em>name-keyed</em>, so it is identical for a given cookie name across every site, and it is never the yardstick. The <b>verdict</b> is strictly declared-vs-observed; a Strictly-Necessary declaration is refuted when we observe tracking, and we abstain ("not assessable") where our own confidence is low. Each cookie's <b>what was sent</b> box shows the actual request bytes that carried its value, with the matched part highlighted — computed deterministically from the crawl's request bodies and headers, never by a model.</div>

  <h2>How pass 3 reconciled identity vs behaviour</h2>
  <div class="sitesum">The classifier runs three passes: <b>A</b> infers purpose from the cookie name, <b>B</b> re-decides from behaviour alone (name-blind), <b>C</b> reconciles them into the final label. Pass 3 acted on <b>${roll.p3TookA + roll.p3TookB + roll.p3Blend}</b> of ${roll.cookies} cookies. Each row's Observed cell carries a <b>pass 3</b> badge and the full three-pass trace.</div>
  <div class="tiles">
    <div class="tile"><div class="v">${roll.p3Unchanged}</div><div class="k">A = B = C (unchanged)</div></div>
    <div class="tile"><div class="v p3a">${roll.p3TookA}</div><div class="k">kept identity (A) over B</div></div>
    <div class="tile"><div class="v p3b">${roll.p3TookB}</div><div class="k">kept behaviour (B) over A</div></div>
    <div class="tile"><div class="v p3blend">${roll.p3Blend}</div><div class="k">new blend (neither)</div></div>
  </div>

  <h2>Websites</h2>
  <div class="tbl-scroll"><table class="idx"><thead><tr>
    <th>Website</th><th>Cookies</th><th>Under-declared</th><th>Contradictory</th><th>Identifier → 3rd party</th>
  </tr></thead><tbody>${perSite.map(siteIndexRow).join("")}</tbody></table></div>
</section>`;

const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cookie classification — observed vs declared vs MCP</title>
<style>
:root{--bg:#F7F8FA;--panel:#FFFFFF;--ink:#1C2433;--muted:#5C6575;--line:#E3E7EE;--accent:#2563EB;
--bad:#C62828;--warn:#A15C00;--ok:#157A55;--code:#3B4252;
--bad-bg:rgba(198,40,40,.07);--warn-bg:rgba(161,92,0,.09);--ok-bg:rgba(21,122,85,.08);--accent-bg:rgba(37,99,235,.07);
--sans:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box} html{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:1.05rem;line-height:1.55;-webkit-font-smoothing:antialiased}
.nav{position:sticky;top:0;z-index:10;background:var(--panel);border-bottom:1px solid var(--line);padding:.55rem 1.5rem;display:flex;flex-wrap:wrap;align-items:center;gap:.4rem}
.nav .brand{font-weight:700;font-size:.95rem;margin-right:.8rem;color:var(--ink)}
.nav a{color:var(--muted);text-decoration:none;font-size:.9rem;padding:.22rem .7rem;border-radius:6px;border:1px solid transparent}
.nav a:hover{color:var(--ink);background:var(--bg)}
.nav a.active{color:var(--accent);background:var(--accent-bg);border-color:rgba(37,99,235,.25);font-weight:600}
.nav .n-bad{display:inline-block;min-width:1.15rem;text-align:center;font-size:.85rem;font-weight:700;color:#fff;background:var(--bad);border-radius:9px;padding:0 .3rem;margin-left:.3rem;vertical-align:baseline}
.wrap{max-width:1280px;margin:0 auto;padding:2.2rem 1.5rem 5rem}
h1{font-size:2rem;margin:0 0 .3rem;letter-spacing:-.01em} h2{font-size:1.35rem;margin:2.6rem 0 .4rem;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:1rem;margin-bottom:1.5rem}
.badge{font-size:.85rem;color:var(--muted);border:1px solid var(--line);border-radius:5px;padding:.05rem .45rem;vertical-align:middle;font-weight:400}
.sitesum{color:var(--muted);font-size:.95rem;margin-bottom:.6rem} .sitesum .bad,.bad{color:var(--bad)} .sitesum .ok{color:var(--ok)}
.headline{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.4rem 1.7rem;margin:1.3rem 0;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.headline .n{font-size:2.7rem;font-weight:700;color:var(--bad);line-height:1} .headline .n.zero{color:var(--ok)}
.headline .cap{color:var(--muted);max-width:66ch}
.tiles{display:flex;flex-wrap:wrap;gap:.7rem;margin:1.1rem 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:.75rem 1rem;min-width:8rem;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.tile .v{font-size:1.5rem;font-weight:700;font-variant-numeric:tabular-nums} .tile .k{font-size:.85rem;color:var(--muted)}
.tile.bad .v{color:var(--bad)} .tile.ok .v{color:var(--ok)}
.note{background:var(--accent-bg);border-left:3px solid var(--accent);padding:.9rem 1.15rem;border-radius:0 8px 8px 0;margin:1.1rem 0;color:var(--ink);font-size:.95rem}
table{width:100%;border-collapse:separate;border-spacing:0;margin-top:.4rem;font-size:.95rem;background:var(--panel);border:1px solid var(--line);border-radius:10px}
/* Sticky column headers: stick just below the nav (height measured into --navh by the router
   script, since the tab row can wrap). border-collapse must be "separate" — collapsed borders
   detach from a sticky header — and the bottom rule rides a box-shadow for the same reason. */
th{text-align:left;color:var(--muted);font-weight:600;font-size:.85rem;padding:.55rem .6rem;background:var(--bg);position:sticky;top:var(--navh,49px);z-index:5;box-shadow:0 1px 0 var(--line)}
td{padding:.65rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
.idx td.num{font-variant-numeric:tabular-nums;font-weight:600} .idx td.num.bad{color:var(--bad)}
.site-link{color:var(--accent);font-weight:600;text-decoration:none} .site-link:hover{text-decoration:underline}
/* Optimizely-style names embed a whole URL + random id in the cookie NAME; without break-all
   one name stretches the row past the viewport. */
.ck{max-width:30ch}
.ck code{color:#0F4CBB;font-family:var(--mono);font-size:.92rem;font-weight:600;word-break:break-all;overflow-wrap:anywhere;display:inline-block;max-width:100%}
.hst,.grp{color:var(--muted);font-size:.85rem;margin-top:.12rem;word-break:break-all}
.detail{color:var(--muted);font-size:.88rem;margin-top:.22rem;max-width:60ch}
.ev{color:#3C4557;font-size:.86rem;line-height:1.45;margin-top:.3rem;max-width:52ch}
.ev-l{font-weight:600;font-size:.85rem} .ev-l.trk{color:var(--bad)} .ev-l.ben{color:var(--ok)}
.gev{margin:.5rem 0 .15rem}
.gev>summary{cursor:pointer;color:var(--accent);list-style:none;display:inline-block}
.gev>summary::-webkit-details-marker{display:none}
.gev>summary{font-size:0} .gev>summary::before{font-size:.86rem;font-weight:500}
.gev>summary::before{content:"▸ graph evidence"} .gev[open]>summary::before{content:"▾ graph evidence"}
.gev-g{margin:.45rem 0 .45rem .1rem;max-width:62ch}
.gev-h{display:block;font-size:.85rem;color:var(--muted);font-weight:600}
.gev ul{margin:.15rem 0 .15rem 1.1rem;padding:0}
.gev li{font-size:.88rem;color:#3C4557;margin:.14rem 0;line-height:1.5}
.gev li.emore{list-style:none;color:var(--muted);font-style:italic;font-size:.85rem;margin-left:-.6rem}
.eh{font-family:var(--mono);font-size:.86rem;color:var(--code)}
.echain{font-family:var(--mono);font-size:.85rem;color:#3C4557}
.escript{font-family:var(--mono);font-size:.85rem;color:var(--muted);margin:.05rem 0 .1rem;word-break:break-all;max-width:54ch}
.emeth{font-family:var(--mono);font-size:.85rem;color:var(--muted);font-weight:600}
.earr{color:var(--muted)} .emut{color:var(--muted);font-size:.85rem;font-style:italic}
.ecnt{color:var(--muted);font-size:.85rem;margin-left:.25rem;font-variant-numeric:tabular-nums}
.etag{display:inline-block;font-size:.85rem;font-weight:600;padding:.02rem .38rem;border-radius:4px;vertical-align:baseline}
.et-auto{background:var(--warn-bg);color:var(--warn)}
.et-js{background:var(--ok-bg);color:var(--ok)}
.et-http{background:var(--accent-bg);color:var(--accent)}
.et-mut{background:rgba(92,101,117,.1);color:var(--muted)}
.et-third{background:var(--bad-bg);color:var(--bad)}
.et-first{background:rgba(92,101,117,.1);color:var(--muted)}
.et-form{background:rgba(92,101,117,.1);color:var(--ink)}
.et-snap{background:var(--warn-bg);color:var(--warn)}
.et-id{background:var(--bad-bg);color:var(--bad)}
.et-noid{background:var(--ok-bg);color:var(--ok)}
.gev.ob>summary::before{content:"▸ what was sent — per destination"} .gev.ob[open]>summary::before{content:"▾ what was sent — per destination"}
.ob-box{margin:.5rem 0 .6rem;padding:.55rem .65rem;background:var(--panel);border:1px solid var(--line);border-radius:8px;border-left:3px solid var(--muted);max-width:72ch}
.ob-box.ob-hot{border-left-color:var(--bad);background:rgba(198,40,40,.025)}
.ob-hd{display:flex;flex-wrap:wrap;align-items:baseline;gap:.4rem;font-size:.9rem}
.ob-host{font-family:var(--mono);font-weight:700;color:var(--ink);word-break:break-all}
.ob-path{font-family:var(--mono);color:var(--muted);font-size:.86rem;word-break:break-all}
.ob-badge{font-size:.85rem;font-weight:700;padding:.04rem .45rem;border-radius:5px;margin-left:auto}
.ob-badge.ob-bad{background:var(--bad-bg);color:var(--bad)} .ob-badge.ob-warn{background:var(--warn-bg);color:var(--warn)}
.ob-badge.ob-ok{background:var(--ok-bg);color:var(--ok)} .ob-badge.ob-unk{background:rgba(92,101,117,.1);color:var(--muted)}
.ob-parts{font-size:.88rem;color:#3C4557;margin-top:.3rem} .ob-parts code{font-family:var(--mono);color:#0F4CBB;font-weight:600}
.ob-kind{font-size:.85rem;color:var(--muted)}
.ob-shared{font-size:.86rem;color:var(--warn);margin-top:.2rem} .ob-shared code{font-family:var(--mono)}
.ob-excerpt{font-family:var(--mono);font-size:.85rem;line-height:1.55;color:var(--code);background:var(--bg);margin:.35rem 0 .1rem;padding:.45rem .55rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;border-radius:6px;border:1px solid var(--line)}
.ob-mark{background:#FFE58A;color:#4A3600;font-weight:700;padding:0 .06rem;border-radius:2px}
.ob-noexcerpt{font-size:.86rem;color:var(--muted);font-style:italic;margin-top:.3rem} .ob-noexcerpt code{font-style:normal;font-family:var(--mono)}
.ob-facts{margin-top:.35rem;font-size:.86rem;color:var(--bad);max-width:60ch;line-height:1.45}
.ob-facts-h{font-weight:700;font-size:.85rem;color:var(--ink)}
.gev.code>summary::before{content:"▸ source — where it's set, read & sent"} .gev.code[open]>summary::before{content:"▾ source — where it's set, read & sent"}
.cs-site{margin:.5rem 0 .55rem;padding:.5rem .6rem;background:var(--panel);border:1px solid var(--line);border-radius:8px;border-left:2px solid var(--accent)}
.cs-hd{display:flex;flex-wrap:wrap;align-items:baseline;gap:.35rem;font-size:.88rem;margin-bottom:.3rem}
.cs-what{font-weight:700;font-size:.85rem;padding:.03rem .4rem;border-radius:4px}
.cs-writes{background:var(--bad-bg);color:var(--bad)} .cs-reads{background:var(--accent-bg);color:var(--accent)} .cs-deletes{background:rgba(92,101,117,.1);color:var(--muted)}
.cs-sends{background:var(--warn-bg);color:var(--warn)}
.cs-sendsite{border-left-color:var(--warn)}
.cs-dest{font-family:var(--mono);font-size:.88rem;color:var(--bad);font-weight:600;word-break:break-all}
.cs-method{font-family:var(--mono);font-size:.85rem;color:var(--muted)}
.cs-sent{font-size:.86rem;color:#3C4557;margin:.05rem 0 .25rem}
.cs-sub{margin-top:.15rem;font-size:.85rem} .cs-from{color:var(--muted);font-size:.85rem}
.cs-note{font-size:.86rem;color:var(--muted);line-height:1.5;margin:.35rem 0 .1rem;padding:.35rem .5rem;border-left:2px solid var(--line);background:var(--bg)} .cs-note code{color:#0F4CBB}
.cs-readsite{border-left-style:dashed;border-left-color:var(--accent)}
.cs-inferred{font-size:.85rem;color:var(--accent);border:1px dashed rgba(37,99,235,.45);border-radius:3px;padding:0 .3rem;margin-left:auto}
.cs-reason{font-size:.86rem;color:var(--muted);font-style:italic;margin-top:.2rem}
.cs-url{font-family:var(--mono);font-size:.85rem;color:var(--accent);text-decoration:none;word-break:break-all} .cs-url:hover{text-decoration:underline}
.cs-loc{font-family:var(--mono);font-size:.85rem;color:var(--warn);font-variant-numeric:tabular-nums}
.cs-inline,.cs-chan{font-size:.85rem;color:var(--muted);border:1px solid var(--line);border-radius:3px;padding:0 .28rem}
.cs-code{font-family:var(--mono);font-size:.85rem;line-height:1.55;color:var(--code);background:var(--bg);margin:.15rem 0;padding:.35rem .45rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;border-radius:5px;max-width:62ch;border:1px solid var(--line)}
.cs-mark{color:var(--ok);font-weight:700;background:var(--ok-bg);padding:0 .1rem;border-radius:2px}
.cs-nosrc{font-size:.86rem;color:var(--muted);font-style:italic;margin:.1rem 0}
.cs-stack{font-family:var(--mono);font-size:.85rem;color:var(--muted);margin-top:.2rem;line-height:1.5;word-break:break-all} .cs-fl{color:#8A93A6} .cs-arr{color:var(--line)}
.why{margin:.45rem 0 .2rem;font-size:.92rem;line-height:1.45;color:var(--ink);max-width:58ch}
.why-h{color:var(--accent);font-weight:600;font-size:.85rem}
.gev.llm>summary::before{content:"▸ classifier reasoning"} .gev.llm[open]>summary::before{content:"▾ classifier reasoning"}
.pass-l{font-size:.88rem;color:#3C4557;margin:.1rem 0} .pass-s{font-size:.88rem;color:var(--muted);line-height:1.45;max-width:58ch}
.p3{display:inline-block;font-size:.86rem;margin:.4rem 0 .1rem;padding:.12rem .5rem;border-radius:5px;border:1px solid var(--line);background:var(--panel)}
.p3-t{font-weight:700;font-size:.85rem;margin-right:.35rem}
.p3.p3-none{color:var(--muted)} .p3.p3-a{color:var(--accent);border-color:rgba(37,99,235,.35)}
.p3.p3-b{color:var(--ok);border-color:rgba(21,122,85,.35)} .p3.p3-blend{color:var(--warn);border-color:rgba(161,92,0,.35)}
.tile .v.p3a{color:var(--accent)} .tile .v.p3b{color:var(--ok)} .tile .v.p3blend{color:var(--warn)}
.chip{display:inline-block;padding:.06rem .45rem;border-radius:5px;font-size:.88rem;border:1px solid var(--line);margin:.04rem;background:var(--panel)}
.chip.trk{color:var(--bad);border-color:rgba(198,40,40,.35)} .chip.ben{color:var(--ok);border-color:rgba(21,122,85,.3)}
.conf{color:var(--muted);font-size:.85rem} .muted{color:var(--muted)}
.verdict{font-weight:600;font-size:.92rem} .verdict.bad{color:var(--bad)} .verdict.warn{color:var(--warn)} .verdict.ok{color:var(--ok)} .verdict.muted{color:var(--muted)}
tr.st-bad td{background:rgba(198,40,40,.035)}
/* A scroll container would trap the sticky header inside itself, so the wrapper only becomes a
   horizontal scroller on narrow viewports where the table genuinely cannot fit. */
.tbl-scroll{overflow-x:auto}
@media (min-width:900px){.tbl-scroll{overflow-x:visible}}
footer{margin-top:3rem;padding-top:1.5rem;border-top:1px solid var(--line);color:var(--muted);font-size:.88rem}
.page[hidden]{display:none}
</style></head><body>
<nav class="nav"><span class="brand">Cookie compliance report</span>
  <a href="#overview" data-page="overview">Overview</a>
  ${perSite.map((s) => { const { u, c } = siteCounts(s); const bad = u + c; return `<a href="#site-${slugOf(s.site)}" data-page="site-${slugOf(s.site)}">${esc(s.site)}${bad ? `<span class="n-bad">${bad}</span>` : ""}</a>`; }).join("\n  ")}
</nav>
<div class="wrap">
  ${overviewPage}
  ${perSite.map(sitePage).join("")}
  <footer>Observed: independent behavioural classifier (classify-v2 / pass3), confidence-gated · Declared: site CMP ruleset (re-fetched full) · MCP: ${esc(mcp.source || "cookie_classification")} (name corpus, reference only) · mutual-exclusivity from category-rules.json (PECR · ICC · IAB TCF) · "what was sent" boxes: deterministic byte matching against captured request bodies/headers · generated ${new Date().toISOString().slice(0, 10)}.</footer>
</div>
<script>
(function () {
  var pages = Array.prototype.slice.call(document.querySelectorAll(".page"));
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".nav a[data-page]"));
  var nav = document.querySelector(".nav");
  function measureNav() {
    document.documentElement.style.setProperty("--navh", nav.offsetHeight + "px");
  }
  window.addEventListener("resize", measureNav);
  measureNav();
  function show() {
    var id = (location.hash || "#overview").slice(1);
    if (!document.getElementById(id)) id = "overview";
    pages.forEach(function (p) { p.hidden = p.id !== id; });
    tabs.forEach(function (t) { t.classList.toggle("active", t.getAttribute("data-page") === id); });
    window.scrollTo(0, 0);
  }
  window.addEventListener("hashchange", show);
  show();
})();
</script>
</body></html>`;

writeFileSync(outPath, html);
console.log(`${roll.cookies} cookies · ${roll.sites} sites -> ${outPath}`);
console.log(`  necessary-but-tracking ${roll.necessaryButTracking} · under-declared ${roll.underDeclared} · contradictory ${roll.contradictory}`);
console.log(`  MCP↔ours exact agreement ${roll.mcpAgreesObserved}/${roll.mcpScorable} (reference only, name-keyed)`);
