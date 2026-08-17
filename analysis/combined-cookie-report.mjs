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
  .filter((s) => { try { return readdirSync(join(crawlRoot, s)).some((f) => f.endsWith(".graphml")); } catch { return false; } })
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
    `<li>${eHost(t.host)} <span class="emeth">${esc(t.method || "")}</span> ${eChanTag(t.channel)} ${ePartyTag(t.party)}${eCount(t.count)}</li>`)
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
    s.transformedThenSent ? "value transformed by JS then sent" : null,
    s.setterAlsoEndpointForOtherCookies ? `setter also collected ${s.setterAlsoEndpointForOtherCookies} other cookie(s)` : null,
  ].filter(Boolean);
  g("signals", flags.length ? [`<li>${flags.join("; ")}</li>`] : []);

  const at = sg.attributes || {};
  g("cookie attributes", [`<li>${esc(at.party || "?")}-party${at.persistent ? ", persistent" : ""}${at.httpOnly ? ", httpOnly" : ""}${at.secure ? ", secure" : ""}${at.sameSite ? `, SameSite=${esc(at.sameSite)}` : ""}${at.valueLength ? `, ${at.valueLength}-char value` : ""}</li>`]);

  if (!groups.length) return "";
  return `<details class="gev"><summary>graph evidence</summary>${groups.map(([edge, facts]) =>
    `<div class="gev-g"><span class="gev-h">${esc(edge)}</span><ul>${facts.join("")}</ul></div>`).join("")}</details>`;
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
const sendSite = (s) => `<div class="cs-site cs-sendsite">` +
  `<div class="cs-hd"><span class="cs-what cs-sends">sends&nbsp;&rarr;</span> ` +
  `<span class="cs-dest">${esc(s.destUrl ? shortUrl(s.destUrl) : "(request)")}</span> ` +
  `<span class="cs-method">${esc(s.method || "")}</span></div>` +
  `<div class="cs-hd cs-sub"><span class="cs-from">from</span> ` +
  `<a class="cs-url" href="${escAttr(s.scriptUrl)}" title="${escAttr(s.scriptUrl)}" target="_blank" rel="noopener">${esc(shortUrl(s.scriptUrl))}</a>` +
  `<span class="cs-loc">:${s.line ?? "?"}:${s.col ?? "?"}</span>${s.inline ? ` <span class="cs-inline">inline</span>` : ""}</div>` +
  codeExcerpt(s) + codeStack(s.stack) + `</div>`;
const codeEvidence = (cs) => {
  if (!cs) return "";
  const w = (cs.writes || []).slice(0, 4).map((s) => codeSite(s, "writes"));
  const sends = (cs.sends || []).filter((s) => s.isNetworkSink && s.destUrl);
  // Dedup sends by destination + line so a wrapped fetch does not repeat.
  const seen = new Set();
  const sh = sends.filter((s) => { const k = `${s.destUrl}|${s.scriptUrl}|${s.line}`; if (seen.has(k)) return false; seen.add(k); return true; })
    .slice(0, 4).map(sendSite);
  const r = (cs.reads || []).slice(0, 3).map((s) => codeSite(s, "reads"));
  const d = (cs.deletes || []).slice(0, 2).map((s) => codeSite(s, "deletes"));
  const all = [...w, ...sh, ...r, ...d];
  if (!all.length) return "";
  // Reads of document.cookie return the WHOLE jar, so PageGraph records them against the jar, not
  // this cookie — there is no per-cookie read site. The jar-wide readers are in the graph evidence.
  const readNote = (!r.length) ? `<div class="cs-note">Reads are not shown per-cookie: <code>document.cookie</code> returns the whole jar, so PageGraph records reads against the jar (the reader scripts are under <b>graph evidence &rarr; read edges</b>).</div>` : "";
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
  // Observed: per-label reasoning, the holistic "why", the 3-pass trace, then the graph facts.
  const obs = labelCell(r.observedIcc, "reasoning",
    r.observedConf ? `<span class="conf">${esc(r.observedConf)}</span>` : "") +
    (r.observedTcf.length ? `<div class="grp">TCF ${esc(r.observedTcf.slice(0, 4).join(" "))}</div>` : "") +
    classifierReasoning(r.passes, r.p3) +
    graphEvidence(r.subgraph, r.features) +
    codeEvidence(r.codeSites);
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
    <td><span class="verdict ${m.cls}">${esc(m.label)}</span>${r.detail ? `<div class="detail">${esc(r.detail)}</div>` : ""}</td>
  </tr>`;
};

const siteSection = (s) => {
  const u = s.rows.filter((r) => r.status === "mismatch-under-declared").length;
  const c = s.rows.filter((r) => r.status === "contradictory-declaration").length;
  return `<h2>${esc(s.site)} <span class="badge">${s.cmp || "no CMP"}</span></h2>
  <div class="sitesum">${s.rows.length} cookies · <span class="bad">${u} under-declared</span> · <span class="bad">${c} contradictory</span></div>
  <div class="tbl-scroll"><table><thead><tr>
    <th>Cookie</th><th>Observed (ours, behaviour)</th><th>Declared (site CMP)</th><th>MCP (name corpus)</th><th>Verdict — declared vs observed</th>
  </tr></thead><tbody>${s.rows.map(rowHtml).join("")}</tbody></table></div>`;
};

const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cookie classification — observed vs declared vs MCP</title>
<style>
:root{--navy:#0E1227;--panel:#161B33;--sky:#6390EE;--pool:#00DBFF;--salmon:#FC7D73;--seagreen:#40EBC2;--gold:#F0B53D;--white:#FFFFFF;--muted:#9AA2B8;--line:#2A3150;
--sans:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box} body{margin:0;background:var(--navy);color:var(--white);font-family:var(--sans);font-size:1.02rem;line-height:1.55;-webkit-font-smoothing:antialiased}
.wrap{max-width:1240px;margin:0 auto;padding:3rem 1.5rem 5rem}
h1{font-size:2.1rem;margin:0 0 .3rem;letter-spacing:-.01em} h2{font-size:1.35rem;margin:2.8rem 0 .4rem;letter-spacing:-.01em}
.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:.8rem;color:var(--sky);font-weight:600}
.sub{color:var(--muted);font-size:1rem;margin-bottom:1.6rem}
.badge{font-size:.75rem;color:var(--muted);border:1px solid var(--line);border-radius:5px;padding:.05rem .45rem;vertical-align:middle;text-transform:none;letter-spacing:0}
.sitesum{color:var(--muted);font-size:.9rem;margin-bottom:.5rem} .sitesum .bad{color:var(--salmon)}
.headline{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.5rem 1.8rem;margin:1.4rem 0}
.headline .n{font-size:2.8rem;font-weight:700;color:var(--salmon);line-height:1} .headline .n.zero{color:var(--seagreen)}
.headline .cap{color:var(--muted);max-width:66ch}
.tiles{display:flex;flex-wrap:wrap;gap:.7rem;margin:1.2rem 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:.8rem 1rem;min-width:8rem}
.tile .v{font-size:1.5rem;font-weight:700;font-variant-numeric:tabular-nums} .tile .k{font-size:.78rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.tile.bad .v{color:var(--salmon)} .tile.ok .v{color:var(--seagreen)}
.note{background:rgba(99,144,238,.08);border-left:3px solid var(--sky);padding:.9rem 1.15rem;border-radius:0 8px 8px 0;margin:1.1rem 0;color:#C9D2EA;font-size:.92rem}
table{width:100%;border-collapse:collapse;margin-top:.4rem;font-size:.92rem} th{text-align:left;color:var(--muted);font-weight:600;font-size:.76rem;text-transform:uppercase;letter-spacing:.05em;padding:.5rem .55rem;border-bottom:1px solid var(--line)}
td{padding:.6rem .55rem;border-bottom:1px solid var(--line);vertical-align:top}
.ck code{color:var(--pool);font-family:var(--mono);font-size:.88rem} .hst,.grp{color:var(--muted);font-size:.76rem;margin-top:.12rem}
.detail{color:var(--muted);font-size:.82rem;margin-top:.22rem;max-width:60ch}
.ev{color:#B8C0D8;font-size:.8rem;line-height:1.4;margin-top:.3rem;max-width:52ch}
.ev-l{font-weight:600;font-size:.76rem} .ev-l.trk{color:var(--salmon)} .ev-l.ben{color:var(--seagreen)}
.gev{margin:.45rem 0 .1rem}
.gev>summary{cursor:pointer;color:var(--sky);font-size:.78rem;list-style:none;display:inline-block}
.gev>summary::-webkit-details-marker{display:none}
.gev>summary::before{content:"▸ graph evidence"}
.gev[open]>summary{color:var(--pool)} .gev[open]>summary::before{content:"▾ graph evidence"}
.gev>summary{font-size:0} .gev>summary::before{font-size:.78rem}
.gev-g{margin:.4rem 0 .4rem .1rem;max-width:60ch}
.gev-h{display:block;text-transform:uppercase;letter-spacing:.05em;font-size:.66rem;color:var(--muted);font-weight:600}
.gev ul{margin:.15rem 0 .15rem 1.1rem;padding:0}
.gev li{font-size:.82rem;color:#C9D2EA;margin:.12rem 0;line-height:1.5}
.gev li.emore{list-style:none;color:var(--muted);font-style:italic;font-size:.76rem;margin-left:-.6rem}
.eh{font-family:var(--mono);font-size:.8rem;color:#D6DCF0}
.echain{font-family:var(--mono);font-size:.76rem;color:#C9D2EA}
.escript{font-family:var(--mono);font-size:.7rem;color:var(--muted);margin:.05rem 0 .1rem;word-break:break-all;max-width:54ch}
.emeth{font-family:var(--mono);font-size:.72rem;color:var(--muted);font-weight:600}
.earr{color:var(--muted)} .emut{color:var(--muted);font-size:.74rem;font-style:italic}
.ecnt{color:var(--muted);font-size:.72rem;margin-left:.25rem;font-variant-numeric:tabular-nums}
.etag{display:inline-block;font-size:.66rem;font-weight:700;padding:.02rem .34rem;border-radius:4px;letter-spacing:.02em;vertical-align:baseline}
.et-auto{background:rgba(240,181,61,.16);color:var(--gold)}
.et-js{background:rgba(64,235,194,.15);color:var(--seagreen)}
.et-http{background:rgba(99,144,238,.16);color:var(--sky)}
.et-mut{background:rgba(154,162,184,.14);color:var(--muted)}
.et-third{background:rgba(252,125,115,.15);color:var(--salmon)}
.et-first{background:rgba(154,162,184,.14);color:var(--muted)}
.gev.code>summary::before{content:"▸ source — where it's set, read & sent"} .gev.code[open]>summary::before{content:"▾ source — where it's set, read & sent"}
.cs-site{margin:.5rem 0 .55rem;padding:.5rem .6rem;background:#0A0E1F;border:1px solid var(--line);border-radius:8px;border-left:2px solid var(--sky)}
.cs-hd{display:flex;flex-wrap:wrap;align-items:baseline;gap:.35rem;font-size:.78rem;margin-bottom:.35rem}
.cs-what{font-weight:700;font-size:.66rem;text-transform:uppercase;letter-spacing:.05em;padding:.03rem .35rem;border-radius:4px}
.cs-writes{background:rgba(252,125,115,.16);color:var(--salmon)} .cs-reads{background:rgba(99,144,238,.16);color:var(--sky)} .cs-deletes{background:rgba(154,162,184,.16);color:var(--muted)}
.cs-sends{background:rgba(240,181,61,.18);color:var(--gold)}
.cs-sendsite{border-left-color:var(--gold)}
.cs-dest{font-family:var(--mono);font-size:.8rem;color:var(--salmon);font-weight:600;word-break:break-all}
.cs-method{font-family:var(--mono);font-size:.72rem;color:var(--muted)}
.cs-sub{margin-top:.15rem;font-size:.72rem} .cs-from{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.04em}
.cs-note{font-size:.74rem;color:var(--muted);line-height:1.5;margin:.35rem 0 .1rem;padding:.35rem .5rem;border-left:2px solid var(--line);background:rgba(154,162,184,.05)} .cs-note code{color:var(--pool)}
.cs-url{font-family:var(--mono);font-size:.76rem;color:var(--pool);text-decoration:none;word-break:break-all} .cs-url:hover{text-decoration:underline}
.cs-loc{font-family:var(--mono);font-size:.76rem;color:var(--gold);font-variant-numeric:tabular-nums}
.cs-inline,.cs-chan{font-size:.64rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);border:1px solid var(--line);border-radius:3px;padding:0 .28rem}
.cs-code{font-family:var(--mono);font-size:.74rem;line-height:1.5;color:#C9D2EA;background:transparent;margin:.15rem 0;padding:.3rem .4rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;border-radius:5px;max-width:60ch;border:1px solid rgba(42,49,80,.6)}
.cs-mark{color:var(--seagreen);font-weight:700;background:rgba(64,235,194,.14);padding:0 .1rem;border-radius:2px}
.cs-nosrc{font-size:.76rem;color:var(--muted);font-style:italic;margin:.1rem 0}
.cs-stack{font-family:var(--mono);font-size:.7rem;color:var(--muted);margin-top:.2rem;line-height:1.5;word-break:break-all} .cs-fl{color:#6B7391} .cs-arr{color:var(--line)}
.cs-more{font-size:.72rem;color:var(--muted);font-style:italic;margin-top:.2rem}
.why{margin:.45rem 0 .2rem;font-size:.85rem;line-height:1.45;color:#D6DCF0;max-width:56ch}
.why-h{color:var(--pool);font-weight:600;font-size:.76rem;text-transform:uppercase;letter-spacing:.04em}
.gev.llm>summary::before{content:"▸ classifier reasoning"} .gev.llm[open]>summary::before{content:"▾ classifier reasoning"}
.pass-l{font-size:.8rem;color:#C9D2EA;margin:.1rem 0} .pass-s{font-size:.8rem;color:var(--muted);line-height:1.4;max-width:56ch}
.p3{display:inline-block;font-size:.78rem;margin:.4rem 0 .1rem;padding:.12rem .5rem;border-radius:5px;border:1px solid var(--line)}
.p3-t{font-weight:700;font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;margin-right:.35rem}
.p3.p3-none{color:var(--muted)} .p3.p3-a{color:var(--sky);border-color:rgba(99,144,238,.4)}
.p3.p3-b{color:var(--seagreen);border-color:rgba(64,235,194,.4)} .p3.p3-blend{color:var(--gold);border-color:rgba(240,181,61,.4)}
.tile .v.p3a{color:var(--sky)} .tile .v.p3b{color:var(--seagreen)} .tile .v.p3blend{color:var(--gold)}
.chip{display:inline-block;padding:.06rem .45rem;border-radius:5px;font-size:.8rem;border:1px solid var(--line);margin:.04rem}
.chip.trk{color:var(--salmon);border-color:rgba(252,125,115,.4)} .chip.ben{color:var(--seagreen);border-color:rgba(64,235,194,.35)}
.conf{color:var(--muted);font-size:.76rem} .muted{color:var(--muted)}
.verdict{font-weight:600;font-size:.88rem} .verdict.bad{color:var(--salmon)} .verdict.warn{color:var(--gold)} .verdict.ok{color:var(--seagreen)} .verdict.muted{color:var(--muted)}
tr.st-bad td{background:rgba(252,125,115,.05)} .tbl-scroll{overflow-x:auto}
footer{margin-top:3rem;padding-top:1.5rem;border-top:1px solid var(--line);color:var(--muted);font-size:.84rem}
</style></head><body><div class="wrap">
  <div class="eyebrow">VaultJS · Cookie compliance</div>
  <h1>Observed vs declared vs MCP — per cookie, per site</h1>
  <div class="sub">${roll.cookies} cookies across ${roll.sites} sites. Three independent views side by side; the verdict compares only <b>our observed</b> classification against the <b>site's declaration</b>.</div>

  <div class="headline"><div class="n ${roll.necessaryButTracking ? "" : "zero"}">${roll.necessaryButTracking}</div>
    <div class="cap">cookie(s) the site declares <b>Strictly Necessary</b> that our behavioural classifier observed doing something requiring consent — a consent-exempt declaration the behaviour refutes.</div></div>

  <div class="tiles">
    <div class="tile bad"><div class="v">${roll.underDeclared}</div><div class="k">Under-declared</div></div>
    <div class="tile bad"><div class="v">${roll.contradictory}</div><div class="k">Contradictory decl.</div></div>
    <div class="tile"><div class="v">${roll.mcpScorable ? Math.round(100 * roll.mcpAgreesObserved / roll.mcpScorable) + "%" : "—"}</div><div class="k">MCP ↔ ours agree</div></div>
  </div>

  <div class="note"><b>Three columns, three provenances.</b> <b>Observed</b> is ours, from behaviour, and never saw the other two. <b>Declared</b> is the site's own CMP claim. <b>MCP</b> is a name-corpus classifier shown for reference only — it is <em>name-keyed</em>, so it is identical for a given cookie name across every site, and it is never the yardstick. The <b>verdict</b> is strictly declared-vs-observed; a Strictly-Necessary declaration is refuted when we observe tracking, and we abstain ("not assessable") where our own confidence is low.</div>

  <h2>How pass 3 reconciled identity vs behaviour</h2>
  <div class="sitesum">The classifier runs three passes: <b>A</b> infers purpose from the cookie name, <b>B</b> re-decides from behaviour alone (name-blind), <b>C</b> reconciles them into the final label. Pass 3 acted on <b>${roll.p3TookA + roll.p3TookB + roll.p3Blend}</b> of ${roll.cookies} cookies. Each row's Observed cell carries a <b>pass 3</b> badge and the full three-pass trace.</div>
  <div class="tiles">
    <div class="tile"><div class="v">${roll.p3Unchanged}</div><div class="k">A = B = C (unchanged)</div></div>
    <div class="tile"><div class="v p3a">${roll.p3TookA}</div><div class="k">kept identity (A) over B</div></div>
    <div class="tile"><div class="v p3b">${roll.p3TookB}</div><div class="k">kept behaviour (B) over A</div></div>
    <div class="tile"><div class="v p3blend">${roll.p3Blend}</div><div class="k">new blend (neither)</div></div>
  </div>

  ${perSite.map(siteSection).join("")}

  <footer>Observed: independent behavioural classifier (classify-v2 / pass3), confidence-gated · Declared: site CMP ruleset (re-fetched full) · MCP: ${esc(mcp.source || "cookie_classification")} (name corpus, reference only) · mutual-exclusivity from category-rules.json (PECR · ICC · IAB TCF) · generated ${new Date().toISOString().slice(0, 10)}.</footer>
</div></body></html>`;

writeFileSync(outPath, html);
console.log(`${roll.cookies} cookies · ${roll.sites} sites -> ${outPath}`);
console.log(`  necessary-but-tracking ${roll.necessaryButTracking} · under-declared ${roll.underDeclared} · contradictory ${roll.contradictory}`);
console.log(`  MCP↔ours exact agreement ${roll.mcpAgreesObserved}/${roll.mcpScorable} (reference only, name-keyed)`);
