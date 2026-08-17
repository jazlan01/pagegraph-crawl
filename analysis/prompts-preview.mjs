#!/usr/bin/env node
// prompts-preview.mjs — render every LLM prompt in the classifier, verbatim, as one HTML page.
//
//   node analysis/prompts-preview.mjs [--out <file>]
//
// The prompts are read from source at generation time (not retyped), so this preview cannot drift
// from what the pipeline actually sends. It shows, per pass: the system prompt exactly, what
// evidence the model receives, and the structured output it is forced to return.

import { readFileSync, writeFileSync } from "node:fs";
import { CONFIDENCE_LEVELS, ICC_UK_CATEGORIES, IAB_LABELS, US_STATE_PRIVACY_CATEGORIES } from "./lib/tcf-taxonomy.mjs";
import { HEAD_INSTRUCTIONS } from "./lib/llm-head.mjs";

const flag = (n, d) => { const i = process.argv.indexOf(n); return i !== -1 ? process.argv[i + 1] : d; };
const outPath = flag("--out", "output/classifier-prompts.html");

// Pull a `const NAME = `...`;` template literal verbatim. The prompts DO contain backticks now
// (e.g. `observedBehaviour`), escaped as \` in source — so a naive scan-to-first-backtick truncates
// the prompt after paragraph one. Honour backslash escapes and unescape them for display.
const grab = (file, name) => {
  const t = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
  const start = t.indexOf(`const ${name} = \``);
  if (start === -1) return null;
  const open = t.indexOf("`", start);
  let i = open + 1, out = "";
  while (i < t.length && t[i] !== "`") {
    if (t[i] === "\\" && i + 1 < t.length) { out += t[i + 1]; i += 2; continue; }
    out += t[i]; i++;
  }
  return out;
};

const PASSES = [
  {
    id: "A", tag: "Pass A", title: "Inferred purpose — from identity",
    file: "analysis/classify-v2.mjs", prompt: grab("analysis/classify-v2.mjs", "SYSTEM_A"),
    sees: "The cookie's IDENTITY only: name, domain, value length + a short value preview, and its attributes (httpOnly / secure / sameSite / persistence). No behaviour.",
    role: "The name-corpus question — what a cookie of this name is *for*. Deliberately sees the name; this is the inference baseline the later passes are measured against.",
  },
  {
    id: "B", tag: "Pass B", title: "Exercised purpose — from behaviour, name-blind",
    file: "analysis/classify-v2.mjs", prompt: grab("analysis/classify-v2.mjs", "SYSTEM_B"),
    sees: "ONLY the name-free behaviour subgraph: deduped write/read/transmission edges, the JS taint path (value → consumer → transform → destination host), redirect/sync hops, and derived behavioural flags. NO cookie name, NO value, and NOTHING from Pass A.",
    role: "What the cookie actually DID this load, judged on behaviour alone and independently. Does not see identity or Pass A's verdict — resolving destination/setter hosts to a purpose is its whole job.",
  },
  {
    id: "C", tag: "Pass C", title: "Reconciled — identity AND behaviour",
    file: "analysis/pass3.mjs", prompt: grab("analysis/pass3.mjs", "SYSTEM_C"),
    sees: "Identity (name, domain), the concrete graph artefacts (setting scripts, setter hosts, redirect chain, exfil destinations), the behaviour vector, AND both prior verdicts (A and B) as labels.",
    role: "The final label. Identity is authoritative for semantic categories (security / consent / infra); behaviour may ADD a purpose only on a deliberate transmission — a third-party destination or a JS-initiated send, never a value merely auto-attached to a same-party request; behaviour may not REMOVE a purpose on a single load.",
  },
  {
    id: "H", tag: "Legacy", title: "Single-pass head (classify-cookies.mjs)",
    file: "analysis/lib/llm-head.mjs", prompt: HEAD_INSTRUCTIONS,
    sees: "The compact evidence payload (party, set channel, reads, destinations, persistence, entropy) plus the deterministic rule prior.",
    role: "The original one-shot classifier, superseded by the A→B→C pipeline. Kept for the standalone classify-cookies.mjs path.",
  },
];

const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const chips = (xs) => xs.map((x) => `<span class="chip">${esc(x)}</span>`).join(" ");

const passHtml = (p) => `
  <section class="pass" id="pass-${p.id}">
    <div class="pass-head"><span class="tag">${esc(p.tag)}</span><h2>${esc(p.title)}</h2></div>
    <div class="meta"><span class="mk">defined in</span> <code>${esc(p.file)}</code> · <span class="mk">${p.prompt ? p.prompt.length + " chars" : "MISSING"}</span></div>
    <div class="role">${esc(p.role)}</div>
    <div class="io"><span class="io-k">Model receives</span> ${esc(p.sees)}</div>
    <div class="label">System prompt (verbatim)</div>
    <pre class="prompt">${esc(p.prompt || "— not found —")}</pre>
  </section>`;

const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Classifier prompts</title>
<style>
:root{--navy:#0E1227;--panel:#161B33;--sky:#6390EE;--pool:#00DBFF;--salmon:#FC7D73;--seagreen:#40EBC2;--gold:#F0B53D;--white:#FFFFFF;--muted:#9AA2B8;--line:#2A3150;
--sans:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box} body{margin:0;background:var(--navy);color:var(--white);font-family:var(--sans);font-size:1.05rem;line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:920px;margin:0 auto;padding:3rem 1.5rem 5rem}
.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:.8rem;color:var(--sky);font-weight:600}
h1{font-size:2.1rem;margin:.2rem 0 .4rem;letter-spacing:-.01em}
.sub{color:var(--muted);margin-bottom:1.6rem}
.flow{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1rem 1.2rem;margin:1.4rem 0}
.flow .step{border:1px solid var(--line);border-radius:8px;padding:.4rem .7rem;font-size:.9rem}
.flow .step b{color:var(--pool)} .flow .arr{color:var(--muted)}
.toc{display:flex;flex-wrap:wrap;gap:.5rem;margin:1.2rem 0 2rem}
.toc a{color:var(--sky);text-decoration:none;border:1px solid var(--line);border-radius:6px;padding:.25rem .6rem;font-size:.9rem}
.pass{margin:2.4rem 0;padding-top:1.4rem;border-top:1px solid var(--line)}
.pass-head{display:flex;align-items:baseline;gap:.7rem} .pass-head h2{font-size:1.5rem;margin:0;letter-spacing:-.01em}
.tag{background:var(--sky);color:var(--navy);font-weight:700;font-size:.75rem;padding:.15rem .55rem;border-radius:5px;text-transform:uppercase;letter-spacing:.05em}
#pass-H .tag{background:var(--muted)}
.meta{color:var(--muted);font-size:.85rem;margin:.5rem 0} .meta code{color:var(--pool);font-family:var(--mono)}
.mk{text-transform:uppercase;font-size:.7rem;letter-spacing:.05em}
.role{margin:.7rem 0;color:#D6DCF0}
.io{background:rgba(99,144,238,.08);border-left:3px solid var(--sky);padding:.7rem 1rem;border-radius:0 8px 8px 0;margin:.8rem 0;font-size:.95rem;color:#C9D2EA}
.io-k{display:block;text-transform:uppercase;font-size:.7rem;letter-spacing:.05em;color:var(--sky);font-weight:600;margin-bottom:.2rem}
.label{text-transform:uppercase;letter-spacing:.06em;font-size:.72rem;color:var(--muted);font-weight:600;margin:1rem 0 .35rem}
pre.prompt{background:#0A0E1F;border:1px solid var(--line);border-radius:10px;padding:1.1rem 1.2rem;overflow-x:auto;
  font-family:var(--mono);font-size:.86rem;line-height:1.6;color:#DCE3F5;white-space:pre-wrap;word-wrap:break-word}
.schema{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.3rem 1.5rem;margin:2rem 0}
.schema h3{margin:.2rem 0 .6rem;font-size:1.15rem} .schema .ax{margin:.7rem 0} .schema .ax-k{color:var(--pool);font-family:var(--mono);font-size:.85rem}
.chip{display:inline-block;border:1px solid var(--line);border-radius:5px;padding:.08rem .5rem;font-size:.82rem;color:#C9D2EA;margin:.1rem}
footer{margin-top:3rem;padding-top:1.5rem;border-top:1px solid var(--line);color:var(--muted);font-size:.84rem}
</style></head><body><div class="wrap">
  <div class="eyebrow">VaultJS · Cookie classifier</div>
  <h1>Every prompt, verbatim</h1>
  <div class="sub">The system prompts the classifier sends, read straight from source. The pipeline runs three passes per cookie; a legacy single-pass head is included for reference.</div>

  <div class="flow">
    <span class="step"><b>Pass A</b> identity</span><span class="arr">→</span>
    <span class="step"><b>Pass B</b> behaviour (name-blind)</span><span class="arr">→</span>
    <span class="step"><b>Pass C</b> reconcile → final label</span>
  </div>

  <div class="toc">${PASSES.map((p) => `<a href="#pass-${p.id}">${esc(p.tag)} — ${esc(p.title.split(" — ")[0])}</a>`).join("")}<a href="#schema">Output contract</a></div>

  ${PASSES.map(passHtml).join("")}

  <section class="schema" id="schema">
    <h3>The output contract (all passes)</h3>
    <p class="role">Every pass is forced to return a schema-valid object across three axes, each label carrying a <b>text confidence</b> — never a number — and a ≤15-word reasoning that must cite the supplied evidence.</p>
    <div class="ax"><span class="ax-k">confidence</span> (ordered): ${chips(CONFIDENCE_LEVELS)}</div>
    <div class="ax"><span class="ax-k">icc_uk_categories</span>: ${chips(ICC_UK_CATEGORIES)}</div>
    <div class="ax"><span class="ax-k">us_state_privacy_categories</span>: ${chips(US_STATE_PRIVACY_CATEGORIES)}</div>
    <div class="ax"><span class="ax-k">iab_purposes</span> (TCF):<br>${chips(IAB_LABELS)}</div>
  </section>

  <footer>Read from source: <code>classify-v2.mjs</code> (Pass A/B), <code>pass3.mjs</code> (Pass C), <code>lib/llm-head.mjs</code> (legacy head), <code>lib/tcf-taxonomy.mjs</code> (output contract). Generated ${new Date().toISOString().slice(0, 10)}.</footer>
</div></body></html>`;

writeFileSync(outPath, html);
console.log(`wrote ${outPath} (${PASSES.filter((p) => p.prompt).length}/${PASSES.length} prompts)`);
