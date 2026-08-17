# PageGraph behavioural classifier vs. the cookie-classification MCP — evaluation notes

**Purpose.** Feedback on the Behavioural Storage Audit prototype, focused on the one comparison that matters for this project: the behavioural (observed-tier) classifier vs. the existing VaultJS cookie-classification MCP, which is the system this work is meant to beat.

**Position in one line.** The provenance/forensic layer is genuinely good and worth keeping. The *classification* layer, as it stands, does not beat the MCP — on the cookies I checked it is systematically *less* accurate, and the "deterministic + explainable" framing doesn't close that gap. The assignment (cookies whose purpose varies with execution) is real and valuable, but it is a statement about the **gap between observed and inferred**, and the current design only has the observed half.

Everything below that cites a cookie is from the audit's own embedded data cross-checked against the cookie-classification MCP (customer-scoped) and `pagerunner.reporting`. Jazlan should still run the formal head-to-head himself — see §6.

---

## 1. What the PageGraph approach genuinely does better

Stated up front so the rest is read as calibration, not dismissal:

- **Observed-only discipline.** Not asserting a purpose where no behaviour occurred is the right instinct, and the MCP does not do this today. This is the seed of something the MCP lacks (see §4).
- **First-party-served source detection.** This is the one capability that is *not* just scope. Confirmed against our resolver: `gateway.chegg.com/aOtQIWNf/init.js` resolves to **"Chegg Inc."** and `tms.delta.com/.../fb….js` to **"Delta Air Lines"** — i.e. Pagerunner attributes first-party-served vendor code to the first party, while PageGraph unmasks it by execution signature. Worth keeping regardless of the classification outcome.
- **In-page reads and byte-level body evidence.** Real, and outside the reporting table's default view.

None of these are cookie-classification quality. That is the point of separating them out: the forensic layer can be a win *and* the classifier can still lose to the MCP. They are different claims.

---

## 2. Where it underperforms the MCP — the core

Same cookies, three columns: what the audit labelled, what the MCP returned, and the hand read.

| Cookie (value) | Audit label | Cookie-MCP | Correct read |
|---|---|---|---|
| `introSeen` = `true` | Functional + **P10** (observed) | **Necessary, P1** | Necessary/P1 |
| `_ga_006T86XBJP` = `deleted` | **Functional**, unresolved | **Analytics 0.98**, P1/P8 | (unresolved) Analytics |
| `_sdsat_authState` = `Logged Out` | Analytics + **Advertising** | **Necessary** (auth/SP1) | Necessary |
| `app_name` = `Chegg Study Web` | Analytics + **Advertising** | **Necessary** (delivery) | Necessary |
| `device_id` = real UUID | Analytics + Advertising | Necessary 0.7 / Analytics 0.4 | identifier — the one real case |
| `_pxvid`, `pxcts`, `pxsid` | **Advertising** + Analytics | **Necessary / SP1** | security (bot defence) |
| `aws-waf-token` | Analytics + **Advertising** | **Necessary / SP1** | security (WAF) |

On every disputed cookie the MCP is right and the audit is wrong. Two failure modes explain almost all of it, and both are structural, not tuning:

### 2a. Payload bundling
The audit stamps **every field in a shared request with the recipient host's inferred role.** `Logged Out`, `Chegg Study Web` and a genuine `device_id` UUID all ride in the same `api2.amplitude.com` POST batch, so all three get identical `Analytics + Advertising`. That is why constant status strings inherit an "Advertising" label they cannot possibly deserve, and why the one field that *is* an identifier is indistinguishable from the noise around it. A classifier that cannot tell a 4-character constant from a UUID is not doing value-level classification; it is doing a **join on the destination host**.

### 2b. Two axes computed from different sources
**61 of 81** items carrying ICC **Advertising** have **no** advertising TCF purpose (P3/P4/P6/P7) — they are P1/P8/P9, which is analytics. The ICC axis is an inferred host-role lookup ("this value reached a host we treat as ad-capable"); the TCF axis is observed behaviour. They are derived from different inputs and diverge on three quarters of the advertising population. The most visible casualties are the bot-defence / WAF tokens above: security infrastructure labelled Advertising because it POSTs to a vendor collector.

Add the standing objection to `Functional` as the default bin for unexercised cookies (`_ga_006T86XBJP` → Functional): that bin is precisely where sneaked-in analytics hides, so defaulting to it is the least safe default available.

The MCP has none of these three problems because it classifies the **value and the name family**, not the destination.

---

## 3. The "explainability" argument, head-on

The expected defence is that deterministic observed rules are more explainable than a model. Three responses:

1. **Deterministic ≠ correct.** The rules in §2 are fully explainable and still wrong. "The value reached host X, host X is tagged advertising, therefore advertising" is a legible chain to a wrong conclusion. Explainability of a bad rule is not an asset.
2. **The MCP is auditable too.** It exposes the name-pattern family (regex + family id), the customer-scoped evidence bundle, prior labels, and it sits on the same provenance chain (`initiatorchainhostnames` / `calculatedprovenancevendordomainchain`) that gives the full page→CDN→tag→vendor path. "Only the deterministic system can be explained" is not true.
3. **For a client artifact, confident-and-wrong is worse than calibrated.** A deterministic `Advertising` on a WAF token reads as authoritative and is defensible by no one in a regulator conversation. A probability the MCP can show as low-confidence is the safer failure mode.

So explainability is not a differentiator here, and where it exists it is attached to the wrong answers.

---

## 4. The actual assignment: observed vs inferred is a *gap*, and the design only has one side

The brief was to find cookies whose purpose **varies with execution**. That is inherently a comparison between two quantities:

- **Potential / intended purpose** — what the cookie is *for*, from its name family, corpus behaviour and code. This is the question the **MCP** answers.
- **Exercised purpose** — what it actually *did* in this one load. This is the question **PageGraph** answers.

The finding you want is the **delta** between them: a cookie that is capable of analytics but did nothing this load; a "necessary"-named cookie that quietly exfiltrated; a value whose purpose flips between an authenticated and an unauthenticated run.

`_ga_006T86XBJP` is the textbook case and it exposes the design gap exactly. It was written and never read (single-request load), so *observed* purpose is genuinely nil — the observed-only discipline is right to withhold "analytics observed." But the useful output there is **inferred (unresolved) Analytics**, because the name family makes the potential unambiguous. The audit instead emits **Functional**, which loses the potential *and* picks the wrong category. So at the one moment the assignment is live, the system cannot express it: it has the observed half and its inferred fallback is a default bin.

To actually surface execution-dependent purpose you need a principled inferred label to diff against — and that inferred label is what the MCP already produces at ~90%. The observed layer's job is to be the *overlay* that flags where reality diverges from that inference. Right now the overlay is *introducing* errors (§2a payload bundling) rather than correcting the MCP's.

**This reframes "beat the MCP" usefully:** the win is not a second, weaker classifier. The win is `observed_behaviour ⊕ MCP_inference` — MCP potential as the baseline, PageGraph execution as the overlay, and the **gap** as the deliverable. A prototype that replaces the inference with a host-role join is strictly behind the baseline it is meant to beat.

---

## 5. Two smaller notes for accuracy

- **No decryption/deobfuscation.** Body matches are `raw` (100) or `urlencoded` (8) only. So "invisible to any audit that reads URLs and headers" is a scope statement about URL/header-only tools, not a capability claim — a body-capturing audit (ours, via HAR) sees these, and the token engine matches a stored value in query *or* body regardless.
- **Cost.** 6.2 GB (Chegg) and 6.7 GB (Delta) of provenance graph **per single homepage load**. Fine for a forensic probe; a hard ceiling for anything resembling monitoring. Relevant when positioning this against a system that runs hundreds of thousands of pages.

---

## 6. Recommended benchmark (Jazlan to run)

Assertions about which classifier is better should be settled on the labelled set, not on architecture:

1. **Same taxonomy, same inputs.** Run both classifiers over the labelled cookie set. Report precision/recall per ICC category and per TCF purpose, plus a confusion matrix. The bar is the MCP at ~90% (with the caveat that some of the residual is dataset-label mistrust, so effective accuracy may be higher).
2. **Report the security/necessary classes explicitly.** The §2 failures are concentrated there; an aggregate number will hide them. Break out bot-defence/WAF, auth-state, and consent cookies as their own slices.
3. **Isolate the execution-dependent subset** — the cookies whose observed behaviour differs from their inferred potential (the actual assignment). Measure the overlay's value *there*, where it should win, rather than on the whole population where it mostly adds join errors.
4. **Ablate the two failure modes.** Show the numbers with and without payload-bundling and with the ICC axis reconciled to the observed TCF purposes. If those two changes don't move it near the MCP, the approach needs rethinking, not tuning.

---

## 7. Bottom line for the response

- Keep and lean into the forensic layer: first-party-served detection, in-page reads, provenance-anchored body evidence. That is the defensible novelty.
- Do **not** position the observed-behaviour classifier as beating the cookie-classification MCP on its own. On the evidence it is behind, for structural reasons (host-role bundling, split taxonomy axes, Functional default).
- Reframe the deliverable as **inference (MCP) + observed overlay (PageGraph) + the gap**, and benchmark the overlay on the execution-dependent subset specifically. That is a version of this work that genuinely clears the bar; a standalone deterministic classifier is not.
