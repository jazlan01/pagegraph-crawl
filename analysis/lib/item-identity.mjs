// item-identity.mjs — resolve WHAT A STORED ITEM IS, as opposed to what happened to it.
//
// The rest of this pipeline judges behaviour and never the name, on purpose: a label like
// "Advertising" must rest on what was recorded, not on a cookie being called `_fbp`. That rule is
// right for LABELS and wrong for DESCRIPTIONS — a reader needs to be told that `_ga` is Google
// Analytics' visitor-distinguishing cookie, and no amount of observed behaviour states that.
//
// So identity lives here, in its own field, with its own source tag, and NEVER feeds `icc`/`tcf`.
// Two rules keep it from becoming a back door for name-based labelling:
//
//   1. Every claim carries `source` — "mcp", "llm:<model>", or "observed". A reader (and a
//      reviewer) can always see whether a sentence came from a knowledge base, a model, or the
//      recording itself.
//   2. THE RECORDING IS THE ARBITER. A name-derived identity that contradicts what was observed is
//      dropped, not preferred. See `contradicts()` below.
//
// What is deliberately NOT here: attributing a product from the writing script's HOST. That was
// measured across all 548 items of the 2026-08-02 audit and is unsound — 52 unambiguous against
// 128 ambiguous, because a single first-party bundle host routinely serves several vendors at once
// (chegg's `lpc-ui.prod.cheggcdn.com` carries PerimeterX, Optimizely, Next.js, React and webpack
// together). A looser variant produced confident nonsense: `assortmentStoreId` → PerimeterX,
// `OptanonConsent` → Dynatrace RUM, Adobe cookies → Akamai Bot Manager. Host tells you who WROTE
// the cookie, which the report already says; it cannot tell you whose cookie it IS.

import { roleOf } from "./host-role.mjs";

const reg = (host) => {
  if (!host) return null;
  const p = String(host).toLowerCase().replace(/\.$/, "").split(".");
  return p.length >= 2 ? p.slice(-2).join(".") : p[0];
};

export const hostOf = (url) => {
  const m = /^https?:\/\/([^/]+)/.exec(String(url || ""));
  return m ? m[1] : null;
};

// The script that actually performed the write, best-effort, most precise first.
export const writingScriptUrl = (it) => {
  const cc = it.codeCtx?.u;
  if (cc) return cc;
  const fr = it.frames?.[0]?.[0]?.u;
  if (fr) return fr;
  const lp = it.loadPath || [];
  return lp.length ? lp[lp.length - 1].u ?? null : null;
};

// Every host the recording ties to this item: who wrote it, who read it, where the value went.
export const observedHosts = (it) => {
  const hosts = new Set();
  for (const w of it.writers || []) {
    if (w.v) hosts.add(w.v);
    const m = /response from (\S+)/.exec(String(w.t || ""));
    if (m) hosts.add(m[1]);
  }
  for (const s of it.sends || []) if (s.h && s.h !== "(unresolved)") hosts.add(s.h);
  for (const h of it.tpr || []) hosts.add(h);
  for (const h of it.off || []) hosts.add(h);
  const ws = hostOf(writingScriptUrl(it));
  if (ws) hosts.add(ws);
  for (const b of it.bodyHits || []) { const h = hostOf(b.u); if (h) hosts.add(h); }
  return [...hosts];
};

/**
 * Does a name-derived identity contradict the recording?
 *
 * The check is deliberately permissive about ABSENCE and strict about CONFLICT. A vendor we simply
 * did not observe is not a contradiction — a cookie can be set by a bundle whose host resolves to
 * the first party, and plenty of items have no resolvable writer at all. What IS a contradiction is
 * a claim naming a company while every host the recording touched belongs to *other* companies.
 * That is the shape of a wrong lookup (a name collision, or a model confidently guessing), and it
 * is the case where preferring the name over the graph would put a false vendor in a client report.
 */
export const contradicts = (claimedCompany, it) => {
  if (!claimedCompany) return false;
  const claimed = String(claimedCompany).toLowerCase();
  const hosts = observedHosts(it);
  if (!hosts.length) return false;                 // nothing to contradict

  const owners = [];
  for (const h of hosts) {
    const r = roleOf(h);
    if (r?.owner) owners.push(String(r.owner).toLowerCase());
    // A host whose registrable domain literally contains the claimed name corroborates it
    // (perimeterx.net for "PerimeterX / HUMAN"), even when Tracker Radar has no owner for it.
    const rd = reg(h) || "";
    if (rd && (claimed.includes(rd.split(".")[0]) || rd.split(".")[0].includes(claimed.split(/[\s/]/)[0]))) {
      return false;
    }
  }
  if (!owners.length) return false;                // no owner resolved anywhere: cannot judge
  // Corroborated if any observed owner shares a significant token with the claim.
  const tok = s => new Set(String(s).toLowerCase().split(/[^a-z0-9]+/).filter(w => w.length > 2));
  const claimTok = tok(claimed);
  for (const o of owners) {
    for (const w of tok(o)) if (claimTok.has(w)) return false;
  }
  return true;                                     // named a company, observed only others
};

/**
 * Resolve identity for one item.
 *
 * `nameRecord` is the Tier-1 lookup for this item's NAME — `{company, product, knownAs, source}` —
 * or null when no knowledge base had a record. Callers supply it; this module does not fetch,
 * so the knowledge source stays swappable and testable.
 */
export const identify = (it, nameRecord, site) => {
  const wsUrl = writingScriptUrl(it);
  const wsHost = hostOf(wsUrl);
  const siteReg = reg(site?.host);

  // Company from the recording is always safe: it describes the host that was actually contacted.
  const writerHost = (it.writers || []).find(w => w.v)?.v || wsHost;
  const role = writerHost ? roleOf(writerHost) : null;

  // "Third party" means a different COMPANY, not merely a different registrable domain. A site's
  // own asset domain is a separate domain (walmart.com serves from walmartimages.com) and calling
  // that third-party would overstate every first-party cookie it sets. Fall back to the domain
  // comparison only when neither side resolves to a known owner.
  const siteOwner = roleOf(site?.host)?.owner ?? null;
  const writerOwner = role?.owner ?? null;
  const thirdPartyWriter = (siteOwner && writerOwner)
    ? siteOwner !== writerOwner
    : ((it.writers || []).some(w => w.third) ||
       (wsHost ? reg(wsHost) !== siteReg : false));

  // A record counts as Tier 1 if it says ANYTHING about the name — a knowledge base that returns
  // only prose ("Used by Akamai Bot Manager to…") is still name knowledge, and requiring a
  // structured vendor field here would silently discard the only source we actually have.
  if (nameRecord?.company || nameRecord?.product || nameRecord?.knownAs) {
    if (contradicts(nameRecord.company, it)) {
      return {
        source: "observed",
        company: role?.owner ?? null,
        writerHost: writerHost ?? null,
        thirdParty: thirdPartyWriter,
        rejected: {
          claim: nameRecord.company,
          why: "a name lookup attributed this to a vendor the recording never touched; " +
               "the graph is the arbiter, so the claim was dropped",
        },
      };
    }
    return {
      source: nameRecord.source || "mcp",
      company: nameRecord.company ?? role?.owner ?? null,
      product: nameRecord.product ?? null,
      knownAs: nameRecord.knownAs ?? null,     // the prose: what this cookie is known to do
      writerHost: writerHost ?? null,
      thirdParty: thirdPartyWriter,
    };
  }

  // Tier 2: no name record. Company only, never a product.
  return {
    source: "observed",
    company: role?.owner ?? null,
    writerHost: writerHost ?? null,
    thirdParty: thirdPartyWriter,
  };
};
