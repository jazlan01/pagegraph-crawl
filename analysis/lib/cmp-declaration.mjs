// cmp-declaration.mjs — recover the SITE'S OWN declared purpose per cookie, from its CMP ruleset.
//
// This is the report's reference: what the site tells its users each cookie is for. It is NOT an
// input to the classifier — the classifier never sees it. Kept deliberately separate.
//
// Scaling contract: a site whose CMP we cannot parse yields `{ cmp: null }` and every cookie reads
// "not declared" downstream. Never throw on an unrecognised or malformed CMP — at corpus scale most
// sites will be one or the other, and the honest output is absence, not a crash.
//
// Coverage today: OneTrust (cdn.cookielaw.org) is parsed. Costco self-hosts its consent manager,
// fidelity.co.uk uses Ensighten, walmart ships no CMP config — all three fall through to null until
// a parser for each is added. The vendor dispatch below is where they plug in.

import { createInterface } from "node:readline";
import { createReadStream } from "node:fs";

import { toIcc } from "./category-rules.mjs";

// --- find the ruleset URL the crawl already fetched -------------------------
// OneTrust serves the per-cookie declaration at
// cdn.cookielaw.org/consent/<groupId>/<rulesetId>/<lang>.json. Prefer en; accept any 2-letter lang.
const ONETRUST_RE = /https:\/\/cdn\.cookielaw\.org\/consent\/[^\s"']+?\/(?:en|[a-z]{2})\.json/g;

export const findRulesetUrl = async (bodiesPath) => {
  const seen = new Set();
  try {
    const rl = createInterface({ input: createReadStream(bodiesPath), crlfDelay: Infinity });
    for await (const line of rl) {
      for (const m of line.matchAll(ONETRUST_RE)) seen.add(m[0]);
      if (seen.size && line.length > 200_000) break; // enough
    }
  } catch { /* no bodies sidecar */ }
  // Prefer the English ruleset if several languages were fetched.
  const urls = [...seen];
  const en = urls.find((u) => u.endsWith("/en.json"));
  return en ? { cmp: "OneTrust", url: en } : urls.length ? { cmp: "OneTrust", url: urls[0] } : { cmp: null };
};

// --- parse a OneTrust en.json into a per-cookie declaration -----------------
export const parseOneTrust = (json, sourceUrl) => {
  const groups = json?.DomainData?.Groups;
  if (!Array.isArray(groups)) return { cmp: "OneTrust", source: sourceUrl, parseFailed: true, cookies: {} };

  const groupNames = {}; // C0001 -> "Strictly Necessary Cookies"  (also decodes OptanonConsent ids)
  const cookies = {};    // name -> { declaredGroups, declaredGroupNames, declaredCategories, hosts, descriptions, isThirdParty }

  for (const g of groups) {
    const gid = g.OptanonGroupId ?? null;
    const gname = g.GroupName ?? null;
    if (gid && gname) groupNames[gid] = gname;
    const icc = toIcc(gname); // may be null for non-category groups ("Privacy Rights", region lists)
    const entries = [...(g.FirstPartyCookies || []), ...(g.Cookies || [])];
    for (const c of entries) {
      const name = c?.Name;
      if (!name) continue;
      const rec = (cookies[name] ??= {
        declaredGroups: new Set(), declaredGroupNames: new Set(),
        declaredCategories: new Set(), hosts: new Set(), descriptions: new Set(),
        isThirdParty: false, isPattern: /[*\[\]]/.test(name),
      });
      if (gid) rec.declaredGroups.add(gid);
      if (gname) rec.declaredGroupNames.add(gname);
      if (icc) rec.declaredCategories.add(icc);
      if (c.Host) rec.hosts.add(c.Host);
      if (c.description && c.description !== "n/a") rec.descriptions.add(c.description);
      if (c.isThirdParty) rec.isThirdParty = true;
    }
  }

  // freeze sets to arrays
  const out = {};
  for (const [name, r] of Object.entries(cookies)) {
    out[name] = {
      declaredGroups: [...r.declaredGroups],
      declaredGroupNames: [...r.declaredGroupNames],
      declaredCategories: [...r.declaredCategories], // ICC families the site assigned
      hosts: [...r.hosts],
      description: [...r.descriptions][0] ?? null,
      isThirdParty: r.isThirdParty,
      isPattern: r.isPattern,
    };
  }
  return { cmp: "OneTrust", source: sourceUrl, groupNames, cookieCount: Object.keys(out).length, cookies: out };
};

// --- dispatch ---------------------------------------------------------------
export const parseDeclaration = (cmp, json, sourceUrl) => {
  if (cmp === "OneTrust") return parseOneTrust(json, sourceUrl);
  return { cmp: cmp ?? null, source: sourceUrl ?? null, cookies: {} }; // unrecognised → not declared
};
