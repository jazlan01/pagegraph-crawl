// host-role.mjs — resolve a hostname to its DuckDuckGo Tracker Radar categorisation.
//
// Replaces the hand-written HOST_ROLE regex table that used to live in label-from-flows.mjs.
// The old table was an ungrounded list of domains someone decided were "advertising" or
// "analytics". This reads a committed snapshot of Tracker Radar (built by build-host-roles.mjs)
// so the categorisation comes from a maintained public dataset, offline and deterministically.
//
// roleOf() returns the FULL evidence, not a bare role string: the raw DDG categories and owner
// travel with it so a verdict can cite "Tracker Radar: New Relic, categories [Analytics, …]"
// rather than hiding the grounding behind our own re-labelling. A host that is absent, or
// present but uncategorised, returns a record with an empty `roles` array — the caller treats
// that as recipient-unresolved and must not guess a category.

import { readFileSync, existsSync } from "node:fs";

const SNAPSHOT = new URL("../data/tracker-radar-roles.json", import.meta.url).pathname;
let DB = null;
const db = () => {
  if (DB) return DB;
  DB = existsSync(SNAPSHOT)
    ? JSON.parse(readFileSync(SNAPSHOT, "utf8"))
    : { domains: {}, trackerRadarRev: null, domainCount: 0 };
  return DB;
};

export const snapshotInfo = () => {
  const d = db();
  return { rev: d.trackerRadarRev, domains: d.domainCount, withCategories: d.domainsWithCategories };
};

// Tracker Radar catalogues TRACKERS. Security / WAF / anti-bot / bot-challenge infrastructure is
// deliberately outside its scope, so those endpoints resolve to nothing there even though their
// role is unambiguous. This is a small, explicitly-scoped supplement for that specific gap — not
// a general-purpose vendor table. Membership is by what the service IS (bot-defence/WAF), which
// is public infrastructure fact, and matches are reported with source "infrastructure-supplement"
// so a verdict never claims Tracker Radar said something it did not.
const SECURITY_INFRA = {
  "awswaf.com": "Amazon Web Services (AWS WAF)",
  "datadome.co": "DataDome",
  "hcaptcha.com": "hCaptcha",
  "arkoselabs.com": "Arkose Labs",
  "funcaptcha.com": "Arkose Labs",
};

// Tracker Radar keys by registrable domain. Try the full host, then drop one leftmost label at
// a time until a match. First match wins, so `insight.adsrvr.org` resolves to `adsrvr.org` and
// cannot over-reduce to a public suffix (the dataset has no entry for one).
export const roleOf = (host) => {
  if (!host) return null;
  const domains = db().domains;
  const parts = String(host).toLowerCase().replace(/\.$/, "").split(".");
  let rolelessTR = null;   // a Tracker Radar hit that carries no mapped role
  for (let i = 0; i < parts.length - 1; i++) {
    const cand = parts.slice(i).join(".");
    const rec = domains[cand];
    // A Tracker Radar record WITH a role wins outright.
    if (rec && (rec.roles || []).length) {
      return { matchedDomain: cand, owner: rec.owner || null,
        categories: rec.categories || [], roles: rec.roles, source: "tracker-radar" };
    }
    // The infrastructure supplement fills Tracker Radar's gap for security/WAF/anti-bot
    // endpoints — including ones TR lists but leaves uncategorised (e.g. awswaf.com).
    if (SECURITY_INFRA[cand]) {
      return { matchedDomain: cand, owner: SECURITY_INFRA[cand],
        categories: ["Security / bot-defence infrastructure"], roles: ["security"],
        source: "infrastructure-supplement" };
    }
    // Remember the first roleless TR hit as a last resort (known owner, no role).
    if (rec && !rolelessTR) {
      rolelessTR = { matchedDomain: cand, owner: rec.owner || null,
        categories: rec.categories || [], roles: [], source: "tracker-radar" };
    }
  }
  return rolelessTR;   // roleless TR record, or null if in neither
};

// Convenience: the set of roles across a list of hosts, plus the per-host evidence records.
// Hosts with no resolution or no role are reported so the coverage gap stays visible.
export const rolesForHosts = (hosts) => {
  const roles = new Set();
  const resolved = [];
  const unresolved = [];
  for (const h of [...new Set((hosts || []).filter(Boolean))]) {
    const r = roleOf(h);
    if (r && r.roles.length) { r.roles.forEach(x => roles.add(x)); resolved.push({ host: h, ...r }); }
    else if (r) { resolved.push({ host: h, ...r }); }   // known owner, no mapped role
    else unresolved.push(h);
  }
  return { roles: [...roles], resolved, unresolved };
};
