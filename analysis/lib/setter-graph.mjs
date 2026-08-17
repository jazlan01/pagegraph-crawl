// setter-graph.mjs — the cross-cookie joins. Nothing else in this repo looks at more than one
// cookie at a time, and the literature's most discriminating features are precisely the ones that
// cannot be computed per-cookie:
//
//   "whether the setter's domain also acted as an end-point for other cookie exfiltrations, and
//    whether the setter's domain was involved in redirect chains … domains involved in setting
//    first-party ATS cookies are also involved in sharing information with other ATSes."
//
// The intuition is a vendor-cluster one: a domain that both plants cookies and collects other
// cookies is behaving like an ATS regardless of what any individual cookie looks like.
//
// NO COOKIE NAMES are used as signal here. Names appear only as map keys — identity for the
// join — and never enter a returned feature. That distinction matters: the papers exclude name
// as a FEATURE because it is trivially renamed, not as an identifier.

const uniq = (xs) => [...new Set(xs.filter(Boolean))];

// Every host this cookie's value was observed reaching, by any channel.
const destinationsOf = (ev) => uniq([
  ...(ev.httpTransmission || []).map((t) => t.host),
  ...(ev.jsExfil?.destinations || []).map((d) => d.host),
  ...(ev.headerExfil?.destinations || []).map((d) => d.host),
  ...(ev.bodyExfil?.destinations || []).map((d) => d.host),
]);

// Every host observed setting this cookie, by either channel.
const settersOf = (ev) => uniq([
  ...(ev.set?.httpSetters || []).map((s) => s.host),
  ...(ev.set?.jsWrites || []).map((w) => w.host),
]);

// Every script URL that wrote this cookie. Write-side attribution is exact (the `storage set`
// edge carries the cookie name as `key`), unlike reads, which are jar-wide.
const writersOf = (ev) => uniq((ev.set?.jsWrites || []).map((w) => w.scriptUrl));

const jaccard = (a, b) => {
  if (!a.size || !b.size) return 0;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  return inter / (a.size + b.size - inter);
};

/**
 * Build the page-wide joins once, then answer per-cookie questions against them.
 * `cookies` is the Map<name, evidence> from buildEvidence.
 */
export const buildSetterGraph = (cookies, pageRegDomain = null) => {
  // The page's own domain both sets and receives nearly every cookie on it, so counting it makes
  // the cluster signal fire maximally for ordinary first-party cookies and WEAKER for genuine
  // adtech: measured on directv, WAF cookies set by www.directv.com scored 36 while `ad-id` from
  // amazon-adsystem scored 1. The feature is about a THIRD party that both plants and collects,
  // so the first party is excluded from both sides of the join.
  const isFirstParty = (host) => {
    if (!pageRegDomain || !host) return false;
    const h = String(host).replace(/^\./, "");
    return h === pageRegDomain || h.endsWith(`.${pageRegDomain}`);
  };
  const destByCookie = new Map();
  const setterByCookie = new Map();
  const writerByCookie = new Map();
  const endpointToCookies = new Map();   // host -> Set(cookie names sent there)
  const writerToCookies = new Map();     // script URL -> Set(cookie names it set)

  for (const [name, ev] of cookies) {
    const dests = destinationsOf(ev);
    const setters = settersOf(ev);
    const writers = writersOf(ev);
    destByCookie.set(name, dests);
    setterByCookie.set(name, setters);
    writerByCookie.set(name, new Set(writers));
    for (const h of dests) {
      if (isFirstParty(h)) continue;
      if (!endpointToCookies.has(h)) endpointToCookies.set(h, new Set());
      endpointToCookies.get(h).add(name);
    }
    for (const w of writers) {
      if (!writerToCookies.has(w)) writerToCookies.set(w, new Set());
      writerToCookies.get(w).add(name);
    }
  }

  // How many DISTINCT scripts read the jar anywhere on this page. Read attribution is jar-wide —
  // `document.cookie` returns everything, so a read credits every cookie present — which makes a
  // raw reader count a proxy for "how long this cookie existed". Normalising against the page-wide
  // total at least makes the number comparable across pages; it does not make it per-cookie, and
  // the feature carries that caveat.
  const allReaders = new Set();
  for (const [, ev] of cookies) {
    for (const r of ev.reads?.readerScripts || []) allReaders.add(r.scriptUrl ?? r);
  }

  return {
    pageReaderCount: allReaders.size,

    // The paper's feature: does a domain that set this cookie also collect OTHER cookies?
    setterAlsoEndpoint(name) {
      const setters = (setterByCookie.get(name) || []).filter((h) => !isFirstParty(h));
      const others = new Set();
      for (const h of setters) {
        for (const other of endpointToCookies.get(h) || []) {
          if (other !== name) others.add(other);
        }
      }
      return { hosts: setters.filter((h) => (endpointToCookies.get(h)?.size ?? 0) > 0), otherCookieCount: others.size };
    },

    // Writer promiscuity: a script that sets many cookies is behaving like a tag platform.
    writerPromiscuity(name) {
      const writers = writerByCookie.get(name) || new Set();
      const counts = [...writers].map((w) => writerToCookies.get(w)?.size ?? 0);
      return {
        writerCount: writers.size,
        maxCookiesPerWriter: counts.length ? Math.max(...counts) : 0,
        meanCookiesPerWriter: counts.length
          ? +(counts.reduce((a, b) => a + b, 0) / counts.length).toFixed(2)
          : 0,
      };
    },

    // Vendor clustering with zero name input: how strongly does this cookie's writer set overlap
    // with some other cookie's? A high max-Jaccard means "same code planted both".
    writerSetOverlap(name) {
      const mine = writerByCookie.get(name) || new Set();
      if (!mine.size) return { maxJaccard: 0, sharesWritersWith: 0 };
      let max = 0, shares = 0;
      for (const [other, theirs] of writerByCookie) {
        if (other === name || !theirs.size) continue;
        const j = jaccard(mine, theirs);
        if (j > 0) shares++;
        if (j > max) max = j;
      }
      return { maxJaccard: +max.toFixed(2), sharesWritersWith: shares };
    },
  };
};
