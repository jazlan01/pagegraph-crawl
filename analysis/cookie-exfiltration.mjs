#!/usr/bin/env node
//
// Did a cookie's value leave the page in an HTTP request body?
//
// This is the question the graph alone cannot answer: PageGraph records a
// request's size but never its content, so a value posted to a collector is
// indistinguishable from a bodyless ping. Every provable leak had to appear in a
// URL, a header, or a JS argument. This joins the graph's cookie values against
// the bodies sidecar the crawler now writes, matching encoded forms as well as
// raw substrings, and attributes each hit back to the request edge that carried
// it.
//
// Usage:
//   node analysis/cookie-exfiltration.mjs <graphml> <bodies.ndjson[.gz]> \
//        [--cookie <name>] [--min-len N] [--json]
//
// Output: for each cookie, every body its value reached, the encoding it was in,
// a snippet, and the request URL + method.

import { createReadStream, existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { createGunzip } from "node:zlib";

import {
  streamElements,
  makeAttrReader,
  readPageUrl,
  graphExists,
  unwrap,
} from "./lib/graphml-stream.mjs";

// Values shorter than this match too much unrelated text to be evidence.
const DEFAULT_MIN_LEN = 8;
const SNIPPET_PAD = 40;

const args = process.argv.slice(2);
const positional = args.filter((a) => !a.startsWith("--"));
const flag = (name) => {
  const i = args.indexOf(name);
  return i === -1 ? null : args[i + 1];
};
const graphmlPath = positional[0];
const bodiesPath = positional[1];
const onlyCookie = flag("--cookie");
const minLen = Number(flag("--min-len") ?? DEFAULT_MIN_LEN);
const asJson = args.includes("--json");
const includeResponses = args.includes("--include-responses");

if (!graphmlPath || !bodiesPath) {
  console.error(
    "usage: cookie-exfiltration.mjs <graphml> <bodies.ndjson[.gz]> " +
      "[--cookie <name>] [--min-len N] [--include-responses] [--json]",
  );
  process.exit(2);
}
// graphExists, not existsSync: an archived graph is on disk as <name>.graphml.zst, so a bare
// existsSync on the .graphml path reports "no such file" for a graph that is perfectly readable.
if (!graphExists(graphmlPath)) {
  console.error(`no such file: ${graphmlPath}`);
  process.exit(2);
}
if (!existsSync(bodiesPath)) {
  console.error(`no such file: ${bodiesPath}`);
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Pass 1: collect cookie name -> values from the graph, and request id -> the
// script that initiated it, so a hit can name the code responsible.
// ---------------------------------------------------------------------------

const { noteKey, eAttr, nAttr } = makeAttrReader();

// cookie name -> Set of distinct values seen
const cookieValues = new Map();
// request id -> {url, initiatorNode}
const requestInitiator = new Map();
// node id -> script url, for attributing a request to code
const scriptUrlByNode = new Map();

const noteCookie = (key, value) => {
  if (!key || !value) return;
  if (onlyCookie && key !== onlyCookie) return;
  const v = unwrap(value);
  if (!v || v.length < minLen) return;
  if (!cookieValues.has(key)) cookieValues.set(key, new Set());
  cookieValues.get(key).add(v);
};

// A cookie READ returns the whole jar as one string with no per-cookie key
// ("a=1; b=2"), unlike a write which carries key and value separately. Splitting
// it is what makes each cookie's own value the thing we search for — matching the
// entire jar string instead finds only bodies that happened to post the whole
// jar, and misses every request that sent one identifier.
const noteCookieJar = (jar) => {
  const v = unwrap(jar);
  if (!v || !v.includes("=")) return;
  for (const pair of v.split(";")) {
    const trimmed = pair.trim();
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    noteCookie(trimmed.slice(0, eq).trim(), trimmed.slice(eq + 1).trim());
  }
};

for await (const { tag, head, body } of streamElements(graphmlPath)) {
  if (tag === "key") {
    noteKey(head);
    continue;
  }
  if (tag === "node") {
    if (nAttr(body, "node type") === "script") {
      const id = (head.match(/id="(n\d+)"/) || [])[1];
      if (id) {
        // PageGraph leaves `url` empty even on external scripts, so fall back to
        // the head of the recorded source — enough to identify the code by eye.
        const url = nAttr(body, "url");
        const source = nAttr(body, "source") ?? "";
        const firstLine = source.split("\n")[0].trim().slice(0, 80);
        scriptUrlByNode.set(
          id,
          url ||
            (firstLine
              ? `${nAttr(body, "script type") ?? "script"}: ${firstLine}`
              : null),
        );
      }
    }
    continue;
  }

  const edgeType = eAttr(body, "edge type");
  if (!edgeType) continue;

  // Writes carry key and value separately: the JS channel (document.cookie,
  // cookieStore) and the synthesized `set-cookie-header` edges both land here.
  if (edgeType === "storage set") {
    noteCookie(eAttr(body, "key"), eAttr(body, "value"));
  }
  // Reads hand back the whole jar in one value.
  if (edgeType === "storage read result") {
    noteCookieJar(eAttr(body, "value"));
  }

  // Which script started each request, so a leak can be blamed on code.
  if (edgeType === "request start") {
    const rid = eAttr(body, "request id");
    if (rid) {
      const source = (head.match(/source="(n\d+)"/) || [])[1];
      requestInitiator.set(String(rid), source ?? null);
    }
  }
}

if (cookieValues.size === 0) {
  console.error(
    "No cookie values found in the graph" +
      (onlyCookie ? ` for --cookie ${onlyCookie}` : "") +
      ` with length >= ${minLen}.`,
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Encodings a value can be wearing by the time it reaches a body. A tracker that
// base64s an identifier is still exfiltrating it, so matching only raw
// substrings understates the problem.
// ---------------------------------------------------------------------------

const b64 = (s) => Buffer.from(s, "utf8").toString("base64");
const encodingsFor = (value) => {
  const forms = new Map();
  const add = (name, s) => {
    if (s && s.length >= minLen && !forms.has(s)) forms.set(s, name);
  };
  add("raw", value);
  add("urlencoded", encodeURIComponent(value));
  add("base64", b64(value));
  // base64url, and base64 without padding — both common in tracker payloads.
  add("base64url", b64(value).replace(/\+/g, "-").replace(/\//g, "_"));
  add("base64-nopad", b64(value).replace(/=+$/, ""));
  // A value embedded in a JSON string is escaped; only matters if it contains
  // characters JSON escapes.
  const jsonEscaped = JSON.stringify(value).slice(1, -1);
  add("json-escaped", jsonEscaped);
  return forms;
};

const snippetAround = (haystack, needle) => {
  const i = haystack.indexOf(needle);
  if (i === -1) return null;
  const start = Math.max(0, i - SNIPPET_PAD);
  const end = Math.min(haystack.length, i + needle.length + SNIPPET_PAD);
  return (start > 0 ? "…" : "") + haystack.slice(start, end) +
    (end < haystack.length ? "…" : "");
};

// ---------------------------------------------------------------------------
// Pass 2: stream the bodies sidecar, matching every cookie value against every
// body.
// ---------------------------------------------------------------------------

const openBodies = (path) => {
  const raw = createReadStream(path);
  return path.endsWith(".gz") ? raw.pipe(createGunzip()) : raw;
};

// cookie name -> array of hits
const findings = new Map();
const stats = { records: 0, withBody: 0, truncated: 0, dropped: 0 };

const rl = createInterface({
  input: openBodies(bodiesPath),
  crlfDelay: Infinity,
});

for await (const line of rl) {
  const text = line.trim();
  if (text === "") continue;
  let rec;
  try {
    rec = JSON.parse(text);
  } catch {
    // A crash during the crawl can leave a partial final line; skip it rather
    // than lose every finding before it.
    continue;
  }
  stats.records += 1;
  if (rec.truncated) stats.truncated += 1;
  if (rec.dropped) stats.dropped += 1;
  if (!rec.body) continue;
  stats.withBody += 1;

  // Outbound only by default. A value in a RESPONSE body is usually its origin
  // (a script whose source hardcodes it) or a partner echoing it back — worth
  // seeing sometimes, but reporting it as a "leak" alongside real exfiltration
  // buries the finding that matters.
  if (rec.kind !== "request" && !includeResponses) continue;

  // base64 bodies are compared in their decoded form too, so a value inside a
  // binary payload is still found.
  const haystacks = [rec.body];
  if (rec.encoding === "base64") {
    try {
      haystacks.push(Buffer.from(rec.body, "base64").toString("utf8"));
    } catch {
      /* not decodable */
    }
  }

  for (const [name, values] of cookieValues) {
    for (const value of values) {
      for (const [form, encoding] of encodingsFor(value)) {
        const hay = haystacks.find((h) => h.includes(form));
        if (!hay) continue;
        if (!findings.has(name)) findings.set(name, []);
        const initiatorNode = requestInitiator.get(String(rec.requestId));
        findings.get(name).push({
          cookie: name,
          value,
          encoding,
          kind: rec.kind,
          method: rec.method ?? null,
          status: rec.status ?? null,
          url: rec.url,
          requestId: rec.requestId,
          truncated: Boolean(rec.truncated),
          initiatorScript: initiatorNode
            ? (scriptUrlByNode.get(initiatorNode) ?? initiatorNode)
            : null,
          snippet: snippetAround(hay, form),
        });
        // One hit per value per body is enough; don't report the same leak once
        // per encoding.
        break;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

// Resolved once: on an archived graph each readPageUrl call re-opens and re-decompresses the
// header, and this value is printed on both the JSON and the human path.
const pageUrlValue = await readPageUrl(graphmlPath);

if (asJson) {
  console.log(
    JSON.stringify(
      {
        pageUrl: pageUrlValue,
        stats,
        cookiesConsidered: [...cookieValues.keys()],
        findings: Object.fromEntries(findings),
      },
      null,
      2,
    ),
  );
  // NO process.exit() here. stdout to a pipe is asynchronous: exiting immediately after a large
  // write truncates it at the 64 KB pipe buffer, and the consumer sees "Unterminated string in
  // JSON". That is exactly how this tool's output reached cookie-evidence.mjs as a parse error
  // rather than as data. Falling off the end lets Node flush before the process ends.
}
if (!asJson) {

console.log(`page: ${pageUrlValue ?? "(unknown)"}`);
console.log(
  `bodies: ${stats.records} records, ${stats.withBody} with content, ` +
    `${stats.truncated} truncated, ${stats.dropped} dropped`,
);
console.log(
  `cookies considered (value length >= ${minLen}): ` +
    `${cookieValues.size}\n`,
);

if (findings.size === 0) {
  console.log("No cookie value was found in any captured request body.");
  if (stats.dropped > 0) {
    console.log(
      `Note: ${stats.dropped} bodies were not captured (MIME filter or size ` +
        "budget), so this is not proof of absence — re-run with " +
        "--save-bodies-full and a larger --bodies-budget-mb to widen coverage.",
    );
  }
  process.exit(0);
}

for (const [name, hits] of findings) {
  console.log(`${name}: ${hits.length} leak(s)`);
  for (const h of hits) {
    const where = h.kind === "request" ? `${h.method} ${h.url}` : `<- ${h.url}`;
    console.log(`  ${where}`);
    console.log(
      `    encoding=${h.encoding} requestId=${h.requestId}` +
        (h.truncated ? " (body truncated; match found in kept prefix)" : ""),
    );
    if (h.initiatorScript) {
      console.log(`    initiated by: ${h.initiatorScript}`);
    }
    if (h.snippet) {
      console.log(`    ${h.snippet}`);
    }
  }
  console.log("");
}
}
