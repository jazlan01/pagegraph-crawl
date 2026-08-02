import assert from "node:assert";
import { createReadStream, createWriteStream } from "node:fs";
import { readFile } from "node:fs/promises";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

import type { HTTPRequest, HTTPResponse } from "puppeteer-core";
import { Element } from "xml-stream-editor";

import type { BodyLog } from "./body_log.js";
import { PageGraphXMLRewriter } from "./graphml_rewriter.js";

interface HTTPHeader {
  name: string;
  value: string;
}

// Minimal shapes of the CDP events we consume. The full Protocol types live in
// puppeteer-core's devtools-protocol, but we only touch these fields.
interface RequestWillBeSentExtraInfo {
  requestId: string;
  headers: Record<string, string>;
}

interface ResponseReceivedExtraInfo {
  requestId: string;
  headers: Record<string, string>;
}

// One hop of a request. A request with no redirects has exactly one.
//
// Hops matter because a redirect chain shares a single request id, so storing
// response metadata per id collapses the chain to its last hop — which both loses
// every intermediate `Set-Cookie` and misattributes the surviving ones to the
// final URL rather than the hop that actually sent them. That is the cookie-sync
// pattern (a tracker bouncing through partners, each dropping an identifier), so
// getting it wrong names the wrong party.
interface RedirectHop {
  url: string;
  // Status of the response that ended this hop: 3xx for intermediate hops, the
  // final status for the last one.
  status?: number;
  setCookies?: SetCookie[];
  responseHeaders?: HTTPHeader[];
}

interface Metadata {
  headers: HTTPHeader[];
  size: number;
}

// The URL + method of a request, keyed by request id, so the per-cookie network
// map can name which request carried or set each cookie.
interface RequestInfo {
  url: string;
  method: string;
}

// A cookie set by an HTTP `Set-Cookie` response header, associated with the
// request that carried the response. These are synthesized into the graph as
// `storage set` edges tagged `cookie source = set-cookie-header`, because the
// renderer never sees the raw `Set-Cookie` (the network service strips it), so
// PageGraph cannot record them itself.
interface SetCookie {
  key: string;
  value: string;
}

type RequestToHeadersMap = Record<RequestId, HTTPHeader[] | undefined>;
type RequestToSetCookiesMap = Record<RequestId, SetCookie[] | undefined>;

// The graphml `node type` / `edge type` / `cookie source` values we key off of.
const nodeTypeCookieJar = "cookie jar";
const nodeTypeResource = "resource";
const edgeTypeStorageSet = "storage set";
const cookieSourceSetCookieHeader = "set-cookie-header";

enum RequestIdParseType {
  NAVIGATION,
  SUB_REQUEST,
  INTERCEPTION,
}

interface RequestIdParse {
  id: RequestId;
  type: RequestIdParseType;
}

type RequestType = typeof HTTPRequest;
type ResponseType = typeof HTTPResponse;
type PuppeteerRequestId = string;
type RequestId = number | string;
type RequestToMetadataMap = Record<RequestId, Metadata | undefined>;
type RequestToInfoMap = Record<RequestId, RequestInfo | undefined>;

enum UpdateType {
  ADD = "ADD",
  REDUNDANT = "REDUNDANT",
  UPDATE = "UPDATE",
}

const edgeAttrEdgeType = "edge type";
const edgeAttrRequestId = "request id";
const edgeAttrHeaders = "headers";
const edgeAttrSize = "size";
const edgeAttrTimestamp = "timestamp";
const edgeAttrKey = "key";
const edgeAttrValue = "value";
const edgeAttrCookieSource = "cookie source";

const requestIdPatternWorker = /interception-job-([0-9]+)\.0/;
const requestIdPatternNavigation = /^[A-Z0-9]{32}$/;
const requestIdPatternSubRequest = /^[0-9]+\.([0-9]+)$/;

const headerSortFunc = (a: HTTPHeader, b: HTTPHeader) => {
  if (a.name !== b.name) {
    return a.name < b.name ? -1 : 1;
  }
  return a.value < b.value ? -1 : 1;
};

export class RequestMetadataTracker {
  #requestMetadata: RequestToMetadataMap = {};
  #responseMetadata: RequestToMetadataMap = {};
  // Raw request/response headers from CDP `*ExtraInfo` events. Unlike the
  // puppeteer `request/response.headers()` used above, these include the raw
  // `Cookie` (outgoing) and `Set-Cookie` (incoming) headers, which puppeteer
  // omits. Merged into the injected `headers` attribute at rewrite time.
  #requestExtraHeaders: RequestToHeadersMap = {};
  #responseExtraHeaders: RequestToHeadersMap = {};
  // Cookies set by `Set-Cookie` response headers, per request. Accumulated
  // across every hop of a redirect chain rather than overwritten, so no hop's
  // cookies are lost even if per-hop attribution below fails.
  #responseSetCookies: RequestToSetCookiesMap = {};
  // The hop chain per request id.
  #hopsByRequest: Record<RequestId, RedirectHop[] | undefined> = {};
  // URL + method per request id, so the per-cookie network map can name which
  // request carried or set each cookie.
  #requestInfo: RequestToInfoMap = {};
  readonly #logger: Logger | undefined;
  readonly #strict: boolean;
  // When set, every request/response body observed is streamed to this log
  // instead of being discarded after its length is measured.
  readonly #bodyLog: BodyLog | undefined;

  constructor(logger?: Logger, strict = false, bodyLog?: BodyLog) {
    this.#logger = logger;
    this.#strict = strict;
    this.#bodyLog = bodyLog;
  }

  #log(methodName: string, msg: any): void {
    if (!this.#logger) {
      return;
    }
    this.#logger.info(`RequestMetadataTracker.${methodName}) `, msg);
  }

  #logVerbose(methodName: string, msg: any): void {
    if (!this.#logger) {
      return;
    }
    this.#logger.verbose(`RequestMetadataTracker.${methodName}) `, msg);
  }

  #error(msg: string): never {
    throw new Error(msg);
  }

  // Fetches a request's post data over CDP, keeping both its size (for the
  // graphml `size` attribute) and the bytes themselves (for the body sidecar).
  // The CDP round trip happens either way, so retaining the body is free.
  //
  // `size` stays the string length rather than the byte length, because that is
  // what the graphml `size` attribute has always carried.
  #captureRequestBody = async (
    request: RequestType,
  ): Promise<{ size: number; body?: string }> => {
    try {
      const requestBody = await request.fetchPostData();
      if (!requestBody) {
        return { size: 0 };
      }
      return { size: +requestBody.length, body: requestBody };
    } catch {
      this.#log(
        "#captureRequestBody",
        "No content for request: " + String(request.url()),
      );
      return { size: 0 };
    }
  };

  #captureResponseBody = async (
    response: ResponseType,
  ): Promise<{ size: number; bytes?: Uint8Array; failed: boolean }> => {
    try {
      const body = await response.content();
      // Puppeteer returns bytes, but tolerate a string in case a future version
      // (or a mocked response) hands back decoded text.
      const bytes: Uint8Array =
        typeof body === "string" ? Buffer.from(body, "utf8") : body;
      return { size: +body.length, bytes, failed: false };
    } catch {
      this.#log(
        "#captureResponseBody",
        "No content for response: " + String(response.url()),
      );
      return { size: 0, failed: true };
    }
  };

  #addMetadata(
    requestId: RequestId,
    reqOrRes: RequestType,
    bodySize: number,
    collection: RequestToMetadataMap,
  ): UpdateType {
    const headers: HTTPHeader[] = [];
    for (const headerEntry of Object.entries(reqOrRes.headers())) {
      headers.push({
        name: headerEntry[0],
        value: headerEntry[1] as string,
      });
    }
    headers.sort(headerSortFunc);

    const metadata: Metadata = {
      headers: headers,
      size: bodySize,
    };
    const typeName =
      collection === this.#requestMetadata ? "request" : "response";
    this.#logVerbose(
      "addMetadata",
      `RequestId=${String(requestId)} (${typeName}): size=${String(bodySize)}, ` +
        `headers=${JSON.stringify(metadata)}`,
    );
    // Seeing a repeated request id can happen when the page redirects
    // during the crawl (e.g., the page makes requests 1, 2, and 3; the browser
    // is redirected to a new page; that new page also makes requests 1,
    // 2, and 3). When this happens, overwrite the older request's headers
    // with the new ones, since the most recent request will always be
    // the one depicted in the page-graph file.
    const prevMetadata = collection[requestId];
    const isFirstTimeSeeingRequestId = prevMetadata === undefined;
    if (!isFirstTimeSeeingRequestId) {
      const previousMetadataJSON = JSON.stringify(prevMetadata);
      const currentMetadataJSON = JSON.stringify(metadata);
      const areSame = previousMetadataJSON === currentMetadataJSON;

      if (areSame) {
        // If the headers for this request are the same
        // as for the previously seen request, and so no changes needed.
        this.#log(
          "addMetadata",
          `RequestId=${String(requestId)} (${typeName}): same as previous.`,
        );
        return UpdateType.REDUNDANT;
      }

      this.#log(
        "addMetadata",
        `RequestId=${String(requestId)} (${typeName}): set new value.`,
      );
      collection[requestId] = metadata;
      return UpdateType.UPDATE;
    }

    collection[requestId] = metadata;
    return UpdateType.ADD;
  }

  // Request ids in puppeteer are in three formats.
  // 1. requests made in workers: "interception-job-<int>.0"
  // 2. sub-resource requests: "<int (process id)>.<int (request id)>"
  // 3. top level navigation requests: 32 alpha num characters
  //
  // Since PageGraph runs in single process mode, we can discard the process
  // id for this second category of requests.
  #simplifyRequestId(rawRequestId: PuppeteerRequestId): RequestIdParse {
    const interceptRequestMatchRs = requestIdPatternWorker.exec(rawRequestId);
    if (interceptRequestMatchRs !== null) {
      const requestId = parseInt(interceptRequestMatchRs[1], 10);
      this.#log(
        "simplifyRequestId",
        `RequestId: ${String(requestId)} ("intercept", from ${rawRequestId})`,
      );
      return { id: requestId, type: RequestIdParseType.INTERCEPTION };
    }

    const subRequestMatchRs = requestIdPatternSubRequest.exec(rawRequestId);
    if (subRequestMatchRs !== null) {
      const requestIdParts = rawRequestId.split(".");
      const requestId = parseInt(requestIdParts[1], 10);
      this.#log(
        "simplifyRequestId",
        `RequestId: ${String(requestId)} ("subrequest", from ${rawRequestId})`,
      );
      return { id: requestId, type: RequestIdParseType.SUB_REQUEST };
    }

    const navRequestMatchRs = requestIdPatternNavigation.exec(rawRequestId);
    if (navRequestMatchRs !== null) {
      this.#log(
        "simplifyRequestId",
        `RequestId: ${rawRequestId} ("navigation")`,
      );
      return { id: rawRequestId, type: RequestIdParseType.NAVIGATION };
    }

    this.#error(`RequestId does not have a known format: "${rawRequestId}"`);
  }

  async addMetadataFromRequest(request: RequestType): Promise<UpdateType> {
    const parseResult = this.#simplifyRequestId(request.id);
    this.#noteRequestHop(parseResult.id, request);
    this.#requestInfo[parseResult.id] = {
      url: request.url(),
      method: request.method(),
    };

    // Navigation requests keep the historical `-1` size and are not fetched over
    // CDP. `postData()` is synchronous and already populated from
    // `requestWillBeSent`, so a form-submit navigation body is still captured
    // without reintroducing a round trip here.
    const captured =
      parseResult.type === RequestIdParseType.NAVIGATION
        ? { size: -1, body: request.postData() as string | undefined }
        : await this.#captureRequestBody(request);

    if (this.#bodyLog !== undefined) {
      await this.#bodyLog.appendRequest({
        requestId: parseResult.id,
        rawRequestId: request.id,
        url: request.url(),
        method: request.method(),
        resourceType: request.resourceType(),
        body: captured.body,
        hasPostData: request.hasPostData() === true,
      });
    }

    const collection = this.#requestMetadata;
    return this.#addMetadata(
      parseResult.id,
      request,
      captured.size,
      collection,
    );
  }

  async addMetadataFromResponse(response: ResponseType): Promise<UpdateType> {
    const rawRequestId = response.request().id;
    const parseResult = this.#simplifyRequestId(rawRequestId);

    // Record the status against the hop this response ended, so an intermediate
    // 302 is not overwritten by the chain's final 200.
    //
    // Positional rather than `response.request().redirectChain()`: for a redirect
    // response that returns the chain's *latest* request, not the one this
    // response answered, which lands every hop's status on the final hop.
    const hopForResponse = this.#currentHop(parseResult.id);
    if (hopForResponse !== undefined) {
      hopForResponse.status = response.status();
    }

    const captured = await this.#captureResponseBody(response);

    if (this.#bodyLog !== undefined) {
      const headers = response.headers();
      await this.#bodyLog.appendResponse({
        requestId: parseResult.id,
        rawRequestId,
        url: response.url(),
        status: response.status(),
        mimeType: headers["content-type"],
        resourceType: response.request().resourceType(),
        bytes: captured.bytes,
        failed: captured.failed,
      });
    }

    const collection = this.#responseMetadata;
    return this.#addMetadata(
      parseResult.id,
      response,
      captured.size,
      collection,
    );
  }

  // The request id on CDP `*ExtraInfo` events uses the same formats puppeteer
  // exposes, but a format we don't recognize should be skipped rather than
  // abort the crawl, so this never throws.
  #trySimplifyRequestId(
    rawRequestId: PuppeteerRequestId,
  ): RequestId | undefined {
    try {
      return this.#simplifyRequestId(rawRequestId).id;
    } catch {
      this.#logVerbose(
        "trySimplifyRequestId",
        `Skipping ExtraInfo for unrecognized request id "${rawRequestId}"`,
      );
      return undefined;
    }
  }

  #headersFromObject(
    headersObj: Record<string, string> | undefined,
  ): HTTPHeader[] {
    const headers: HTTPHeader[] = [];
    if (!headersObj) {
      return headers;
    }
    for (const [name, value] of Object.entries(headersObj)) {
      headers.push({ name, value });
    }
    headers.sort(headerSortFunc);
    return headers;
  }

  // Records which hop of a redirect chain a request event represents.
  //
  // `redirectChain()` is the hop index directly: 0 for the original request, 1 for
  // the first redirect target, and so on. A hop index of 0 therefore also marks a
  // brand new request reusing this id, which is the case the old last-wins storage
  // was really guarding against.
  //
  // Must be called before any `await`, so the reset cannot race the
  // `responseReceivedExtraInfo` events whose cookies it clears.
  #noteRequestHop(requestId: RequestId, request: RequestType): void {
    const hopIndex: number = request.redirectChain().length;
    if (hopIndex === 0) {
      // A fresh logical request, so discard any previous chain under this id —
      // matching the existing "most recent request wins" behaviour, but at
      // whole-chain rather than per-hop granularity.
      this.#hopsByRequest[requestId] = [{ url: request.url() }];
      this.#responseSetCookies[requestId] = undefined;
      return;
    }
    const hops = this.#hopsByRequest[requestId] ?? [];
    hops[hopIndex] = { url: request.url() };
    this.#hopsByRequest[requestId] = hops;
  }

  // The hop a just-arrived `*ExtraInfo` event belongs to. Those events carry no
  // URL and no request object, so the hop is identified positionally: always the
  // most recently started one, because a redirect's response is delivered before
  // the browser issues the next hop's request (verified against a three-hop
  // fixture: req/res strictly interleave per hop).
  #currentHop(requestId: RequestId): RedirectHop | undefined {
    const hops = this.#hopsByRequest[requestId];
    if (hops === undefined || hops.length === 0) {
      return undefined;
    }
    return hops[hops.length - 1];
  }

  // The hop chain of every request that redirected at least once, keyed by
  // request id. Written to a sidecar because the graphml's request edges declare
  // only `headers` and `size`, so there is nowhere in the graph to put per-hop
  // status or `Set-Cookie`.
  toRedirectChainsJSON(): string {
    const chains: Record<string, RedirectHop[]> = {};
    for (const [requestId, hops] of Object.entries(this.#hopsByRequest)) {
      if (hops !== undefined && hops.length > 1) {
        chains[requestId] = hops;
      }
    }
    return JSON.stringify(chains, null, 2);
  }

  // CDP `Network.requestWillBeSentExtraInfo`: the raw outgoing request headers,
  // including the `Cookie` header (which puppeteer's request.headers() omits).
  addExtraInfoFromRequestEvent(event: RequestWillBeSentExtraInfo): void {
    const requestId = this.#trySimplifyRequestId(event.requestId);
    if (requestId === undefined) {
      return;
    }
    this.#requestExtraHeaders[requestId] = this.#headersFromObject(
      event.headers,
    );
  }

  // CDP `Network.responseReceivedExtraInfo`: the raw incoming response headers,
  // including `Set-Cookie` (which puppeteer's response.headers() omits, and
  // which the renderer never sees so PageGraph cannot record).
  addExtraInfoFromResponseEvent(event: ResponseReceivedExtraInfo): void {
    const requestId = this.#trySimplifyRequestId(event.requestId);
    if (requestId === undefined) {
      return;
    }
    const headers = this.#headersFromObject(event.headers);
    this.#responseExtraHeaders[requestId] = headers;

    // These events carry no URL, so the hop is identified positionally: this
    // response belongs to the most recently started hop.
    const setCookies = this.#parseSetCookieHeaders(event.headers);
    const hop = this.#currentHop(requestId);
    if (hop !== undefined) {
      hop.responseHeaders = headers;
      if (setCookies.length > 0) {
        hop.setCookies = setCookies;
      }
    }

    if (setCookies.length > 0) {
      // Accumulate rather than overwrite: a redirect chain shares one request id
      // and each hop may set its own cookies.
      const accumulated = this.#responseSetCookies[requestId] ?? [];
      accumulated.push(...setCookies);
      this.#responseSetCookies[requestId] = accumulated;
    }
  }

  // CDP joins multiple `Set-Cookie` response headers into a single value
  // separated by newlines. Each is a cookie definition whose leading
  // `name=value` pair identifies the cookie.
  #parseSetCookieHeaders(
    headersObj: Record<string, string> | undefined,
  ): SetCookie[] {
    if (!headersObj) {
      return [];
    }
    const cookies: SetCookie[] = [];
    for (const [name, value] of Object.entries(headersObj)) {
      if (name.toLowerCase() !== "set-cookie") {
        continue;
      }
      for (const line of value.split("\n")) {
        const trimmed = line.trim();
        if (trimmed === "") {
          continue;
        }
        const eqIndex = trimmed.indexOf("=");
        const semiIndex = trimmed.indexOf(";");
        const nameEnd = eqIndex === -1 ? trimmed.length : eqIndex;
        const cookieName = trimmed.slice(0, nameEnd).trim();
        const valueEnd = semiIndex === -1 ? trimmed.length : semiIndex;
        const cookieValue =
          eqIndex === -1 ? "" : trimmed.slice(eqIndex + 1, valueEnd).trim();
        cookies.push({ key: cookieName, value: cookieValue });
      }
    }
    return cookies;
  }

  // Merges base headers with the raw `*ExtraInfo` headers, letting the raw
  // headers win on a name collision (case-insensitive), then re-sorts.
  #mergeHeaders(base: HTTPHeader[], extra: HTTPHeader[]): HTTPHeader[] {
    if (extra.length === 0) {
      return base;
    }
    const extraNames = new Set(extra.map((h) => h.name.toLowerCase()));
    const merged = base.filter((h) => !extraNames.has(h.name.toLowerCase()));
    merged.push(...extra);
    merged.sort(headerSortFunc);
    return merged;
  }

  toJSON(): string {
    return JSON.stringify({
      requests: this.#requestMetadata,
      responses: this.#responseMetadata,
    });
  }

  // Parses the cookie names present in outgoing `Cookie` request headers, e.g.
  // `Cookie: a=1; b=2` -> ["a", "b"].
  #cookieNamesFromHeaders(headers: HTTPHeader[]): string[] {
    const names: string[] = [];
    for (const header of headers) {
      if (header.name.toLowerCase() !== "cookie") {
        continue;
      }
      for (const pair of header.value.split(";")) {
        const eqIndex = pair.indexOf("=");
        const name = (eqIndex === -1 ? pair : pair.slice(0, eqIndex)).trim();
        if (name !== "") {
          names.push(name);
        }
      }
    }
    return names;
  }

  // Builds a per-cookie network map from the captured request/response headers:
  // for each cookie name, which responses set it (`Set-Cookie`) and which
  // requests carried it (outgoing `Cookie` header), each tagged with the request
  // URL. This is the network-level view of every cookie's lifecycle, and is built
  // entirely from the non-pausing CDP `*ExtraInfo` data, so it is available even
  // when graph generation fails.
  toCookieNetworkJSON(): string {
    interface CookieSetEvent {
      requestId: RequestId;
      url: string | undefined;
      value: string;
      // Present when the setter was a hop of a redirect chain: which hop, and the
      // status it answered with. Without this a cookie dropped mid-chain looks
      // like it came from the chain's final URL.
      hopIndex?: number;
      hopStatus?: number;
    }
    interface CookieSentEvent {
      requestId: RequestId;
      url: string | undefined;
      method: string | undefined;
    }
    interface CookieNetwork {
      setBy: CookieSetEvent[];
      sentTo: CookieSentEvent[];
    }
    const cookies = new Map<string, CookieNetwork>();
    const entryFor = (name: string): CookieNetwork => {
      let entry = cookies.get(name);
      if (entry === undefined) {
        entry = { setBy: [], sentTo: [] };
        cookies.set(name, entry);
      }
      return entry;
    };

    // Responses that set a cookie via `Set-Cookie`. Attributed to the specific
    // hop that sent the header, not to the request id's final URL.
    for (const [requestId, setCookies] of Object.entries(
      this.#responseSetCookies,
    )) {
      if (setCookies === undefined) {
        continue;
      }
      const hops = this.#hopsByRequest[requestId];
      // Cookies we could place on a hop, so the fallback below only covers the
      // rest (e.g. a response whose request never produced a
      // `requestWillBeSent`, such as one served from cache).
      const attributed = new Set<SetCookie>();
      if (hops !== undefined) {
        hops.forEach((hop, hopIndex) => {
          for (const cookie of hop.setCookies ?? []) {
            attributed.add(cookie);
            entryFor(cookie.key).setBy.push({
              requestId,
              url: hop.url,
              value: cookie.value,
              hopIndex,
              hopStatus: hop.status,
            });
          }
        });
      }
      const fallbackUrl = this.#requestInfo[requestId]?.url;
      for (const cookie of setCookies) {
        if (attributed.has(cookie)) {
          continue;
        }
        entryFor(cookie.key).setBy.push({
          requestId,
          url: fallbackUrl,
          value: cookie.value,
        });
      }
    }

    // Requests that carried a cookie in the outgoing `Cookie` header.
    for (const [requestId, headers] of Object.entries(
      this.#requestExtraHeaders,
    )) {
      if (headers === undefined) {
        continue;
      }
      const info = this.#requestInfo[requestId];
      for (const name of this.#cookieNamesFromHeaders(headers)) {
        entryFor(name).sentTo.push({
          requestId,
          url: info?.url,
          method: info?.method,
        });
      }
    }

    return JSON.stringify(Object.fromEntries(cookies), null, 2);
  }

  async fromJSONFile(fromPath: FilePath): Promise<void> {
    const jsonText = await readFile(fromPath, { encoding: "utf8" });
    const data = JSON.parse(jsonText);
    if (typeof data.requests !== "object") {
      this.#error(
        `JSON from "${fromPath}" is missing "requests" property.\n${jsonText}`,
      );
    }
    this.#requestMetadata = data.requests as RequestToMetadataMap;

    if (typeof data.responses !== "object") {
      this.#error(
        `JSON from "${fromPath}" is missing "responses" property.\n${jsonText}`,
      );
    }
    this.#responseMetadata = data.responses as RequestToMetadataMap;
  }

  async rewriteGraphML(graphMLPath: FilePath, toPath: FilePath): Promise<void> {
    const inputStream = createReadStream(graphMLPath, { encoding: "utf8" });
    const outputStream = createWriteStream(toPath);
    const rewriter = new PageGraphXMLRewriter();

    // Graph structure collected during the streaming pass, used afterwards to
    // synthesize `set-cookie-header` edges. All populated before the closing
    // </graph> flows through the injector below.
    let cookieJarNodeId: string | undefined;
    const resourceNodeIds = new Set<string>();
    const requestResourceNodeId: Record<RequestId, string | undefined> = {};
    const requestTimestamp: Record<RequestId, string | undefined> = {};
    let maxEdgeNumericId = 0;

    const editNodeFunc = (elm: Element, editor: PageGraphXMLRewriter) => {
      const nodeType = editor.getAttr(elm, "node type");
      const nodeId = elm.attributes.id;
      if (nodeType === nodeTypeCookieJar) {
        cookieJarNodeId = nodeId;
      } else if (nodeType === nodeTypeResource) {
        resourceNodeIds.add(nodeId);
      }
      return elm;
    };

    const editEdgeFunc = (elm: Element, editor: PageGraphXMLRewriter) => {
      // Track the largest edge id so synthesized edges get fresh, unique ids.
      const edgeNumericId = parseInt(elm.attributes.id.replace(/^e/, ""), 10);
      if (!Number.isNaN(edgeNumericId) && edgeNumericId > maxEdgeNumericId) {
        maxEdgeNumericId = edgeNumericId;
      }

      const attrs = editor.getAttrs(
        elm,
        edgeAttrEdgeType,
        edgeAttrRequestId,
        edgeAttrTimestamp,
      );
      const edgeType = attrs[edgeAttrEdgeType];
      assert(edgeType);

      let metadataCollection: RequestToMetadataMap | undefined;
      let extraHeadersCollection: RequestToHeadersMap | undefined;
      switch (edgeType) {
        case "request start":
        case "request redirect":
          metadataCollection = this.#requestMetadata;
          extraHeadersCollection = this.#requestExtraHeaders;
          break;
        case "request error":
        case "request complete":
          metadataCollection = this.#responseMetadata;
          extraHeadersCollection = this.#responseExtraHeaders;
          break;
        default:
          return elm;
      }

      const requestId = attrs[edgeAttrRequestId];
      assert(requestId);

      // Remember where to attach synthesized Set-Cookie edges: the resource
      // node of the completed request, and when it completed.
      if (
        edgeType === "request complete" &&
        this.#responseSetCookies[requestId] !== undefined
      ) {
        const { source, target } = elm.attributes;
        const resourceNodeId = resourceNodeIds.has(source)
          ? source
          : resourceNodeIds.has(target)
            ? target
            : undefined;
        if (resourceNodeId !== undefined) {
          requestResourceNodeId[requestId] = resourceNodeId;
        }
        const timestamp = attrs[edgeAttrTimestamp];
        if (timestamp) {
          requestTimestamp[requestId] = timestamp;
        }
      }

      const metadata = metadataCollection[requestId];
      const extraHeaders = extraHeadersCollection[requestId] ?? [];
      const mergedHeaders = this.#mergeHeaders(
        metadata?.headers ?? [],
        extraHeaders,
      );

      if (metadata === undefined && extraHeaders.length === 0) {
        if (this.#strict) {
          this.#error(
            "Unable to find metadata for request record in graphml. " +
              `RequestId=${requestId}`,
          );
        }
        return elm;
      }

      if (mergedHeaders.length > 0) {
        editor.setAttr(elm, edgeAttrHeaders, JSON.stringify(mergedHeaders));
      }
      if (metadata !== undefined) {
        editor.setAttr(elm, edgeAttrSize, String(metadata.size));
      }
      return elm;
    };

    rewriter.setNodeEditor(editNodeFunc);
    rewriter.setEdgeEditor(editEdgeFunc);

    // Built lazily, once the streaming pass has populated the collections above.
    const buildSynthesizedEdges = (): string =>
      this.#buildSetCookieEdges(
        rewriter,
        cookieJarNodeId,
        requestResourceNodeId,
        requestTimestamp,
        () => ++maxEdgeNumericId,
      );

    await pipeline(
      inputStream,
      rewriter.createTransform(),
      makeGraphCloseInjector(buildSynthesizedEdges),
      outputStream,
    );
  }

  // Builds the `<edge>` XML for every cookie set via an HTTP `Set-Cookie`
  // header, each running from the request's resource node to the cookie jar and
  // tagged `cookie source = set-cookie-header`. These have no JS stack (their
  // provenance is the request, reachable via the shared `request id`).
  #buildSetCookieEdges(
    rewriter: PageGraphXMLRewriter,
    cookieJarNodeId: string | undefined,
    requestResourceNodeId: Record<RequestId, string | undefined>,
    requestTimestamp: Record<RequestId, string | undefined>,
    nextEdgeId: () => number,
  ): string {
    if (cookieJarNodeId === undefined) {
      return "";
    }
    const edgeTypeId = rewriter.getEdgeAttrId(edgeAttrEdgeType);
    const keyId = rewriter.getEdgeAttrId(edgeAttrKey);
    const valueId = rewriter.getEdgeAttrId(edgeAttrValue);
    const cookieSourceId = rewriter.getEdgeAttrId(edgeAttrCookieSource);
    const requestIdId = rewriter.getEdgeAttrId(edgeAttrRequestId);
    const timestampId = rewriter.getEdgeAttrId(edgeAttrTimestamp);
    // If the engine build lacks any of these keys, skip synthesis entirely
    // rather than emit malformed edges.
    if (!edgeTypeId || !keyId || !valueId || !cookieSourceId) {
      return "";
    }

    const dataElm = (keyAttrId: string, value: string): string =>
      `<data key="${keyAttrId}">${xmlEscape(value)}</data>`;

    let out = "";
    for (const [requestId, cookies] of Object.entries(
      this.#responseSetCookies,
    )) {
      if (cookies === undefined) {
        continue;
      }
      const resourceNodeId = requestResourceNodeId[requestId];
      if (resourceNodeId === undefined) {
        // No resource node was found for this request, so there is nothing in
        // the graph to attach the cookie to.
        continue;
      }
      const timestamp = requestTimestamp[requestId];
      for (const cookie of cookies) {
        const edgeId = "e" + String(nextEdgeId());
        out +=
          `<edge id="${edgeId}" source="${xmlEscapeAttr(resourceNodeId)}"` +
          ` target="${xmlEscapeAttr(cookieJarNodeId)}">`;
        out += dataElm(edgeTypeId, edgeTypeStorageSet);
        out += dataElm(keyId, cookie.key);
        out += dataElm(valueId, cookie.value);
        out += dataElm(cookieSourceId, cookieSourceSetCookieHeader);
        if (requestIdId) {
          out += dataElm(requestIdId, requestId);
        }
        if (timestampId && timestamp) {
          out += dataElm(timestampId, timestamp);
        }
        out += "</edge>";
      }
    }
    return out;
  }
}

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function xmlEscapeAttr(value: string): string {
  return xmlEscape(value).replace(/"/g, "&quot;");
}

// A Transform that injects text produced by `getInjection()` immediately before
// the closing `</graph>` tag. Keeps a small carry buffer so the marker is still
// found when it straddles a chunk boundary; streams everything else untouched.
function makeGraphCloseInjector(getInjection: () => string): Transform {
  const marker = "</graph>";
  let carry = "";
  let injected = false;

  return new Transform({
    decodeStrings: false,
    transform(chunk: Buffer | string, _encoding, callback) {
      let data = carry + chunk.toString();
      if (!injected) {
        const idx = data.indexOf(marker);
        if (idx !== -1) {
          data = data.slice(0, idx) + getInjection() + data.slice(idx);
          injected = true;
          carry = "";
          callback(null, data);
          return;
        }
        // Hold back the last (marker.length - 1) chars in case the marker is
        // split across this and the next chunk.
        const keep = marker.length - 1;
        if (data.length > keep) {
          carry = data.slice(data.length - keep);
          callback(null, data.slice(0, data.length - keep));
        } else {
          carry = data;
          callback();
        }
        return;
      }
      callback(null, data);
    },
    flush(callback) {
      callback(null, carry);
    },
  });
}
