import { createHash } from "node:crypto";
import { createWriteStream, type WriteStream } from "node:fs";
import { once } from "node:events";

// HTTP request and response bodies, streamed to an NDJSON sidecar as they are
// observed.
//
// PageGraph records only a request's *size*, never its content, so a value
// leaving the page in a POST body is invisible in the graph. The crawler already
// pulls every body over CDP to compute that size and then discards it; this
// class keeps the bytes instead.
//
// Why NDJSON rather than one JSON object written at the end: bodies are large
// and a crawl can make thousands of requests, so accumulating them in memory to
// stringify later is the one shape guaranteed to fail on a heavy page. Each line
// is also durable the moment it is written, so a renderer crash during graph
// generation leaves a valid (if truncated) prefix rather than nothing.
//
// Joining back to the graph: `requestId` is the *simplified* request id, the
// same value `RequestMetadataTracker` injects as the `request id` attribute on
// request edges, so a record joins directly to the edge that initiated it.

// Response MIME types worth capturing. Image/font/video/audio bytes cannot carry
// a cookie-value substring match and would otherwise dominate the sidecar.
const textualMimePattern =
  /^(?:text\/|application\/(?:json|javascript|x-javascript|ecmascript|xml|xhtml\+xml|x-www-form-urlencoded|graphql)|[^;]*\+(?:json|xml))/i;

const isTextualMimeType = (mimeType: string | undefined): boolean => {
  if (mimeType === undefined || mimeType === "") {
    // An absent Content-Type is more likely a small API response than a video,
    // so capture it rather than silently dropping it.
    return true;
  }
  return textualMimePattern.test(mimeType.trim());
};

// Why a body's content is absent from a record. Every observed request and
// response emits a record even when its body was not kept, so that "no body
// here" is always distinguishable from "this request was never seen".
type DropReason =
  // Response MIME type is outside the textual allowlist.
  | "mime"
  // The total body-bytes budget for this crawl was exhausted.
  | "budget"
  // CDP could not produce the body (redirect, no content, buffer evicted).
  | "error"
  // The body was empty.
  | "empty";

interface BodyRecord {
  kind: "request" | "response";
  requestId: number | string;
  rawRequestId: string;
  url: string;
  ts: number;
  method?: string;
  status?: number;
  mimeType?: string;
  resourceType?: string;
  // Byte length of the *full* body, before any truncation.
  size: number;
  // SHA-256 of the *full* body, so integrity and dedup joins survive both
  // truncation and dropping.
  sha256?: string;
  encoding?: "utf8" | "base64";
  truncated?: boolean;
  // Present when `truncated`: the byte length actually stored in `body`.
  storedSize?: number;
  dropped?: DropReason;
  // Set on request records when CDP reported post data exists but would not hand
  // it over — currently binary multipart uploads, which
  // `Network.getRequestPostData` cannot return.
  postDataUnavailable?: boolean;
  body?: string;
}

export interface BodyLogOptions {
  path: FilePath;
  // Per-body cap on stored bytes.
  bodyMax: number;
  // Cap on total stored body bytes for the whole crawl.
  budgetBytes: number;
  // Skip the response MIME allowlist and keep every response body.
  allMimeTypes: boolean;
}

export interface BodyLogStats {
  records: number;
  bodiesStored: number;
  bytesStored: number;
  truncated: number;
  dropped: Record<DropReason, number>;
}

export interface RequestBodyInput {
  requestId: number | string;
  rawRequestId: string;
  url: string;
  method: string;
  resourceType?: string;
  // The post data CDP gave us, if any.
  body: string | undefined;
  // CDP said a body exists. With `body` undefined this means CDP refused to
  // hand it over rather than that there was nothing to hand over.
  hasPostData: boolean;
}

export interface ResponseBodyInput {
  requestId: number | string;
  rawRequestId: string;
  url: string;
  status?: number;
  mimeType?: string;
  resourceType?: string;
  bytes: Uint8Array | undefined;
  // Body retrieval threw (redirect, no content, evicted buffer).
  failed: boolean;
}

export class BodyLog {
  readonly #stream: WriteStream;
  readonly #options: BodyLogOptions;
  readonly #logger: Logger | undefined;
  #bytesStored = 0;
  #stats: BodyLogStats = {
    records: 0,
    bodiesStored: 0,
    bytesStored: 0,
    truncated: 0,
    dropped: { mime: 0, budget: 0, error: 0, empty: 0 },
  };
  #closed = false;

  constructor(options: BodyLogOptions, logger?: Logger) {
    this.#options = options;
    this.#logger = logger;
    this.#stream = createWriteStream(options.path, { encoding: "utf8" });
    // A sidecar write failure must never take down the crawl; the graph is the
    // primary output.
    this.#stream.on("error", (err: Error) => {
      this.#logger?.error("body log write failed: ", String(err));
      this.#closed = true;
    });
  }

  get path(): FilePath {
    return this.#options.path;
  }

  getStats(): BodyLogStats {
    return { ...this.#stats, bytesStored: this.#bytesStored };
  }

  async appendRequest(input: RequestBodyInput): Promise<void> {
    const record: BodyRecord = {
      kind: "request",
      requestId: input.requestId,
      rawRequestId: input.rawRequestId,
      url: input.url,
      method: input.method,
      resourceType: input.resourceType,
      ts: Date.now(),
      size: 0,
    };
    if (input.body === undefined || input.body === "") {
      record.dropped = "empty";
      if (input.hasPostData) {
        // CDP reported a body but would not return it. Recording this keeps the
        // gap visible in the data instead of looking like a bodyless request.
        record.postDataUnavailable = true;
      }
      await this.#write(record);
      return;
    }
    // Request bodies are never MIME-filtered: they are the exfiltration channel
    // this sidecar exists to capture, and they are small.
    this.#fill(record, Buffer.from(input.body, "utf8"));
    await this.#write(record);
  }

  async appendResponse(input: ResponseBodyInput): Promise<void> {
    const record: BodyRecord = {
      kind: "response",
      requestId: input.requestId,
      rawRequestId: input.rawRequestId,
      url: input.url,
      status: input.status,
      mimeType: input.mimeType,
      resourceType: input.resourceType,
      ts: Date.now(),
      size: 0,
    };
    if (input.failed) {
      record.dropped = "error";
      await this.#write(record);
      return;
    }
    if (input.bytes === undefined || input.bytes.length === 0) {
      record.dropped = "empty";
      await this.#write(record);
      return;
    }

    const bytes = Buffer.from(
      input.bytes.buffer,
      input.bytes.byteOffset,
      input.bytes.byteLength,
    );
    // Hash and size are recorded even for dropped bodies, so a body can still be
    // identified and deduped without its content.
    record.size = bytes.length;
    record.sha256 = createHash("sha256").update(bytes).digest("hex");
    if (!this.#options.allMimeTypes && !isTextualMimeType(input.mimeType)) {
      record.dropped = "mime";
      await this.#write(record);
      return;
    }
    this.#fill(record, bytes);
    await this.#write(record);
  }

  // Populates size/hash/encoding/body on a record, applying the per-body cap and
  // the total budget. Safe to call after `size`/`sha256` are already set.
  #fill(record: BodyRecord, bytes: Buffer): void {
    record.size = bytes.length;
    record.sha256 ??= createHash("sha256").update(bytes).digest("hex");

    if (this.#bytesStored >= this.#options.budgetBytes) {
      record.dropped = "budget";
      return;
    }

    const remainingBudget = this.#options.budgetBytes - this.#bytesStored;
    const limit = Math.min(this.#options.bodyMax, remainingBudget);
    const kept = bytes.length > limit ? bytes.subarray(0, limit) : bytes;
    if (kept.length < bytes.length) {
      record.truncated = true;
      record.storedSize = kept.length;
      this.#stats.truncated += 1;
    }

    // Decide the encoding from the *full* body: a body that is valid UTF-8 stays
    // readable as text even if the truncated slice splits a codepoint (the
    // non-fatal decode below leaves a replacement char at the seam).
    let isUtf8 = true;
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      isUtf8 = false;
    }

    if (isUtf8) {
      record.encoding = "utf8";
      record.body = new TextDecoder("utf-8").decode(kept);
    } else {
      record.encoding = "base64";
      record.body = kept.toString("base64");
    }

    this.#bytesStored += kept.length;
    this.#stats.bodiesStored += 1;
  }

  async #write(record: BodyRecord): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#stats.records += 1;
    if (record.dropped !== undefined) {
      this.#stats.dropped[record.dropped] += 1;
    }
    const line = JSON.stringify(record) + "\n";
    // Respect backpressure so a slow disk cannot balloon the stream's internal
    // buffer into the memory problem NDJSON exists to avoid.
    if (!this.#stream.write(line)) {
      try {
        await once(this.#stream, "drain");
      } catch {
        // Stream errored; the 'error' handler has already latched #closed.
      }
    }
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    await new Promise<void>((resolve) => {
      this.#stream.end(() => {
        resolve();
      });
    });
  }
}
