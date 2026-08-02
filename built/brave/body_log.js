import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
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
const textualMimePattern = /^(?:text\/|application\/(?:json|javascript|x-javascript|ecmascript|xml|xhtml\+xml|x-www-form-urlencoded|graphql)|[^;]*\+(?:json|xml))/i;
const isTextualMimeType = (mimeType) => {
    if (mimeType === undefined || mimeType === "") {
        // An absent Content-Type is more likely a small API response than a video,
        // so capture it rather than silently dropping it.
        return true;
    }
    return textualMimePattern.test(mimeType.trim());
};
export class BodyLog {
    #stream;
    #options;
    #logger;
    #bytesStored = 0;
    #stats = {
        records: 0,
        bodiesStored: 0,
        bytesStored: 0,
        truncated: 0,
        dropped: { mime: 0, budget: 0, error: 0, empty: 0 },
    };
    #closed = false;
    constructor(options, logger) {
        this.#options = options;
        this.#logger = logger;
        this.#stream = createWriteStream(options.path, { encoding: "utf8" });
        // A sidecar write failure must never take down the crawl; the graph is the
        // primary output.
        this.#stream.on("error", (err) => {
            this.#logger?.error("body log write failed: ", String(err));
            this.#closed = true;
        });
    }
    get path() {
        return this.#options.path;
    }
    getStats() {
        return { ...this.#stats, bytesStored: this.#bytesStored };
    }
    async appendRequest(input) {
        const record = {
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
    async appendResponse(input) {
        const record = {
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
        const bytes = Buffer.from(input.bytes.buffer, input.bytes.byteOffset, input.bytes.byteLength);
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
    #fill(record, bytes) {
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
        }
        catch {
            isUtf8 = false;
        }
        if (isUtf8) {
            record.encoding = "utf8";
            record.body = new TextDecoder("utf-8").decode(kept);
        }
        else {
            record.encoding = "base64";
            record.body = kept.toString("base64");
        }
        this.#bytesStored += kept.length;
        this.#stats.bodiesStored += 1;
    }
    async #write(record) {
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
            }
            catch {
                // Stream errored; the 'error' handler has already latched #closed.
            }
        }
    }
    async close() {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        await new Promise((resolve) => {
            this.#stream.end(() => {
                resolve();
            });
        });
    }
}
