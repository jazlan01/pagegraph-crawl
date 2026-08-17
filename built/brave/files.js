import { createReadStream, createWriteStream, existsSync } from "node:fs";
import { mkdtemp, open, readdir, rm, stat, unlink, writeFile, } from "node:fs/promises";
import { unlink as unlinkCb } from "node:fs";
import { tmpdir } from "node:os";
import { join, parse, resolve } from "node:path";
import { pipeline } from "node:stream";
import { createGzip, gzipSync } from "node:zlib";
import { isDir } from "./checks.js";
const dateTimeStamp = Math.floor(Date.now() / 1000);
const createFilename = (url) => {
    const fileSafeUrl = String(url).replace(/[^\w]/g, "_");
    return ["page_graph_", fileSafeUrl, "_", dateTimeStamp].join("");
};
const createOutputPath = (args, url) => {
    if (isDir(args.outputPath)) {
        return join(args.outputPath, createFilename(url));
    }
    else {
        const pathParts = parse(args.outputPath);
        return pathParts.dir + "/" + pathParts.name;
    }
};
export const createScreenshotPath = (args, url) => {
    const outputPath = join(createOutputPath(args, url) + ".png");
    return outputPath;
};
const createHeadersLogPath = (args, url) => {
    const extension = args.compress ? ".headers.json.gz" : ".headers.json";
    const outputPath = join(createOutputPath(args, url) + extension);
    return outputPath;
};
export const writeHeadersLog = async (args, url, headersJSON, logger) => {
    try {
        const outputFilename = createHeadersLogPath(args, url);
        logger.info("Writing headers log to: ", outputFilename);
        const data = args.compress ? gzipSync(headersJSON) : headersJSON;
        await writeFile(outputFilename, data);
    }
    catch (err) {
        logger.error("writing headers log output: ", String(err));
    }
};
const createGraphMLPath = (args, url) => {
    const outputPath = join(createOutputPath(args, url) + ".graphml");
    return outputPath;
};
export const writeGraphML = async (args, url, response, headersLogger, logger) => {
    try {
        const finalOutputFilename = createGraphMLPath(args, url);
        const data = response.data;
        // The rebuilt PageGraph streams the graphml to a file on disk (to avoid the
        // ~2GB single-blink::String limit) and returns that file's path in `data`.
        // Older builds return the XML inline. Detect which we got: a path is short,
        // single-line, and names an existing file; inline XML is large/multiline.
        const looksLikePath = data.length > 0 &&
            data.length < 4096 &&
            !data.includes("\n") &&
            existsSync(data);
        // The pre-stitch source that rewriteGraphML reads from, then deletes: either
        // the renderer's streamed file, or a .tmp we materialize from inline XML.
        let intermediateFilename;
        if (looksLikePath) {
            intermediateFilename = data;
            logger.info("PageGraph streamed graphml to: ", intermediateFilename);
        }
        else {
            intermediateFilename = finalOutputFilename + ".tmp";
            logger.info("Writing PageGraph file to: ", intermediateFilename);
            await writeFile(intermediateFilename, data);
        }
        logger.info("... and stitching request headers to: ", finalOutputFilename);
        await headersLogger.rewriteGraphML(intermediateFilename, finalOutputFilename);
        logger.verbose("... finished writing to: ", finalOutputFilename);
        await unlink(intermediateFilename);
        logger.verbose("... and deleting: ", intermediateFilename);
        if (args.compress) {
            return await compressAtPath(finalOutputFilename);
        }
        return finalOutputFilename;
    }
    catch (err) {
        logger.error("saving Page.generatePageGraph output: ", String(err));
        return null;
    }
};
// The k-th recovered graph for a crawl: the primary (largest) recovery keeps
// the historical `.partial.graphml` name; any further recovered graphs get
// `.partial.2.graphml`, `.partial.3.graphml`, ... so no recovery source is
// ever silently discarded.
const createPartialGraphMLPath = (args, url, index = 1) => {
    const suffix = index <= 1 ? ".partial.graphml" : `.partial.${String(index)}.graphml`;
    return join(createOutputPath(args, url) + suffix);
};
// Closing tags searched for when repairing a truncated streamed graphml.
const CLOSE_GRAPHML = Buffer.from("</graphml>");
const CLOSE_EDGE = Buffer.from("</edge>");
const CLOSE_NODE = Buffer.from("</node>");
const GRAPHML_FOOTER = Buffer.from("\n</graph>\n</graphml>\n");
// The renderer's two on-disk recovery sources, both written to
// PAGEGRAPH_OUT_DIR (= resolve(outputPath)):
// - streamed graphs `pagegraph_<frameId>_<ts>.graphml` (serialization-time
//   crash: ToGraphML died mid-write, the file is a valid prefix), and
// - Tier C event logs `pagegraph_eventlog_<frameId>_<ts>.graphml.partial`
//   (recording-time crash: the renderer died before ToGraphML ever ran, so no
//   streamed file exists; with --recording-event-log every item was appended
//   here as it was recorded).
// The `.graphml.partial` suffix keeps a streamed-graph scan from ever
// confusing an event log with a completed streamed graph.
const isEventLogName = (name) => name.startsWith("pagegraph_eventlog_") && name.endsWith(".graphml.partial");
const isStreamedGraphName = (name) => name.startsWith("pagegraph_") &&
    name.endsWith(".graphml") &&
    !isEventLogName(name);
export const snapshotRendererOutputs = async (outDir, logger) => {
    const preexistingNames = new Set();
    try {
        const entries = await readdir(outDir, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.isFile() &&
                (isStreamedGraphName(entry.name) || isEventLogName(entry.name))) {
                preexistingNames.add(entry.name);
            }
        }
    }
    catch (err) {
        logger.error("snapshotting renderer outputs: ", String(err));
    }
    return { startMs: Date.now(), preexistingNames };
};
const sleepMs = async (millis) => {
    await new Promise((resolve) => setTimeout(resolve, millis));
};
// True once the file's size and mtime have held still for one poll interval.
// A file a live renderer is still appending to must NEVER be recovered:
// repair truncates + footers it in place and recovery then deletes it, which
// on one redirect-chain crawl destroyed the next hop's still-being-written
// event log. A crashed renderer's file is static, so quiescence cleanly
// separates the two. Returns false (skip) if the file never settles or
// vanishes mid-check.
const isQuiescent = async (path, logger, attempts = 6, intervalMs = 500) => {
    try {
        let prev = await stat(path);
        for (let i = 0; i < attempts; i++) {
            await sleepMs(intervalMs);
            const cur = await stat(path);
            if (cur.size === prev.size && cur.mtimeMs === prev.mtimeMs) {
                return true;
            }
            logger.info("file still growing (live renderer?), waiting: ", path);
            prev = cur;
        }
        return false;
    }
    catch (err) {
        logger.error("checking file quiescence: ", String(err), " ", path);
        return false;
    }
};
// All recoverable files of one kind, largest first (the biggest candidate is
// almost always the main frame's graph; on the nytimes crash, newest-mtime
// selection kept a 1 MB log and discarded five others totalling ~8 MB).
// Excludes anything that predates the crawl's navigation and anything still
// being written.
const findRecoveryCandidates = async (outDir, matches, snapshot, logger) => {
    const candidates = [];
    try {
        const entries = await readdir(outDir, { withFileTypes: true });
        for (const entry of entries) {
            if (!entry.isFile() || !matches(entry.name)) {
                continue;
            }
            if (snapshot.preexistingNames.has(entry.name)) {
                logger.info("skipping recovery candidate that predates this crawl: ", entry.name);
                continue;
            }
            const path = join(outDir, entry.name);
            const info = await stat(path);
            // Belt and braces alongside the name snapshot: a file last written
            // before our navigation began cannot hold our page's graph.
            if (info.mtimeMs < snapshot.startMs) {
                logger.info("skipping recovery candidate older than this crawl: ", entry.name);
                continue;
            }
            if (!(await isQuiescent(path, logger))) {
                logger.error("skipping recovery candidate still being written (live renderer): ", path);
                continue;
            }
            candidates.push({ path, size: info.size });
        }
    }
    catch (err) {
        logger.error("scanning for recovery candidates: ", String(err));
    }
    candidates.sort((a, b) => b.size - a.size);
    return candidates.map((c) => c.path);
};
// Delete leftover Tier C event logs in outDir. Called after a healthy crawl:
// generatePageGraph succeeded, so the event log is redundant and would only
// pollute a later crawl's recovery scan. A log that is still growing belongs
// to a live renderer (possibly a concurrent crawl sharing this output dir),
// so it is left alone. Best-effort; failures are logged, not fatal.
export const cleanupEventLogs = async (outDir, logger) => {
    try {
        const entries = await readdir(outDir, { withFileTypes: true });
        for (const entry of entries) {
            if (!entry.isFile() || !isEventLogName(entry.name)) {
                continue;
            }
            const path = join(outDir, entry.name);
            if (!(await isQuiescent(path, logger, 2))) {
                logger.info("leaving still-growing event log alone: ", entry.name);
                continue;
            }
            await unlink(path);
            logger.verbose("deleted redundant event log: ", entry.name);
        }
    }
    catch (err) {
        logger.error("cleaning up event logs: ", String(err));
    }
};
// Repair a truncated streamed graphml in place so it parses. The file is a
// valid prefix (all <node>s, then all <edge>s), so we drop any incomplete
// trailing element and append the closing tags. Scans backward from EOF in
// chunks — never reads the whole (multi-GB) file into memory. Returns true if
// the file is now well-formed (already-complete files are left untouched).
export const repairPartialGraphML = async (path, logger) => {
    const handle = await open(path, "r+");
    try {
        const { size } = await handle.stat();
        if (size === 0) {
            logger.error("partial graphml is empty: ", path);
            return false;
        }
        const CHUNK = 1 << 20; // 1 MiB windows, scanning backward
        const OVERLAP = CLOSE_GRAPHML.length; // re-read to catch boundary-split tags
        let searchEnd = size;
        let cutOffset = -1;
        while (searchEnd > 0) {
            const readLen = Math.min(CHUNK, searchEnd);
            const start = searchEnd - readLen;
            const buf = Buffer.alloc(readLen);
            await handle.read(buf, 0, readLen, start);
            if (buf.includes(CLOSE_GRAPHML)) {
                logger.info("partial graphml already well-formed: ", path);
                return true;
            }
            // Edges are serialized after nodes, so a later </edge> wins over </node>.
            const idxEdge = buf.lastIndexOf(CLOSE_EDGE);
            const idxNode = buf.lastIndexOf(CLOSE_NODE);
            if (idxEdge >= 0) {
                cutOffset = start + idxEdge + CLOSE_EDGE.length;
                break;
            }
            if (idxNode >= 0) {
                cutOffset = start + idxNode + CLOSE_NODE.length;
                break;
            }
            if (start === 0) {
                break;
            }
            searchEnd = start + OVERLAP;
        }
        if (cutOffset < 0) {
            logger.error("no complete <node>/<edge> in partial graphml (nothing to recover): ", path);
            return false;
        }
        await handle.truncate(cutOffset);
        await handle.write(GRAPHML_FOOTER, 0, GRAPHML_FOOTER.length, cutOffset);
        return true;
    }
    catch (err) {
        logger.error("repairing partial graphml: ", String(err));
        return false;
    }
    finally {
        await handle.close();
    }
};
// Recovery entry point: locate every renderer output belonging to *this*
// crawl (filtered by the pre-navigation snapshot, and skipping any file a
// live renderer is still appending to), repair each truncated tail, stitch
// request headers as usual, and emit them as clearly labelled
// `.partial[.k].graphml` files — largest first, so `.partial.graphml` is the
// best candidate for the main frame. Recovering only the newest single file
// used to discard the majority of the salvageable data (nytimes: kept ~1 MB,
// dropped ~8 MB across five sibling logs). Returns null if nothing could be
// recovered. Called only when generatePageGraph fails / writeGraphML yields
// no file — never on the healthy path.
export const recoverPartialGraphML = async (args, url, headersLogger, logger, snapshot) => {
    const outDir = resolve(args.outputPath);
    // Prefer streamed graphs (a serialization-time crash leaves a partial
    // `.graphml`). If there are none, fall back to the Tier C event logs: a
    // recording-time crash aborts before ToGraphML runs, so no streamed file is
    // ever created and the event logs are the only thing on disk.
    let sources = await findRecoveryCandidates(outDir, isStreamedGraphName, snapshot, logger);
    let kind = "streamed graph";
    if (sources.length === 0) {
        sources = await findRecoveryCandidates(outDir, isEventLogName, snapshot, logger);
        kind = "record-time event log";
    }
    if (sources.length === 0) {
        logger.error("no orphaned graphml or event log from this crawl to recover in: ", outDir);
        return null;
    }
    const recovered = [];
    for (const source of sources) {
        logger.error(`RECOVERING partial graphml from ${kind} (renderer likely crashed): `, source);
        if (!(await repairPartialGraphML(source, logger))) {
            continue;
        }
        try {
            const finalOutputFilename = createPartialGraphMLPath(args, url, recovered.length + 1);
            await headersLogger.rewriteGraphML(source, finalOutputFilename);
            await unlink(source);
            logger.error("RECOVERED partial graph written to: ", finalOutputFilename);
            recovered.push(args.compress
                ? await compressAtPath(finalOutputFilename)
                : finalOutputFilename);
        }
        catch (err) {
            logger.error("stitching recovered graphml: ", String(err));
        }
    }
    if (recovered.length === 0) {
        return null;
    }
    logger.error(`RECOVERY complete: ${String(recovered.length)} of ` +
        `${String(sources.length)} candidate ${kind}(s) recovered.`);
    return { primary: recovered[0], all: recovered, sourceKind: kind };
};
const createHARPath = (args, url) => {
    const outputPath = join(createOutputPath(args, url) + ".har");
    return outputPath;
};
export const writeHAR = async (args, url, har, logger) => {
    try {
        const outputFilename = createHARPath(args, url);
        logger.info("Writing HAR file to: ", outputFilename);
        await writeFile(outputFilename, JSON.stringify(har, null, 4));
    }
    catch (err) {
        logger.error("saving HAR file: ", String(err));
    }
};
const createStacksPath = (args, url) => {
    // Pass-2 probe captures are a different artefact from a pass-1 stack dump:
    // no graph accompanies them and they carry the separate-page-load caveat.
    // Name them apart so the two are never joined by mistake.
    const base = args.probe ? ".probe.json" : ".stacks.json";
    const extension = args.compress ? `${base}.gz` : base;
    const outputPath = join(createOutputPath(args, url) + extension);
    return outputPath;
};
export const writeStacks = async (args, url, stacksJSON, logger) => {
    try {
        const outputFilename = createStacksPath(args, url);
        logger.info("Writing debug stacks to: ", outputFilename);
        const data = args.compress ? gzipSync(stacksJSON) : stacksJSON;
        await writeFile(outputFilename, data);
    }
    catch (err) {
        logger.error("saving debug stacks file: ", String(err));
    }
};
const createCookiesPath = (args, url) => {
    const extension = args.compress ? ".cookies.json.gz" : ".cookies.json";
    return join(createOutputPath(args, url) + extension);
};
export const writeCookies = async (args, url, cookiesJSON, logger) => {
    try {
        const outputFilename = createCookiesPath(args, url);
        logger.info("Writing cookie inventory to: ", outputFilename);
        const data = args.compress ? gzipSync(cookiesJSON) : cookiesJSON;
        await writeFile(outputFilename, data);
    }
    catch (err) {
        logger.error("saving cookie inventory file: ", String(err));
    }
};
const createCookieNetworkPath = (args, url) => {
    const extension = args.compress
        ? ".cookie-network.json.gz"
        : ".cookie-network.json";
    return join(createOutputPath(args, url) + extension);
};
export const writeCookieNetwork = async (args, url, cookieNetworkJSON, logger) => {
    try {
        const outputFilename = createCookieNetworkPath(args, url);
        logger.info("Writing cookie-network map to: ", outputFilename);
        const data = args.compress
            ? gzipSync(cookieNetworkJSON)
            : cookieNetworkJSON;
        await writeFile(outputFilename, data);
    }
    catch (err) {
        logger.error("saving cookie-network map file: ", String(err));
    }
};
const createRedirectsPath = (args, url) => {
    const extension = args.compress ? ".redirects.json.gz" : ".redirects.json";
    return join(createOutputPath(args, url) + extension);
};
export const writeRedirects = async (args, url, redirectsJSON, logger) => {
    try {
        const outputFilename = createRedirectsPath(args, url);
        logger.info("Writing redirect chains to: ", outputFilename);
        const data = args.compress ? gzipSync(redirectsJSON) : redirectsJSON;
        await writeFile(outputFilename, data);
    }
    catch (err) {
        logger.error("saving redirect chains file: ", String(err));
    }
};
// Deliberately never compressed: it is tiny, and it is the file a human or
// script checks first to decide whether the rest can be trusted.
const createCrawlStatusPath = (args, url) => {
    return join(createOutputPath(args, url) + ".crawl-status.json");
};
export const writeCrawlStatus = async (args, url, status, logger) => {
    try {
        const outputFilename = createCrawlStatusPath(args, url);
        logger.info("Writing crawl status to: ", outputFilename);
        await writeFile(outputFilename, JSON.stringify(status, null, 2));
    }
    catch (err) {
        logger.error("saving crawl status file: ", String(err));
    }
};
// The body sidecar is written incrementally by `BodyLog` as the crawl runs, so
// unlike the other sidecars there is no one-shot writer here — only the path.
// Compression happens after the log is closed, via `compressAtPath`.
export const createBodiesPath = (args, url) => {
    return join(createOutputPath(args, url) + ".bodies.ndjson");
};
export const deleteAtPath = async (path) => {
    await rm(path, {
        recursive: true,
        force: true,
    });
};
export const createTempDir = async (dirPrefix = "pagegraph-crawl-") => {
    return await mkdtemp(join(tmpdir(), dirPrefix));
};
export const compressAtPath = async (fromPath) => {
    const toPath = fromPath + ".gz";
    // Taken from the node documentation
    // https://nodejs.org/docs/latest-v20.x/api/zlib.html#for-zlib-based-streams
    const gzipTransformer = createGzip();
    const sourceStream = createReadStream(fromPath);
    const destinationStream = createWriteStream(toPath);
    return new Promise((resolve, reject) => {
        pipeline(sourceStream, gzipTransformer, destinationStream, (err) => {
            if (err) {
                reject(err);
                return;
            }
            unlinkCb(fromPath, () => {
                resolve(toPath);
            });
        });
    });
};
