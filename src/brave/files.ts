import { createReadStream, createWriteStream, existsSync } from "node:fs";
import {
  mkdtemp,
  open,
  readdir,
  rm,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { unlink as unlinkCb } from "node:fs";
import { tmpdir } from "node:os";
import { join, parse, resolve } from "node:path";
import { pipeline } from "node:stream";
import { createGzip, gzipSync } from "node:zlib";

import { isDir } from "./checks.js";
import { RequestMetadataTracker } from "./request_metadata_tracker.js";

const dateTimeStamp = Math.floor(Date.now() / 1000);

const createFilename = (url: URL): FilePath => {
  const fileSafeUrl = String(url).replace(/[^\w]/g, "_");
  return ["page_graph_", fileSafeUrl, "_", dateTimeStamp].join("");
};

const createOutputPath = (args: CrawlArgs, url: URL): FilePath => {
  if (isDir(args.outputPath)) {
    return join(args.outputPath, createFilename(url));
  } else {
    const pathParts = parse(args.outputPath);
    return pathParts.dir + "/" + pathParts.name;
  }
};

export const createScreenshotPath = (args: CrawlArgs, url: URL): FilePath => {
  const outputPath = join(createOutputPath(args, url) + ".png");
  return outputPath;
};

const createHeadersLogPath = (args: CrawlArgs, url: URL): FilePath => {
  const extension = args.compress ? ".headers.json.gz" : ".headers.json";
  const outputPath = join(createOutputPath(args, url) + extension);
  return outputPath;
};

export const writeHeadersLog = async (
  args: CrawlArgs,
  url: URL,
  headersJSON: string,
  logger: Logger,
): Promise<undefined> => {
  try {
    const outputFilename = createHeadersLogPath(args, url);
    logger.info("Writing headers log to: ", outputFilename);
    const data = args.compress ? gzipSync(headersJSON) : headersJSON;
    await writeFile(outputFilename, data);
  } catch (err) {
    logger.error("writing headers log output: ", String(err));
  }
};

const createGraphMLPath = (args: CrawlArgs, url: URL): FilePath => {
  const outputPath: string = join(createOutputPath(args, url) + ".graphml");
  return outputPath;
};

export const writeGraphML = async (
  args: CrawlArgs,
  url: URL,
  response: FinalPageGraphEvent,
  headersLogger: RequestMetadataTracker,
  logger: Logger,
): Promise<FilePath | null> => {
  try {
    const finalOutputFilename = createGraphMLPath(args, url);
    const data = response.data;

    // The rebuilt PageGraph streams the graphml to a file on disk (to avoid the
    // ~2GB single-blink::String limit) and returns that file's path in `data`.
    // Older builds return the XML inline. Detect which we got: a path is short,
    // single-line, and names an existing file; inline XML is large/multiline.
    const looksLikePath =
      data.length > 0 &&
      data.length < 4096 &&
      !data.includes("\n") &&
      existsSync(data);

    // The pre-stitch source that rewriteGraphML reads from, then deletes: either
    // the renderer's streamed file, or a .tmp we materialize from inline XML.
    let intermediateFilename: FilePath;
    if (looksLikePath) {
      intermediateFilename = data;
      logger.info("PageGraph streamed graphml to: ", intermediateFilename);
    } else {
      intermediateFilename = finalOutputFilename + ".tmp";
      logger.info("Writing PageGraph file to: ", intermediateFilename);
      await writeFile(intermediateFilename, data);
    }

    logger.info("... and stitching request headers to: ", finalOutputFilename);
    await headersLogger.rewriteGraphML(
      intermediateFilename,
      finalOutputFilename,
    );
    logger.verbose("... finished writing to: ", finalOutputFilename);
    await unlink(intermediateFilename);
    logger.verbose("... and deleting: ", intermediateFilename);
    if (args.compress) {
      return await compressAtPath(finalOutputFilename);
    }
    return finalOutputFilename;
  } catch (err) {
    logger.error("saving Page.generatePageGraph output: ", String(err));
    return null;
  }
};

const createPartialGraphMLPath = (args: CrawlArgs, url: URL): FilePath => {
  return join(createOutputPath(args, url) + ".partial.graphml");
};

// Closing tags searched for when repairing a truncated streamed graphml.
const CLOSE_GRAPHML = Buffer.from("</graphml>");
const CLOSE_EDGE = Buffer.from("</edge>");
const CLOSE_NODE = Buffer.from("</node>");
const GRAPHML_FOOTER = Buffer.from("\n</graph>\n</graphml>\n");

// The renderer streams the graphml to PAGEGRAPH_OUT_DIR (= resolve(outputPath))
// as `pagegraph_<frameId>_<ts>.graphml`, and generatePageGraph returns that
// path. If the renderer aborts, the CDP call rejects and we never get the path
// back, but the (truncated) file is still on disk. Find the newest such orphan.
export const findOrphanGraphML = async (
  outDir: FilePath,
  logger: Logger,
): Promise<FilePath | null> => {
  try {
    const entries = await readdir(outDir, { withFileTypes: true });
    let newest: { path: FilePath; mtimeMs: number } | null = null;
    for (const entry of entries) {
      if (
        !entry.isFile() ||
        !entry.name.startsWith("pagegraph_") ||
        !entry.name.endsWith(".graphml")
      ) {
        continue;
      }
      const path = join(outDir, entry.name);
      const info = await stat(path);
      if (newest === null || info.mtimeMs > newest.mtimeMs) {
        newest = { path, mtimeMs: info.mtimeMs };
      }
    }
    return newest === null ? null : newest.path;
  } catch (err) {
    logger.error("scanning for orphaned graphml: ", String(err));
    return null;
  }
};

// Tier C recovery source. With --recording-event-log the renderer appends every
// item to `pagegraph_eventlog_<frameId>_<ts>.graphml.partial` as it records, so
// a *recording-time* crash (before generatePageGraph/ToGraphML ever runs, i.e.
// no streamed `.graphml` exists) still leaves a tail-repairable prefix. The
// `.graphml.partial` suffix keeps findOrphanGraphML (which matches `.graphml`)
// from ever confusing it with a completed streamed graph. Returns the newest.
export const findEventLog = async (
  outDir: FilePath,
  logger: Logger,
): Promise<FilePath | null> => {
  try {
    const entries = await readdir(outDir, { withFileTypes: true });
    let newest: { path: FilePath; mtimeMs: number } | null = null;
    for (const entry of entries) {
      if (
        !entry.isFile() ||
        !entry.name.startsWith("pagegraph_eventlog_") ||
        !entry.name.endsWith(".graphml.partial")
      ) {
        continue;
      }
      const path = join(outDir, entry.name);
      const info = await stat(path);
      if (newest === null || info.mtimeMs > newest.mtimeMs) {
        newest = { path, mtimeMs: info.mtimeMs };
      }
    }
    return newest === null ? null : newest.path;
  } catch (err) {
    logger.error("scanning for event log: ", String(err));
    return null;
  }
};

// Delete leftover Tier C event logs in outDir. Called after a healthy crawl:
// generatePageGraph succeeded, so the event log is redundant and would only
// confuse a later findEventLog. Best-effort; failures are logged, not fatal.
export const cleanupEventLogs = async (
  outDir: FilePath,
  logger: Logger,
): Promise<void> => {
  try {
    const entries = await readdir(outDir, { withFileTypes: true });
    for (const entry of entries) {
      if (
        entry.isFile() &&
        entry.name.startsWith("pagegraph_eventlog_") &&
        entry.name.endsWith(".graphml.partial")
      ) {
        await unlink(join(outDir, entry.name));
        logger.verbose("deleted redundant event log: ", entry.name);
      }
    }
  } catch (err) {
    logger.error("cleaning up event logs: ", String(err));
  }
};

// Repair a truncated streamed graphml in place so it parses. The file is a
// valid prefix (all <node>s, then all <edge>s), so we drop any incomplete
// trailing element and append the closing tags. Scans backward from EOF in
// chunks — never reads the whole (multi-GB) file into memory. Returns true if
// the file is now well-formed (already-complete files are left untouched).
export const repairPartialGraphML = async (
  path: FilePath,
  logger: Logger,
): Promise<boolean> => {
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
      logger.error(
        "no complete <node>/<edge> in partial graphml (nothing to recover): ",
        path,
      );
      return false;
    }
    await handle.truncate(cutOffset);
    await handle.write(GRAPHML_FOOTER, 0, GRAPHML_FOOTER.length, cutOffset);
    return true;
  } catch (err) {
    logger.error("repairing partial graphml: ", String(err));
    return false;
  } finally {
    await handle.close();
  }
};

// Recovery entry point: locate the renderer's orphaned streamed graphml, repair
// the truncated tail, stitch request headers as usual, and emit it as a clearly
// labelled `.partial.graphml`. Returns the final path, or null if nothing could
// be recovered. Called only when generatePageGraph fails / writeGraphML yields
// no file — never on the healthy path.
export const recoverPartialGraphML = async (
  args: CrawlArgs,
  url: URL,
  headersLogger: RequestMetadataTracker,
  logger: Logger,
): Promise<FilePath | null> => {
  const outDir = resolve(args.outputPath);
  // Prefer the streamed graph (a serialization-time crash leaves a partial
  // `.graphml`). If there is none, fall back to the Tier C event log: a
  // recording-time crash aborts before ToGraphML runs, so no streamed file is
  // ever created and the event log is the only thing on disk.
  let source = await findOrphanGraphML(outDir, logger);
  let kind = "streamed graph";
  if (source === null) {
    source = await findEventLog(outDir, logger);
    kind = "record-time event log";
  }
  if (source === null) {
    logger.error("no orphaned graphml or event log to recover in: ", outDir);
    return null;
  }
  logger.error(
    `RECOVERING partial graphml from ${kind} (renderer likely crashed): `,
    source,
  );
  const repaired = await repairPartialGraphML(source, logger);
  if (!repaired) {
    return null;
  }
  try {
    const finalOutputFilename = createPartialGraphMLPath(args, url);
    await headersLogger.rewriteGraphML(source, finalOutputFilename);
    await unlink(source);
    logger.error("RECOVERED partial graph written to: ", finalOutputFilename);
    if (args.compress) {
      return await compressAtPath(finalOutputFilename);
    }
    return finalOutputFilename;
  } catch (err) {
    logger.error("stitching recovered graphml: ", String(err));
    return null;
  }
};

const createHARPath = (args: CrawlArgs, url: URL): FilePath => {
  const outputPath = join(createOutputPath(args, url) + ".har");
  return outputPath;
};

export const writeHAR = async (
  args: CrawlArgs,
  url: URL,
  har: any,
  logger: Logger,
): Promise<undefined> => {
  try {
    const outputFilename = createHARPath(args, url);
    logger.info("Writing HAR file to: ", outputFilename);
    await writeFile(outputFilename, JSON.stringify(har, null, 4));
  } catch (err) {
    logger.error("saving HAR file: ", String(err));
  }
};

const createStacksPath = (args: CrawlArgs, url: URL): FilePath => {
  const extension = args.compress ? ".stacks.json.gz" : ".stacks.json";
  const outputPath = join(createOutputPath(args, url) + extension);
  return outputPath;
};

export const writeStacks = async (
  args: CrawlArgs,
  url: URL,
  stacksJSON: string,
  logger: Logger,
): Promise<undefined> => {
  try {
    const outputFilename = createStacksPath(args, url);
    logger.info("Writing debug stacks to: ", outputFilename);
    const data = args.compress ? gzipSync(stacksJSON) : stacksJSON;
    await writeFile(outputFilename, data);
  } catch (err) {
    logger.error("saving debug stacks file: ", String(err));
  }
};

const createCookiesPath = (args: CrawlArgs, url: URL): FilePath => {
  const extension = args.compress ? ".cookies.json.gz" : ".cookies.json";
  return join(createOutputPath(args, url) + extension);
};

export const writeCookies = async (
  args: CrawlArgs,
  url: URL,
  cookiesJSON: string,
  logger: Logger,
): Promise<undefined> => {
  try {
    const outputFilename = createCookiesPath(args, url);
    logger.info("Writing cookie inventory to: ", outputFilename);
    const data = args.compress ? gzipSync(cookiesJSON) : cookiesJSON;
    await writeFile(outputFilename, data);
  } catch (err) {
    logger.error("saving cookie inventory file: ", String(err));
  }
};

const createCookieNetworkPath = (args: CrawlArgs, url: URL): FilePath => {
  const extension = args.compress
    ? ".cookie-network.json.gz"
    : ".cookie-network.json";
  return join(createOutputPath(args, url) + extension);
};

export const writeCookieNetwork = async (
  args: CrawlArgs,
  url: URL,
  cookieNetworkJSON: string,
  logger: Logger,
): Promise<undefined> => {
  try {
    const outputFilename = createCookieNetworkPath(args, url);
    logger.info("Writing cookie-network map to: ", outputFilename);
    const data = args.compress
      ? gzipSync(cookieNetworkJSON)
      : cookieNetworkJSON;
    await writeFile(outputFilename, data);
  } catch (err) {
    logger.error("saving cookie-network map file: ", String(err));
  }
};

const createRedirectsPath = (args: CrawlArgs, url: URL): FilePath => {
  const extension = args.compress ? ".redirects.json.gz" : ".redirects.json";
  return join(createOutputPath(args, url) + extension);
};

export const writeRedirects = async (
  args: CrawlArgs,
  url: URL,
  redirectsJSON: string,
  logger: Logger,
): Promise<undefined> => {
  try {
    const outputFilename = createRedirectsPath(args, url);
    logger.info("Writing redirect chains to: ", outputFilename);
    const data = args.compress ? gzipSync(redirectsJSON) : redirectsJSON;
    await writeFile(outputFilename, data);
  } catch (err) {
    logger.error("saving redirect chains file: ", String(err));
  }
};

// The body sidecar is written incrementally by `BodyLog` as the crawl runs, so
// unlike the other sidecars there is no one-shot writer here — only the path.
// Compression happens after the log is closed, via `compressAtPath`.
export const createBodiesPath = (args: CrawlArgs, url: URL): FilePath => {
  return join(createOutputPath(args, url) + ".bodies.ndjson");
};

export const deleteAtPath = async (path: FilePath): Promise<undefined> => {
  await rm(path, {
    recursive: true,
    force: true,
  });
};

export const createTempDir = async (
  dirPrefix = "pagegraph-crawl-",
): Promise<FilePath> => {
  return await mkdtemp(join(tmpdir(), dirPrefix));
};

export const compressAtPath = async (fromPath: FilePath): Promise<FilePath> => {
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
