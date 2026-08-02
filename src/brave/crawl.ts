import assert from "node:assert/strict";

import * as osLib from "os";
import { resolve } from "node:path";

import { harFromMessages } from "chrome-har";
import { Protocol } from "devtools-protocol";
import type { CDPSession, HTTPRequest, HTTPResponse } from "puppeteer-core";
import Xvbf from "xvfb";

import { BodyLog } from "./body_log.js";
import { isTopLevelPageNavigation, isTimeoutError } from "./checks.js";
import { asHTTPUrl } from "./checks.js";
import { DebugStackTracker } from "./debug_stack_tracker.js";
import {
  compressAtPath,
  createBodiesPath,
  createScreenshotPath,
  deleteAtPath,
} from "./files.js";
import {
  writeGraphML,
  recoverPartialGraphML,
  cleanupEventLogs,
} from "./files.js";
import { writeHAR, writeHeadersLog, writeStacks } from "./files.js";
import { writeCookies, writeCookieNetwork, writeRedirects } from "./files.js";
import { getLogger } from "./logging.js";
import { makeNavigationTracker } from "./navigation_tracker.js";
import { selectRandomChildUrl } from "./page.js";
import { puppeteerConfigForArgs, launchWithRetry } from "./puppeteer.js";
import { RequestMetadataTracker } from "./request_metadata_tracker.js";

interface ExtendedResponse extends Protocol.Network.Response {
  body?: string;
}

interface ExtendedResponseReceivedEvent
  extends Protocol.Network.ResponseReceivedEvent {
  response: ExtendedResponse;
}

interface Event<TMethod, TParams> {
  method: TMethod;
  params: TParams;
}

type NetworkEventParams =
  | Protocol.Network.RequestWillBeSentEvent
  | Protocol.Network.RequestServedFromCacheEvent
  | Protocol.Network.DataReceivedEvent
  | Protocol.Network.ResponseReceivedEvent
  | Protocol.Network.ResourceChangedPriorityEvent
  | Protocol.Network.LoadingFinishedEvent
  | Protocol.Network.LoadingFailedEvent;

type NetworkEvent = Event<string, NetworkEventParams>;

type PageEventParams =
  | Protocol.Page.LoadEventFiredEvent
  | Protocol.Page.DomContentEventFiredEvent
  | Protocol.Page.FrameStartedLoadingEvent
  | Protocol.Page.FrameAttachedEvent
  | Protocol.Page.FrameScheduledNavigationEvent;

type PageEvent = Event<string, PageEventParams>;

type CDPSessionType = typeof CDPSession;
type HTTPRequestType = typeof HTTPRequest;
type HTTPResponseType = typeof HTTPResponse;

type XvbfType = typeof Xvbf;

const xvfbPlatforms = new Set(["linux", "openbsd"]);

const setupEnv = (args: CrawlArgs): EnvHandle => {
  const logger = getLogger(args);
  const platformName = osLib.platform();

  let xvfbHandle: XvbfType;
  const closeFunc = () => {
    if (xvfbHandle !== undefined) {
      logger.info("Tearing down Xvfb");
      xvfbHandle.stopSync();
    }
  };

  if (args.interactive) {
    logger.info("Interactive mode, skipping Xvfb");
  } else if (xvfbPlatforms.has(platformName)) {
    logger.info(`Running on ${platformName}, starting Xvfb`);
    xvfbHandle = new Xvbf({
      // ensure 24-bit color depth or rendering might choke
      xvfb_args: ["-screen", "0", "1024x768x24"],
    });
    xvfbHandle.startSync();
  } else {
    logger.info(`Running on ${platformName}, Xvfb not supported`);
  }

  return {
    close: closeFunc,
  };
};

// Returns true if returned be of the func, and false if returned by timeout
const waitUntilUnless = (
  secs: number,
  unlessFunc: () => boolean,
  intervalMs = 500,
): Promise<boolean> => {
  const totalMs = secs * 1000;
  const endTime = Date.now() + totalMs;
  return new Promise((resolve) => {
    const timerId = setInterval(() => {
      const hasTimePassed = Date.now() > endTime;
      const unlessFuncRs = unlessFunc();
      const shouldEnd = hasTimePassed || unlessFuncRs;
      if (shouldEnd) {
        clearTimeout(timerId);
        const returnedBcTimeout = hasTimePassed;
        resolve(returnedBcTimeout);
      }
    }, intervalMs);
  });
};

type ResponseBodies = Map<string, Protocol.Network.GetResponseBodyResponse>;

const prepareHARGenerator = async (
  client: CDPSessionType,
  networkEvents: NetworkEvent[],
  pageEvents: PageEvent[],
  storeHarBody: boolean,
  responseBodies: ResponseBodies,
  logger: Logger,
) => {
  await client.send("Page.enable");
  await client.send("Network.enable");

  const networkMethods = [
    "Network.requestWillBeSent",
    "Network.requestServedFromCache",
    "Network.dataReceived",
    "Network.responseReceived",
    "Network.resourceChangedPriority",
    "Network.loadingFinished",
    "Network.loadingFailed",
  ];

  const pageMethods = [
    "Page.loadEventFired",
    "Page.domContentEventFired",
    "Page.frameStartedLoading",
    "Page.frameAttached",
    "Page.frameScheduledNavigation",
  ];

  networkMethods.forEach((method) => {
    client.on(method, (params: NetworkEventParams) => {
      networkEvents.push({ method, params });
      if (storeHarBody && method == "Network.loadingFinished") {
        const responseParams = params as ExtendedResponseReceivedEvent;
        const requestId = responseParams.requestId;
        client.send("Network.getResponseBody", { requestId: requestId }).then(
          (responseBody: Protocol.Network.GetResponseBodyResponse) => {
            responseBodies.set(requestId, responseBody);
          },
          (reason: unknown) => {
            logger.error("LoadingFinishedError: " + String(reason));
          },
        );
      }
    });
  });

  pageMethods.forEach((method) => {
    client.on(method, (params: PageEventParams) => {
      pageEvents.push({ method, params });
    });
  });
};

const generatePageGraph = async (
  client: CDPSessionType,
  logger: Logger,
): Promise<FinalPageGraphEvent> => {
  // The caller is responsible for the dwell and for detaching any debugger
  // (a renderer paused at a breakpoint cannot run Page.generatePageGraph) and
  // for dumping the cookie inventory first — graph generation can abort the
  // renderer (SIGABRT) on very large pages, so anything we want regardless of
  // the graph must be collected before this call.
  logger.info("calling generatePageGraph");
  const response = await client.send("Page.generatePageGraph");

  const responseLen = response.data.length;
  logger.info("generatePageGraph { size: ", responseLen, " }");
  return response as FinalPageGraphEvent;
};

// Dump the full cookie store (all first- and third-party cookies, including
// httpOnly ones JS cannot see) over CDP. Best-effort: returns [] on failure.
const dumpCookieStore = async (client: CDPSessionType): Promise<any[]> => {
  try {
    const result = await client.send("Network.getAllCookies");
    return (result.cookies ?? []) as any[];
  } catch {
    return [];
  }
};

export const doCrawl = async (
  args: CrawlArgs,
  previouslySeenUrls: URL[],
): Promise<void> => {
  const logger = getLogger(args);
  const urlToCrawl = asHTTPUrl(args.url);
  assert(urlToCrawl);
  logger.info([
    "Starting crawl with URL: ",
    urlToCrawl,
    " and with previously seen urls: [",
    previouslySeenUrls,
    "]",
  ]);

  const navTracker = makeNavigationTracker(urlToCrawl, previouslySeenUrls);
  const depth = Math.max(args.recursiveDepth, 1);
  let randomChildUrl: URL | undefined;
  let shouldRedirectToUrl: URL | undefined;

  const puppeteerConfig = await puppeteerConfigForArgs(args);
  const { launchOptions } = puppeteerConfig;
  const envHandle = setupEnv(args);

  let shouldStopWaitingFlag = false;
  const shouldStopWaitingFunc = () => {
    return shouldStopWaitingFlag;
  };

  try {
    logger.verbose([
      "Launching puppeteer with args: ",
      JSON.stringify(launchOptions),
    ]);
    const browser = await launchWithRetry(
      launchOptions,
      puppeteerConfig.shouldStealthMode,
      logger,
    );

    const pages = await browser.pages();
    if (pages.length > 0) {
      logger.info("Closing ", pages.length, " pages that are already open.");
      for (const aPage of pages) {
        logger.info("  - closing tab with url ", aPage.url());
        await aPage.close();
      }
    }

    try {
      // create new page, update UA if needed, navigate to target URL,
      // and wait for idle time.
      const page = await browser.newPage();
      const client = await page.target().createCDPSession();

      let stackTracker: DebugStackTracker | undefined;
      if (args.debugStacks) {
        stackTracker = new DebugStackTracker(logger, {
          native: args.debugNative,
          encoding: args.debugEncoding,
          breakpoints: args.debugBreakpoints,
          maxCaptures: args.debugMaxCaptures,
          maxValue: args.debugMaxValue,
          // Dump loaded sources of breakpoint-targeted scripts alongside the
          // stacks, so break coordinates can be verified against the exact bytes
          // the renderer ran (obfuscated bundles drift vs. an out-of-band fetch).
          saveScriptsDir: args.outputPath,
        });
        // Enable before navigation so breakpoints exist when scripts parse.
        await stackTracker.enable(client);
      }

      const networkEvents: NetworkEvent[] = [];
      const pageEvents: PageEvent[] = [];
      const responseBodies = new Map<any, any>();
      if (args.storeHar) {
        await prepareHARGenerator(
          client,
          networkEvents,
          pageEvents,
          args.storeHarBody,
          responseBodies,
          logger,
        );
      }

      client.on("Target.targetCrashed", (event: TargetCrashedEvent) => {
        const logMsg = {
          targetId: event.targetId,
          status: event.status,
          errorCode: event.errorCode,
        };
        logger.error(`Target.targetCrashed ${JSON.stringify(logMsg)}`);
        throw new Error(event.status);
      });

      if (args.userAgent !== undefined) {
        await page.setUserAgent(args.userAgent);
      }

      // Bodies are streamed to their sidecar as they are observed, so the log has
      // to exist before the tracker that feeds it.
      let bodyLog: BodyLog | undefined;
      if (args.saveBodies) {
        bodyLog = new BodyLog(
          {
            path: createBodiesPath(args, urlToCrawl),
            bodyMax: args.bodyMax,
            budgetBytes: args.bodiesBudgetMb * 1024 * 1024,
            allMimeTypes: args.saveBodiesFull,
          },
          logger,
        );
        logger.info("Recording request/response bodies to: ", bodyLog.path);
      }

      const metadataTracker = new RequestMetadataTracker(
        logger,
        false,
        bodyLog,
      );

      // Subscribe to the CDP *ExtraInfo events, which carry the raw Cookie
      // (outgoing) and Set-Cookie (incoming) headers that puppeteer strips.
      // These are non-pausing. Network is already enabled when storing a HAR;
      // enabling it again is a harmless no-op.
      await client.send("Network.enable");
      client.on(
        "Network.requestWillBeSentExtraInfo",
        (event: Protocol.Network.RequestWillBeSentExtraInfoEvent) => {
          metadataTracker.addExtraInfoFromRequestEvent(event);
        },
      );
      client.on(
        "Network.responseReceivedExtraInfo",
        (event: Protocol.Network.ResponseReceivedExtraInfoEvent) => {
          metadataTracker.addExtraInfoFromResponseEvent(event);
        },
      );

      await page.setRequestInterception(true);
      // First load is not a navigation redirect, so we need to skip it.
      page.on("request", async (request: HTTPRequestType) => {
        // Never let a request-handler failure become an unhandled rejection:
        // that crashes the whole crawl (and can truncate output written
        // concurrently). On any error, best-effort continue and move on.
        try {
          // Non-HTTP(S) requests (data:, blob:, chrome-extension:, about:, ...)
          // aren't navigations and have no HTTP metadata to track; let them
          // proceed untouched. (asHTTPUrl returns undefined for these.)
          const requestedUrl = asHTTPUrl(request.url());
          if (requestedUrl === undefined) {
            await request.continue();
            return;
          }
          await metadataTracker.addMetadataFromRequest(request);

          // Only capture parent frame navigation requests.
          if (!isTopLevelPageNavigation(request)) {
            logger.verbose(
              "Allowing request to ",
              request.url(),
              ", not ",
              "a top level navigation.",
            );
            await request.continue();
            return;
          }

          const hasUrlBeenSeen = navTracker.isInHistory(requestedUrl);
          const isCurrentNavUrl = navTracker.isCurrentUrl(requestedUrl);
          if (isCurrentNavUrl) {
            logger.info(
              "Loading ",
              requestedUrl,
              " bc it is the first top frame page load",
            );
            await request.continue();
            return;
          }

          if (!hasUrlBeenSeen) {
            logger.info(
              "Detected redirect to ",
              requestedUrl,
              " so stopping page load and moving on",
            );
            shouldRedirectToUrl = requestedUrl;
            shouldStopWaitingFlag = true;
            const client = await page.createCDPSession();
            await client.send("Page.stopLoading");
            await request.continue();
            return;
          }

          if (args.crawlDuplicates) {
            logger.info(
              "Loading ",
              requestedUrl,
              " bc was instructed to crawl duplicates",
            );
            await request.continue();
            return;
          }

          // Otherwise, we're in a redirect loop, so stop recording
          // the pagegraph, but continue.
          logger.info("Quitting bc we're in a redirect loop");
          shouldStopWaitingFlag = true;
          const client = await page.createCDPSession();
          await client.send("Page.stopLoading");
          await request.continue();
        } catch (err) {
          logger.verbose("Request handler error: ", String(err));
          try {
            await request.continue();
          } catch {
            // Request was already handled/aborted; nothing more to do.
          }
        }
      });

      page.on("response", async (response: HTTPResponseType) => {
        await metadataTracker.addMetadataFromResponse(response);
      });

      logger.info("Navigating to ", urlToCrawl);
      try {
        await page.goto(urlToCrawl, { waitUntil: "domcontentloaded" });
      } catch (e: unknown) {
        if (isTimeoutError(e)) {
          logger.info("Navigation timeout exceeded.");
        } else {
          throw e;
        }
      }

      logger.info("Loaded ", String(urlToCrawl));

      // Dwell so the page executes (and any breakpoints fire) before the graph
      // is generated.
      logger.info(`Waiting for ${String(args.seconds)}s`);
      await waitUntilUnless(args.seconds, shouldStopWaitingFunc);

      // Detach the debugger (resuming any pause) before graph generation or
      // teardown — a renderer paused at a breakpoint cannot run
      // Page.generatePageGraph, and closing it mid-pause throws.
      if (stackTracker) {
        await stackTracker.disable();
      }

      // Dump the cookie inventory NOW, while the renderer is alive and before
      // graph generation. Page.generatePageGraph can abort the renderer
      // (SIGABRT / "code 6") on very large pages; collecting cookies first means
      // a graph-gen crash still leaves us the authoritative 1P/3P inventory.
      if (args.saveCookies) {
        await writeCookies(
          args,
          urlToCrawl,
          JSON.stringify(await dumpCookieStore(client), null, 2),
          logger,
        );
        // Network-level per-cookie view (which requests carried each cookie and
        // which responses set it). Written here, before graph generation, so it
        // survives a graph-gen crash just like the cookie inventory.
        await writeCookieNetwork(
          args,
          urlToCrawl,
          metadataTracker.toCookieNetworkJSON(),
          logger,
        );
        // Per-hop detail of every redirect chain (status, Location, Set-Cookie).
        // The graph's request edges have nowhere to hold this, and it is where
        // cookie-syncing over redirects is visible.
        await writeRedirects(
          args,
          urlToCrawl,
          metadataTracker.toRedirectChainsJSON(),
          logger,
        );
      }

      if (args.debugStacks && stackTracker) {
        await writeStacks(
          args,
          urlToCrawl,
          JSON.stringify(stackTracker.getRecords(), null, 2),
          logger,
        );
      }

      // Close the body log before graph generation, for the same reason the
      // cookie sidecars are written here: a SIGABRT during generatePageGraph must
      // not cost us the sidecar. Each NDJSON line is already durable, so this
      // only flushes the tail and (optionally) compresses.
      if (bodyLog !== undefined) {
        await bodyLog.close();
        const stats = bodyLog.getStats();
        logger.info(
          "Recorded bodies: ",
          `${String(stats.bodiesStored)} of ${String(stats.records)} records, ` +
            `${String(stats.bytesStored)} bytes, ` +
            `${String(stats.truncated)} truncated, dropped ` +
            JSON.stringify(stats.dropped),
        );
        if (args.compress) {
          await compressAtPath(bodyLog.path);
        }
      }

      // Graph generation can abort the renderer (SIGABRT) on very large pages.
      // The cookie sidecars above are already on disk, and the rebuilt renderer
      // streams the graphml incrementally, so a crash here still leaves a valid
      // GraphML prefix on disk. Capture whether we produced a graph; if the CDP
      // call rejects (renderer died) or writeGraphML yields nothing, fall back
      // to recovering + tail-repairing that partial streamed file.
      let graphmlPath: FilePath | null = null;
      try {
        const response = await generatePageGraph(client, logger);
        if (args.saveRequestHeaders) {
          await writeHeadersLog(
            args,
            urlToCrawl,
            metadataTracker.toJSON(),
            logger,
          );
        }
        graphmlPath = await writeGraphML(
          args,
          urlToCrawl,
          response,
          metadataTracker,
          logger,
        );
      } catch (err) {
        logger.error(
          "generatePageGraph failed; attempting partial-graph recovery: ",
          String(err),
        );
      }
      if (graphmlPath === null) {
        graphmlPath = await recoverPartialGraphML(
          args,
          urlToCrawl,
          metadataTracker,
          logger,
        );
        if (graphmlPath === null) {
          logger.error("no graph could be recovered for: ", String(urlToCrawl));
        }
      } else if (args.recordingEventLog) {
        // generatePageGraph succeeded, so any Tier C event log is redundant.
        await cleanupEventLogs(resolve(args.outputPath), logger);
      }

      // Store HAR
      if (args.storeHar) {
        logger.verbose("Beginning HAR export");
        await Promise.all(responseBodies);

        for (const event of networkEvents) {
          if (!args.storeHarBody) {
            break;
          }

          if (event.method !== "Network.responseReceived") {
            continue;
          }

          const requestId = event.params.requestId;
          const responseBody = responseBodies.get(requestId);
          const responseParams = event.params as ExtendedResponseReceivedEvent;

          if (!responseBody) {
            responseParams.response.body = undefined;
            continue;
          }

          const responseBodyEncoding = responseBody.base64Encoded
            ? "base64"
            : undefined;
          const responseBodyBuffer = Buffer.from(
            responseBody.body,
            responseBodyEncoding,
          );
          responseParams.response.body = responseBodyBuffer.toString();
        }

        const allEvents = (pageEvents as (PageEvent | NetworkEvent)[]).concat(
          networkEvents,
        );
        const har = harFromMessages(allEvents, {
          includeTextFromResponseBody: args.storeHarBody,
        });
        await writeHAR(args, urlToCrawl, har, logger);
      }

      if (depth > 1) {
        randomChildUrl = await selectRandomChildUrl(page, logger);
      }
      logger.info("Closing page");

      if (args.screenshot) {
        const screenshotPath = createScreenshotPath(args, urlToCrawl);
        logger.info(`About to write screenshot to ${screenshotPath}`);
        await page.screenshot({ type: "png", path: screenshotPath });
        logger.info("Screenshot recorded");
      }
      await page.close();
    } catch (err) {
      logger.info("ERROR runtime fiasco from browser/page:", err);
    } finally {
      logger.info("Closing the browser");
      await browser.close();
    }
  } catch (err) {
    logger.info("ERROR runtime fiasco from infrastructure:", err);
  } finally {
    envHandle.close();
    if (puppeteerConfig.shouldClean) {
      await deleteAtPath(puppeteerConfig.profilePath);
    }
  }

  if (shouldRedirectToUrl !== undefined) {
    const newArgs = { ...args };
    newArgs.url = shouldRedirectToUrl;
    logger.info("Doing new crawl with redirected URL: ", shouldRedirectToUrl);
    await doCrawl(newArgs, navTracker.toHistory());
    return;
  }

  if (randomChildUrl !== undefined) {
    const newArgs = { ...args };
    newArgs.url = randomChildUrl;
    newArgs.recursiveDepth = depth - 1;
    await doCrawl(newArgs, navTracker.toHistory());
  }
};
