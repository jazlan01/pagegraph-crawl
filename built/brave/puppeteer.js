import { cp } from "node:fs/promises";
import { join, resolve } from "path";
import puppeteerLib from "puppeteer-core";
import { isDir } from "./checks.js";
import { deleteAtPath, createTempDir } from "./files.js";
import { getLogger } from "./logging.js";
const disabledBraveFeatures = [
    "Speedreader",
    "Playlist",
    "BraveVPN",
    "AIRewriter",
    "AIChat",
    "BravePlayer",
    "BraveDebounce",
    "BraveRewards",
    "BraveSearchOmniboxBanner",
    "BraveGoogleSignInPermission",
    "BraveNTPBrandedWallpaper",
    "AdEvent",
    "NewTabPageAds",
    "CustomNotificationAds",
    "InlineContentAds",
    "PromotedContentAds",
    "TextClassification",
    "SiteVisit",
];
const disabledChromeFeatures = [
    "IPH_SidePanelGenericMenuFeature",
    // Disable because enabling this results in redundant entires in the
    // MacOS "Local Network" permission table.
    "MacAppCodeSignClone",
    "AutomationControlled",
];
const disabledFeatures = disabledBraveFeatures.concat(disabledChromeFeatures);
const profilePathForArgs = async (args) => {
    const logger = getLogger(args);
    // The easiest case is if we've been told to use an existing profile.
    // In this case, just return the given path.
    if (args.existingUserDataDirPath !== undefined) {
        logger.verbose(`Crawling with profile at ${args.existingUserDataDirPath}.`);
        return { profilePath: args.existingUserDataDirPath, shouldClean: false };
    }
    // Next, figure out which existing profile we're going to use as the
    // template / starter profile for the new crawl.
    const resourcesDirPath = join(process.cwd(), "resources");
    const templateProfile = args.withShieldsUp
        ? join(resourcesDirPath, "shields-up-profile")
        : join(resourcesDirPath, "shields-down-profile");
    // Finally, either copy the above profile to the destination path
    // that was specified, or figure out a temporary location for it.
    const destProfilePath = args.persistUserDataDirPath ?? (await createTempDir("pagegraph-profile-"));
    const shouldClean = args.persistUserDataDirPath === undefined;
    if (isDir(destProfilePath)) {
        logger.info(`Profile exists at ${destProfilePath}, so deleting.`);
        await deleteAtPath(destProfilePath);
    }
    await cp(templateProfile, destProfilePath, {
        recursive: true,
    });
    logger.verbose(`Crawling with profile at ${destProfilePath}.`);
    return { profilePath: destProfilePath, shouldClean };
};
const makePuppeteerConf = async (args) => {
    const { profilePath, shouldClean } = await profilePathForArgs(args);
    // PageGraph (the renderer) reads this to stream the graphml straight to disk
    // instead of returning a >2GB blink::String over the DevTools pipe. It must be
    // absolute: the renderer resolves relative paths against its own working
    // directory, which is not guaranteed to match ours.
    process.env.PAGEGRAPH_OUT_DIR = resolve(args.outputPath);
    // Tier C: when --recording-event-log is set, tell the renderer to also write a
    // durable per-item GraphML event log to the same dir as it records. This is
    // the only thing that survives a *recording-time* crash (before ToGraphML
    // runs); left unset, the renderer never opens the log and normal crawls pay
    // nothing. See recoverPartialGraphML in files.ts.
    if (args.recordingEventLog) {
        process.env.PAGEGRAPH_EVENT_LOG_DIR = resolve(args.outputPath);
    }
    else {
        delete process.env.PAGEGRAPH_EVENT_LOG_DIR;
    }
    const chromeArgs = [
        "--ash-no-nudges",
        "--deny-permission-prompts",
        "--disable-brave-update",
        "--disable-breakpad",
        "--disable-component-extensions-with-background-pages",
        "--disable-component-update",
        "--allow-brave-component-update",
        "--disable-features=" + disabledFeatures.join(","),
        "--disable-first-run-ui",
        "--disable-infobars",
        "--disable-ipc-flooding-protection",
        "--disable-notifications",
        "--disable-renderer-backgrounding",
        "--disable-site-isolation-trials",
        "--disable-sync",
        "--mute-audio",
        "--no-first-run",
        // Required for the file-streaming graphml export: PageGraph::ToGraphML runs
        // in the renderer and writes the graphml directly to PAGEGRAPH_OUT_DIR, but
        // the renderer sandbox (esp. on macOS) blocks arbitrary file writes. This is
        // an automated crawler on a controlled machine, and --no-sandbox is not
        // page-detectable, so disabling it is acceptable here.
        "--no-sandbox",
        // Passive anti-detection: the canonical switch that keeps blink from
        // exposing navigator.webdriver and other AutomationControlled tells. This
        // does not inject any script into the page, so it leaves the recorded graph
        // untouched (unlike navigator-patching stealth plugins). Paired with the
        // ignoreDefaultArgs removal of --enable-automation below.
        "--disable-blink-features=AutomationControlled",
        // A realistic desktop window size; a 0x0 / tiny headful window is itself a
        // bot tell and skews any screenshot. defaultViewport:null makes the page
        // viewport follow this window size.
        "--window-size=1920,1080",
        "--user-data-dir=" + profilePath,
    ];
    chromeArgs.push("--enable-features=PageGraph");
    // Add --disable-setuid-sandbox if environment variable is set
    if (process.env.PAGEGRAPH_DISABLE_SETUID_SANDBOX === "true") {
        chromeArgs.push("--disable-setuid-sandbox");
    }
    const puppeteerArgs = {
        defaultViewport: null,
        args: chromeArgs,
        // Puppeteer injects --enable-automation by default, which paints the
        // "controlled by automated test software" infobar and raises automation
        // fingerprints that bot-management vendors (PerimeterX/HUMAN, Akamai,
        // F5) key on. Dropping it makes the crawl look like an ordinary browser
        // launch without touching the page or the recorded graph.
        ignoreDefaultArgs: ["--enable-automation"],
        executablePath: args.executablePath,
        dumpio: args.loggingLevel === "verbose",
        headless: false,
        // Puppeteer caps every CDP call at 180s by default, including
        // Page.generatePageGraph. A news or retail front page yields a multi-GB
        // graph that legitimately takes longer than that to serialize, and hitting
        // the cap is indistinguishable from a dead renderer: the call rejects, the
        // crawler drops into partial-graph recovery, and a healthy full graph is
        // thrown away in favour of a smaller one rebuilt from the event log. A
        // genuinely dead renderer is still caught promptly by Target.targetCrashed,
        // so raising this only removes the false positive.
        protocolTimeout: 1_800_000,
    };
    if (args.loggingLevel === "verbose") {
        chromeArgs.push("--enable-logging=stderr");
        chromeArgs.push("--vmodule=page_graph*=2");
    }
    if (args.extensionsPath !== undefined) {
        chromeArgs.push("--disable-extensions-except=" + args.extensionsPath);
        chromeArgs.push("--load-extension=" + args.extensionsPath);
    }
    if (args.proxyServer != null) {
        chromeArgs.push(`--proxy-server=${args.proxyServer.toString()}`);
        if (args.proxyServer.protocol === "socks5") {
            const socksProxyRule = "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE " +
                args.proxyServer.hostname;
            chromeArgs.push(socksProxyRule);
        }
    }
    if (args.extraArgs != null) {
        chromeArgs.push(...args.extraArgs);
    }
    return {
        launchOptions: puppeteerArgs,
        shouldStealthMode: args.stealth,
        profilePath,
        shouldClean,
    };
};
export const puppeteerConfigForArgs = makePuppeteerConf;
const asyncSleep = async (millis) => {
    await new Promise((resolve) => setTimeout(resolve, millis));
};
const defaultComputeTimeout = (tryIndex) => {
    return Math.pow(2, tryIndex - 1) * 1000;
};
export const launchWithRetry = async (launchOptions, stealthMode, logger, retryOptions) => {
    // default to 3 retries with a base-2 exponential-backoff delay
    // between each retry (1s, 2s, 4s, ...)
    const retries = retryOptions === undefined ? 3 : retryOptions.retries;
    const computeTimeout = retryOptions !== undefined
        ? retryOptions.computeTimeout
        : defaultComputeTimeout;
    // const puppeteerLib = makeLaunchPuppeteerFunc(stealthMode, logger)
    // `return await` (not `return`) is load-bearing here: launch() returns a
    // promise, and returning it un-awaited hands any rejection straight to the
    // caller without ever entering the catch — which made every retry below
    // dead code and turned any transient launch failure into a fatal one.
    try {
        return await puppeteerLib.launch(launchOptions);
    }
    catch (err) {
        logger.info("Failed to launch: ", err, ". ", retries, " left…");
    }
    for (let i = 1; i <= retries; ++i) {
        await asyncSleep(computeTimeout(i));
        try {
            return await puppeteerLib.launch(launchOptions);
        }
        catch (err) {
            logger.info("Failed to launch: ", err, ". ", retries - i, " left…");
        }
    }
    throw new Error(`Unable to launch after ${String(retries)} retries!`);
};
