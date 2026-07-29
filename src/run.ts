#!/usr/bin/env node

import { ArgumentParser } from "argparse";

import { doCrawl } from "./brave/crawl.js";
import { validate } from "./brave/validate.js";

const defaultCrawlSecs = 30;
const defaultShieldsSetting = "down";
const defaultLoggingSetting = "info";

const parser = new ArgumentParser({
  add_help: true,
  description: "CLI tool for crawling and recording websites with PageGraph",
});
parser.add_argument("-v", "--version", {
  action: "version",
  version: "1.2.1",
});
parser.add_argument("-b", "--binary", {
  help:
    "Path to the PageGraph enabled build of Brave. If not provided, " +
    "try to guess where the binary is, or if its in $PATH",
});
parser.add_argument("-r", "--recursive-depth", {
  default: 1,
  help:
    "If provided, choose a link at random on page and do another crawl " +
    "to this depth. Default: 1 (no recursion).",
});
parser.add_argument("-o", "--output", {
  help:
    "Path to write to. If a directory is provided, then results are " +
    "written to a file in that directory. If a full path is given, " +
    "then results are written to that path.",
  required: true,
});
parser.add_argument("-u", "--url", {
  help: "The URLs to record.",
  required: true,
});
parser.add_argument("-e", "--existing-user-data-dir", {
  help:
    "The chromium user data directory to use when crawling. Cannot " +
    'be used with "--persist-user-data-dir"',
});
parser.add_argument("-p", "--persist-user-data-dir", {
  help:
    "If provided, the user data directory will be saved at this path. " +
    'Cannot be used with "--existing-user-data-dir"',
  default: false,
  action: "store_true",
});
parser.add_argument("--extensions-path", {
  help: "If provided, start browser with the provided extensions installed.",
  default: undefined,
});
parser.add_argument("-s", "--shields", {
  help:
    "Whether to measure with shields up or down. Ignored when using " +
    `"--existing-user-data-dir".  Default: ${defaultShieldsSetting}`,
  choices: ["up", "down"],
  default: defaultShieldsSetting,
});
parser.add_argument("-t", "--secs", {
  help: `The dwell time in seconds. Defaults: ${String(defaultCrawlSecs)} sec.`,
  type: "int",
  default: defaultCrawlSecs,
});
parser.add_argument("--logging", {
  help: `Logging level. Default: ${defaultLoggingSetting}.`,
  choices: ["none", "info", "verbose"],
  default: defaultLoggingSetting,
});
parser.add_argument("-i", "--interactive", {
  help:
    "Suppress use of Xvfb to allow interaction with spawned " +
    "browser instance",
  action: "store_true",
  default: false,
});
parser.add_argument("-a", "--user-agent", {
  help: "Override the browser's UserAgent string to USER_AGENT",
  metavar: "USER_AGENT",
});
parser.add_argument("--proxy-server", {
  help: "Use an HTTP/SOCKS proxy at URL for all navigations",
  metavar: "URL",
});
parser.add_argument("-x", "--extra-args", {
  help:
    "Pass JSON_ARRAY as extra CLI argument to the browser " +
    "instance launched.",
  metavar: "JSON_ARRAY",
});
parser.add_argument("-c", "--crawl-duplicates", {
  help:
    "Enable crawls for redirected URLs that are already present in " +
    "the redirection chain.",
  action: "store_true",
  default: false,
});
parser.add_argument("--screenshot", {
  help: "Record a screenshot of the page at the end of the crawl.",
  action: "store_true",
  dest: "screenshot",
  default: false,
});
parser.add_argument("--har", {
  help: "Generate a HAR file at the end of the crawl.",
  action: "store_true",
  dest: "store_har",
  default: false,
});
parser.add_argument("--har-body", {
  help: "Store the response bodies in the HAR file. Only works in combination with --har.",
  action: "store_true",
  dest: "store_har_body",
  default: false,
});
parser.add_argument("-z", "--compress", {
  help: "Compresses the graphml file as gzip.",
  action: "store_true",
  dest: "compress",
  default: false,
});
parser.add_argument("--debug-stacks", {
  help:
    "Attach the CDP Debugger and capture the JS call stack + local scope " +
    "values at every document.cookie / CookieStore write, writing them to a " +
    "<output>.stacks.json sidecar. Useful for auditing how trackers build " +
    "cookie values.",
  action: "store_true",
  dest: "debug_stacks",
  default: false,
});
parser.add_argument("--debug-native", {
  help:
    "With --debug-stacks, break on native functions (the document.cookie " +
    "setter, plus btoa/atob/XHR.send with --debug-encoding). WARNING: halting " +
    "on a native builtin that is also a PageGraph probe can crash the renderer " +
    "(SIGTRAP / 'error code 5') on PageGraph builds. Prefer --debug-breakpoint " +
    "offsets. Off by default.",
  action: "store_true",
  dest: "debug_native",
  default: false,
});
parser.add_argument("--debug-encoding", {
  help:
    "With --debug-stacks --debug-native, also break on " +
    "btoa/atob/XMLHttpRequest.send to capture stacks + locals at " +
    "encoding/exfiltration boundaries.",
  action: "store_true",
  dest: "debug_encoding",
  default: false,
});
parser.add_argument("--debug-breakpoint", {
  help:
    "With --debug-stacks, set an extra breakpoint at an arbitrary script " +
    "site and capture the stack + locals there. Repeatable. Format: " +
    "'<urlRegex>#<byteOffset>' (offset = column on a one-line minified " +
    "script) or '<urlRegex>@<line>:<col>'.",
  action: "append",
  dest: "debug_breakpoint",
  default: [],
  metavar: "SPEC",
});
parser.add_argument("--debug-max-captures", {
  help:
    "With --debug-stacks, cap the total number of paused-stack captures so " +
    "high-frequency calls (e.g. atob) don't stall the crawl. Default 200.",
  type: "int",
  dest: "debug_max_captures",
  default: 200,
});
parser.add_argument("--debug-max-value", {
  help:
    "With --debug-stacks, the max captured length of each variable value " +
    "(object variables are JSON-stringified up to this length). Raise it to " +
    "capture full payloads/sensor objects. Default 512.",
  type: "int",
  dest: "debug_max_value",
  default: 512,
});
parser.add_argument("--save-cookies", {
  help:
    "Dump the full cookie store (all first- and third-party cookies, including " +
    "httpOnly) over CDP at the end of the crawl to a <output>.cookies.json " +
    "sidecar. Gives an authoritative inventory to pair with the graph.",
  action: "store_true",
  dest: "save_cookies",
  default: false,
});
parser.add_argument("--recording-event-log", {
  help:
    "Write a durable GraphML event log to the output dir as PageGraph records " +
    "each node/edge, so a RECORDING-time renderer crash (which happens before " +
    "generatePageGraph runs and leaves nothing to stream) still yields a " +
    "recoverable partial graph. Adds per-item disk writes during recording, so " +
    "it is off by default; enable it for pages that reliably crash graph gen.",
  action: "store_true",
  dest: "recording_event_log",
  default: false,
});
// parser.add_argument('--no-stealth', {
//   help: 'Do not enable the "puppeteer-extra-plugin-stealth" extension.',
//   default: false,
//   action: 'store_true',
// })

const rawArgs = parser.parse_args();
const [isValid, errorOrArgs] = validate(rawArgs);
if (!isValid) {
  console.error("Invalid arguments!\n\n");
  console.error(errorOrArgs);
  process.exit(1);
}

const crawlArgs = errorOrArgs as CrawlArgs;
await (async () => {
  await doCrawl(crawlArgs, []);
})();
