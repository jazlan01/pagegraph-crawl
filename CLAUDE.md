# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A CLI tool that drives a PageGraph-enabled build of Brave (via puppeteer-core over the
DevTools/CDP protocol) to crawl a URL, then exports a `.graphml` file recording everything
the page did. PageGraph is a Brave feature that records page execution as a graph; this tool
orchestrates the browser, post-processes the output, and can optionally emit HAR files,
screenshots, and request-header logs.

`src/` is TypeScript compiled to `built/`. Tests are plain JavaScript run against the
compiled output in `built/`, not against `src/`.

## Commands

```bash
npm run build          # tsc -> built/ (REQUIRED before crawl or test; tests import from built/)
npm run lint           # eslint over src/
npm run lint:fix       # eslint --fix
npm run clean          # rm -Rf built/*
npm run test           # builds, then runs mocha test/test.js (60s timeout)
npm run crawl -- <args>  # run the CLI; see README for flags, or `npm run crawl -- -h`
```

Running a single test (after `npm run build`):
```bash
node ./node_modules/mocha/bin/mocha.js test/test.js --timeout 60000 --grep "cross-site"
```

Tests require a PageGraph-enabled Brave binary. The test harness reads it from the
`PAGEGRAPH_CRAWL_TEST_BINARY_PATH` env var (other overrides: `PAGEGRAPH_CRAWL_TEST_PORT`,
`PAGEGRAPH_CRAWL_TEST_BASE_URL`, `DEBUG`). The tests spin up a local `http-server` over
`test/pages/` and crawl those fixtures. CI (`.github/workflows/pr.yml`) installs
brave-browser-nightly and runs lint + test on every PR, also setting
`PAGEGRAPH_DISABLE_SETUID_SANDBOX=true`.

A `pre-push` git hook (`.githooks/pre-push`) runs `npm run build`.

## Architecture

Entry point `src/run.ts` defines all CLI flags (argparse), then hands raw args to
`validate()` and the validated `CrawlArgs` to `doCrawl()`. Everything else lives in
`src/brave/`.

**Validation boundary** — `validate.ts` is the single place that turns untrusted argparse
output (snake_case fields, strings) into a frozen `CrawlArgs` object (camelCase, typed). It
guesses the Brave binary location if `--binary` is omitted, creates the output dir, parses
the proxy/extra-args, and rejects conflicting profile flags. Downstream code trusts
`CrawlArgs`. Shared types (`CrawlArgs`, `Logger`, `PuppeteerConfig`, etc.) are declared
globally in `src/declarations.d.ts` — they are ambient, so no import is needed to use them.

**Crawl orchestration** — `crawl.ts` `doCrawl()` is the core loop. It:
1. Builds puppeteer launch options (`puppeteer.ts`) and sets up Xvfb on Linux/OpenBSD
   (skipped with `--interactive` or on unsupported platforms).
2. Launches Brave with retry/backoff (`launchWithRetry`), opens a page, attaches a CDP
   session.
3. Intercepts requests to detect **top-level navigation redirects**. When the page tries to
   navigate somewhere new, it stops loading, records the current PageGraph, and **recursively
   calls `doCrawl()` for the redirect target** — each hop in a redirect chain produces its
   own `.graphml` file. A `NavigationTracker` (`navigation_tracker.ts`) carries the URL
   history across recursive calls to detect redirect loops (broken unless `--crawl-duplicates`).
4. Waits for the dwell time (`-t`/`--secs`), then calls `Page.generatePageGraph` over CDP.
5. `--recursive-depth` is a separate recursion mechanism: after a crawl it picks a random
   child link (`page.ts`) and crawls that, decrementing depth.

**Request metadata stitching** — PageGraph's own graphml does not include HTTP headers or
body sizes. `RequestMetadataTracker` (`request_metadata_tracker.ts`) listens to puppeteer
`request`/`response` events and records headers + sizes keyed by request id. The tricky part
is `#simplifyRequestId`: puppeteer exposes three request-id formats (worker
`interception-job-N.0`, sub-resource `pid.reqid`, 32-char navigation ids) that must be
normalized to match the ids PageGraph writes into the graphml. After the crawl,
`rewriteGraphML()` streams the graphml through `PageGraphXMLRewriter` (`graphml_rewriter.ts`,
built on `xml-stream-editor`) and injects `headers`/`size` attributes onto request edges.

**Output** — `files.ts` owns all path/filename logic and writing. Output filenames are
`page_graph_<sanitized-url>_<timestamp>` with extensions appended (`.graphml`, `.har`,
`.headers.json`, `.png`); `--compress` gzips the graphml/headers. The graphml is first
written to a `.tmp` file, then the header-stitching rewrite produces the final file.

**Browser profiles** — `resources/shields-up-profile/` and `resources/shields-down-profile/`
are template Chromium user-data dirs. By default the chosen one is copied to a temp dir for
the crawl and deleted after; `--persist-user-data-dir` keeps it, `--existing-user-data-dir`
reuses one in place (mutually exclusive). `puppeteer.ts` also assembles the long list of
disabled Brave/Chrome features and the `--enable-features=PageGraph` flag that activates the
recording.

## Conventions

- ESM throughout (`"type": "module"`). Intra-`src` imports use `.js` extensions even for
  `.ts` source files (TS ESM requirement) — e.g. `import { doCrawl } from "./brave/crawl.js"`.
- ESLint runs `strictTypeChecked` + `stylisticTypeChecked` + prettier. The `no-unsafe-*` and
  `no-explicit-any` rules are deliberately disabled because puppeteer-core, chrome-har,
  argparse, xml-stream, and xvfb are declared as untyped `any` modules in
  `declarations.d.ts`. Interaction with those libraries is inherently untyped.
- Logging goes through `getLogger(args)` returning one of three frozen loggers keyed by
  `--logging` (`none`/`info`/`verbose`); never `console.log` directly in `src/brave/`.
- `--logging verbose` also turns on browser stderr logging and `dumpio`.
