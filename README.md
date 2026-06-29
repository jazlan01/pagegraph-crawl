pagegraph-crawl
===

Command line tool for crawling web pages with PageGraph.

Install
---
Requires a recent version of node (current testing is done on `v23.4.0`).

```bash
npm install
npm run build
```

Test
---
```bash
npm run test
```
The tests are defined in `test/test.js`. Test parameters are read from environment variables (`PAGEGRAPH_CRAWL_TEST_BINARY_PATH`, `PAGEGRAPH_CRAWL_TEST_PORT`, `PAGEGRAPH_CRAWL_TEST_BASE_URL`, `DEBUG`). You need to specify a PageGraph binary path.

The `cookie provenance` suite additionally exercises a small `node:http` listener (on `PAGEGRAPH_CRAWL_TEST_PORT` + 1) that emits a `Set-Cookie` response header, since the static file server cannot. Those tests assert on the PageGraph engine's "cookie source" provenance attribute and require a Brave build that includes the corresponding engine changes.

Usage
---
Since [PageGraph](https://github.com/brave/brave-browser/wiki/PageGraph) is built as part of Brave Nightly, you can simply point the binary path to be your local installation.

```bash
npm run crawl -- \
    -b /Applications/Brave\ Browser\ Nightly.app/Contents/MacOS/Brave\ Browser\ Nightly \
    -u https://brave.com \
    -t 5 \
    -o output/ \
    --debug debug
```

The `-t` specifies how many seconds to crawl the URL provided in `-u` using the PageGraph binary in `-b`.

You can see all supported options:
```bash
npm run crawl -- -h
```

**NOTE:** PageGraph currently does not track puppeteer / automation scripts, and so modifying or interacting with the document through [devtools/puppeteer](https://pptr.dev/) while recording a PageGraph file will likely fail.
