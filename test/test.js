/* global describe, before, after, it */

import assert from 'node:assert'
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { gunzipSync } from 'node:zlib'

import kill from 'tree-kill'

import {
  startServer, createTempOutputDir, cleanupTempOutputDir,
  validateHAR, crawlUrl, readCrawlResults, getExpectedFilename,
  startSetCookieServer, stopSetCookieServer, setCookieName, setCookieValue,
  hopCookieName, hop2CookieName, exfilCookieValue, postMessageSyncId
} from './utils.js'

const DEBUG = process.env.DEBUG || false
const testServerPort = process.env.PAGEGRAPH_CRAWL_TEST_PORT || 3000
// The Set-Cookie listener runs on its own port, since the static http-server
// cannot emit a per-response Set-Cookie header.
const setCookieServerPort = Number(testServerPort) + 1
const baseUrl = process.env.PAGEGRAPH_CRAWL_TEST_BASE_URL || 'http://127.0.0.1'
const binaryPath = process.env.PAGEGRAPH_CRAWL_TEST_BINARY_PATH || null

const graphMlExtension = '.graphml'
const testBaseUrl = `${baseUrl}:${testServerPort}`
const setCookieUrl = `${baseUrl}:${setCookieServerPort}/set-cookie`
const simpleUrl = `${testBaseUrl}/simple.html`
const makeTestUrl = (htmlFile) => `${testBaseUrl}/${htmlFile}`
const expectedFilenameSimple = getExpectedFilename(simpleUrl)

// Schema strings the brave-core PageGraph engine emits into the graphml for
// cookie provenance. These match the engine changes in
// brave_page_graph: a "cookie source" edge attribute is added to cookie
// storage-set edges, tagged per channel by CookieSourceToString().
const COOKIE_SCHEMA = {
  // attr.name of the <key> declaring which channel set a cookie.
  sourceAttr: 'cookie source',
  // CookieSourceToString() values, by channel.
  sourceJs: 'js',
  sourceCookieStore: 'cookie-store',
  sourceSetCookieHeader: 'set-cookie-header'
}

const _crawlUrl = async (url, outputDir, args) => {
  return await crawlUrl(url, outputDir, args, binaryPath, DEBUG)
}
const _readCrawlResults = async (outputPath) => {
  return await readCrawlResults(outputPath, DEBUG)
}
// Just the graphs. Most assertions below are counting how many graphs a crawl
// produced (one per redirect hop), which is not the same as how many files it
// wrote — sidecars come and go, and a count over everything turns every new
// sidecar into a spurious failure across the whole suite.
const _readGraphs = async (outputPath) => {
  return (await readCrawlResults(outputPath, DEBUG)).filter(
    (f) => f.endsWith(graphMlExtension) ||
      f.endsWith(graphMlExtension + '.gz'))
}
// Minimal graphml readers for the engine-instrumentation assertions below.
// Attribute ids (dNN) are assigned by the engine in enum order and shift whenever
// it gains an attribute, so always resolve them by attr.name.
const edgeAttrKey = (graphML, name) => {
  const m = new RegExp(
    `<key id="(d\\d+)" for="edge" attr\\.name="${name}"`).exec(graphML)
  return m ? m[1] : null
}
const nodeAttrKey = (graphML, name) => {
  const m = new RegExp(
    `<key id="(d\\d+)" for="node" attr\\.name="${name}"`).exec(graphML)
  return m ? m[1] : null
}
const unescapeXml = (s) => s
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
  .replace(/&#39;/g, "'").replace(/&amp;/g, '&')
const dataValue = (body, key) => {
  if (!key) return null
  const m = new RegExp(`<data key="${key}">([\\s\\S]*?)</data>`).exec(body)
  return m ? unescapeXml(m[1]) : null
}
const edgeElements = (graphML) => {
  const out = []
  const re = /<edge id="(e\d+)" source="(n\d+)" target="(n\d+)">([\s\S]*?)<\/edge>/g
  let m
  while ((m = re.exec(graphML)) !== null) {
    out.push({ id: m[1], source: m[2], target: m[3], body: m[4] })
  }
  return out
}
const edgesOfType = (graphML, edgeType) => {
  const typeKey = edgeAttrKey(graphML, 'edge type')
  return edgeElements(graphML)
    .filter((e) => dataValue(e.body, typeKey) === edgeType)
    .map((e) => e.body)
}
// node id -> the web API method it represents, e.g. "Window.postMessage".
const webApiMethodsByNode = (graphML) => {
  const typeKey = nodeAttrKey(graphML, 'node type')
  const methodKey = nodeAttrKey(graphML, 'method')
  const out = new Map()
  const re = /<node id="(n\d+)">([\s\S]*?)<\/node>/g
  let m
  while ((m = re.exec(graphML)) !== null) {
    if (dataValue(m[2], typeKey) !== 'web API') continue
    const method = dataValue(m[2], methodKey)
    if (method) out.set(m[1], method)
  }
  return out
}

const _createTempOutputDir = createTempOutputDir.bind(undefined, DEBUG)
const _cleanupTempOutputDir = async (outputPath) => {
  return await cleanupTempOutputDir(outputPath, DEBUG)
}

describe('pagegraph-crawl', () => {
  let serverProcessHandle
  let setCookieServerHandle
  before(async () => {
    serverProcessHandle = await startServer(testServerPort, DEBUG)
    setCookieServerHandle = await startSetCookieServer(setCookieServerPort, DEBUG)
  })
  after((done) => {
    stopSetCookieServer(setCookieServerHandle).then(() => {
      kill(serverProcessHandle.pid, 'SIGTERM', (error) => {
        if (error) {
          console.error(error)
        }
        if (DEBUG) {
          console.log('Test server has closed')
        }
        done()
      })
    })
  })

  describe('single page', () => {
    it('static page', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(simpleUrl, testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 1)

        const file = files[0]
        assert.ok(file.startsWith(expectedFilenameSimple))
        assert.ok(file.endsWith(graphMlExtension))

        const graphML = await readFile(join(testDir, file), 'UTF-8')
        assert.ok(graphML.includes('hJc9ZK1sGr'))
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })
    it('static page with gzip', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(simpleUrl, testDir, { '--compress': null })
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 1)

        const file = files[0]
        assert.ok(file.startsWith(expectedFilenameSimple))
        assert.ok(file.endsWith(graphMlExtension + '.gz'))

        const graphMLCompressed = await readFile(join(testDir, file))
        const graphML = await gunzipSync(graphMLCompressed)
        assert.ok(graphML.includes('hJc9ZK1sGr'))
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })
  })

  describe('redirection', () => {
    it('same-site (A->A)', async () => {
      const initialUrl = `${testBaseUrl}/redirect-js-same-site.html`
      const expectedFilenameInitial = getExpectedFilename(initialUrl)

      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(initialUrl, testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 2)

        for (const file of files) {
          assert.ok(file.endsWith(graphMlExtension))
          assert.ok(file.startsWith(expectedFilenameSimple) ||
            file.startsWith(expectedFilenameInitial))

          const graphML = await readFile(join(testDir, file), 'UTF-8')
          if (file.startsWith(expectedFilenameSimple)) {
            assert.ok(graphML.includes('hJc9ZK1sGr'))
            assert.ok(graphML.includes('W0XNNnar') === false)
          } else {
            assert.ok(graphML.includes('W0XNNnar'))
            assert.ok(graphML.includes('hJc9ZK1sGr') === false)
          }
        }
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('multiple same-site (A->A->A)', async () => {
      const initialUrl = `${testBaseUrl}/multiple-redirects-js-same-site.html`
      const secondUrl = `${testBaseUrl}/redirect-js-same-site.html`
      const expectedFilenameInitial = getExpectedFilename(initialUrl)
      const expectedFilenameSecond = getExpectedFilename(secondUrl)

      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(initialUrl, testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 3)

        for (const file of files) {
          assert.ok(file.endsWith(graphMlExtension))
          assert.ok(file.startsWith(expectedFilenameSimple) ||
            file.startsWith(expectedFilenameInitial) ||
            file.startsWith(expectedFilenameSecond))

          const graphML = await readFile(join(testDir, file), 'UTF-8')
          if (file.startsWith(expectedFilenameSimple)) {
            assert.ok(graphML.includes('hJc9ZK1sGr'))
            assert.ok(graphML.includes('W0XNNnar') === false)
            assert.ok(graphML.includes('NsybZB0LO4') === false)
          } else if (file.startsWith(expectedFilenameInitial)) {
            assert.ok(graphML.includes('NsybZB0LO4'))
            assert.ok(graphML.includes('W0XNNnar') === false)
            assert.ok(graphML.includes('hJc9ZK1sGr') === false)
          } else if (file.startsWith(expectedFilenameSecond)) {
            assert.ok(graphML.includes('W0XNNnar'))
            assert.ok(graphML.includes('NsybZB0LO4') === false)
            assert.ok(graphML.includes('hJc9ZK1sGr') === false)
          }
        }
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('cross-site (A->B)', async () => {
      // Crawl with one redirect, cross-site.
      const initialUrl = `${testBaseUrl}/redirect-js-cross-site.html`
      // This has to be hard-coded because it's being set in redirect-js-cross-site.html
      const finalUrl = 'http://127.0.0.1:3000/simple.html'
      const expectedFilenameInitial = getExpectedFilename(initialUrl)
      const expectedFilenameFinal = getExpectedFilename(finalUrl)

      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(initialUrl, testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 2)

        for (const file of files) {
          assert.ok(file.endsWith(graphMlExtension))
          assert.ok(file.startsWith(expectedFilenameFinal) ||
            file.startsWith(expectedFilenameInitial))
          const graphML = await readFile(join(testDir, file), 'UTF-8')
          if (file.startsWith(expectedFilenameInitial)) {
            assert.ok(graphML.includes('Zym8MZp'))
            assert.ok(graphML.includes('hJc9ZK1sGr') === false)
          } else {
            assert.ok(graphML.includes('hJc9ZK1sGr'))
            assert.ok(graphML.includes('Zym8MZp') === false)
          }
        }
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('cross-site chain (A->B->A)', async () => {
      // Crawl with recursive redirects, cross-site.
      const initialUrl = `${testBaseUrl}/redirect-chain-A.html`
      // This has to be hard-coded because it's being set in redirect-chain-A.html
      const finalUrl = 'http://127.0.0.1:3000/redirect-chain-B.html'
      const expectedFilenameInitial = getExpectedFilename(initialUrl)
      const expectedFilenameFinal = getExpectedFilename(finalUrl)

      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(initialUrl, testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 2)

        for (const file of files) {
          assert.ok(file.endsWith(graphMlExtension))
          assert.ok(file.startsWith(expectedFilenameFinal) ||
            file.startsWith(expectedFilenameInitial))
          const graphML = await readFile(join(testDir, file), 'UTF-8')
          if (file.startsWith(expectedFilenameInitial)) {
            assert.ok(graphML.includes('Jro8qF9KOg'))
            assert.ok(graphML.includes('Ec9Z5dlgA5') === false)
          } else {
            assert.ok(graphML.includes('Ec9Z5dlgA5'))
            assert.ok(graphML.includes('Jro8qF9KOg') === false)
          }
        }
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })
  })

  describe('requests', () => {
    describe('metadata', () => {
      const makeRequestSizeTest = (resourceFileName) => {
        return async () => {
          const testDir = await _createTempOutputDir()
          try {
            const testUrl = `${testBaseUrl}/requests-metadata.html`
            await _crawlUrl(testUrl, testDir)
            const files = await _readGraphs(testDir)
            assert.equal(files.length, 1)
            const file = files[0]
            const graphML = await readFile(join(testDir, file), 'UTF-8')

            const relativeResourcePath = 'resources/' + resourceFileName
            const resourceFilePath = './test/pages/' + relativeResourcePath
            const resourceBuffer = await readFile(resourceFilePath)
            const bodySize = resourceBuffer.length
            // Check that it looks like we see the URL of the requested
            // resource in the graphml
            assert.ok(graphML.includes(`${relativeResourcePath}<`))
            // And that we see the expected body size recorded too
            assert.ok(graphML.includes(`>${bodySize}<`))
          } finally {
            await _cleanupTempOutputDir(testDir)
          }
        }
      }

      it('static request (size)', makeRequestSizeTest('document.svg'))
      it('dynamic request (size)', makeRequestSizeTest('page-cookies.js'))
    })

    it('...in web worker', async () => {
      const workerTestUrl = `${testBaseUrl}/worker.html`
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(workerTestUrl, testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 1)

        const file = files[0]
        const graphML = await readFile(join(testDir, file), 'UTF-8')

        // The test page sets a text element 'response: "success"' or
        // 'response: "fail"' once the worker makes it request.
        // So checking for this is a way to guard against the test passing
        // because the worker script never actually made a request.
        assert.ok(graphML.includes('>response: "success"<') ||
          graphML.includes('>response: &quot;success&quot;<'))

        // And this checks to make sure the un-parsed request-id for the
        // worker request didn't end up in the graph (since the crawler
        // catches and rewrites these).
        assert.ok(!graphML.includes('interception-job-'))
      } finally {
        // await _cleanupTempOutputDir(testDir)
      }
    })

    it('http cookies', async () => {
      const testDir = await _createTempOutputDir()
      try {
        const cookiesTestUrl = makeTestUrl('cookies.html')
        await _crawlUrl(cookiesTestUrl, testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 1)

        const file = files[0]
        const graphML = await readFile(join(testDir, file), 'UTF-8')

        // First check and make sure we only see one the below string
        // once, which will appear in the cookie header.
        const cookieHeader = graphML.match(/test-cookie=value-[0-9]+/g) || []
        assert.equal(cookieHeader.length, 1)
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })
  })

  describe('HAR recording', () => {
    it('without response bodies', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(simpleUrl, testDir, { '--har': null })
        const graphs = await _readGraphs(testDir)
        assert.equal(graphs.length, 1)
        const files = await _readCrawlResults(testDir)

        const harFile = files.find(file => file.endsWith('.har'))
        assert.ok(harFile !== undefined)

        const har = await readFile(join(testDir, harFile), 'UTF-8')
        assert.ok(har.includes('hJc9ZK1sGr') === false)
        const parsedHAR = validateHAR(har)

        assert.equal(parsedHAR.log.entries.length, 2)
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('with response bodies', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(simpleUrl, testDir, {
          '--har': null,
          '--har-body': null
        })
        const graphs = await _readGraphs(testDir)
        assert.equal(graphs.length, 1)
        const files = await _readCrawlResults(testDir)

        const harFile = files.find(file => file.endsWith('.har'))
        assert.ok(harFile !== undefined)

        const har = await readFile(join(testDir, harFile), 'UTF-8')
        assert.ok(har.includes('hJc9ZK1sGr'))
        const parsedHAR = validateHAR(har)

        assert.equal(parsedHAR.log.entries.length, 2)
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('with subresources', async () => {
      const testDir = await _createTempOutputDir()
      try {
        const resourcesUrl = makeTestUrl('har-subresources.html')
        await _crawlUrl(resourcesUrl, testDir, {
          '--har': null,
          '--har-body': null
        })
        const graphs = await _readGraphs(testDir)
        assert.equal(graphs.length, 1)
        const files = await _readCrawlResults(testDir)

        const harFile = files.find(file => file.endsWith('.har'))
        assert.ok(harFile !== undefined)

        const har = await readFile(join(testDir, harFile), 'UTF-8')
        const parsedHAR = validateHAR(har)
        assert.equal(parsedHAR.log.entries.length, 5)

        const firstLogEntry = parsedHAR.log.entries[1]
        const secondLogEntry = parsedHAR.log.entries[2]
        const thirdLogEntry = parsedHAR.log.entries[3]

        const firstRequestUrl = firstLogEntry.request.url
        assert.ok(firstRequestUrl.endsWith('resources/page-resources.js'))
        assert.equal(firstLogEntry.response.status, 200)

        assert.ok(secondLogEntry.request.url.includes('this-path-does-not-exist.txt'))
        assert.equal(secondLogEntry.response.status, 404)

        assert.ok(thirdLogEntry.request.url.endsWith('resources/document.svg'))
        assert.ok(thirdLogEntry.response.content.text.includes('<circle'))
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })
  })

  // These tests validate the cookie-provenance instrumentation emitted by the
  // brave-core PageGraph engine (the "cookie source" edge attribute on cookie
  // storage-set edges). They require a Brave binary built WITH those engine
  // changes; against a stock binary they will fail, as expected.
  describe('cookie provenance', () => {
    it('document.cookie write is tagged source=js', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(makeTestUrl('cookie-document.html'), testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 1)

        const graphML = await readFile(join(testDir, files[0]), 'UTF-8')

        // The cookie value the page set, recorded exactly once.
        const cookieWrite = graphML.match(/doc-cookie=docval-[0-9]+/g) || []
        assert.equal(cookieWrite.length, 1)
        // Tagged as a JS-driven cookie set.
        assert.ok(graphML.includes(`attr.name="${COOKIE_SCHEMA.sourceAttr}"`))
        assert.ok(graphML.includes(`>${COOKIE_SCHEMA.sourceJs}<`))
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('cookieStore.set write is tagged source=cookie-store', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(makeTestUrl('cookie-store.html'), testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 1)

        const graphML = await readFile(join(testDir, files[0]), 'UTF-8')

        const cookieWrite = graphML.match(/store-cookie=storeval-[0-9]+/g) || []
        assert.equal(cookieWrite.length, 1)
        assert.ok(graphML.includes(`attr.name="${COOKIE_SCHEMA.sourceAttr}"`))
        assert.ok(graphML.includes(`>${COOKIE_SCHEMA.sourceCookieStore}<`))
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    // The Set-Cookie HTTP channel (CookieSource::kHTTP / "set-cookie-header").
    // The renderer never sees the raw Set-Cookie (the network service strips it
    // before responses reach Blink), so the crawler captures it over CDP
    // (Network.responseReceivedExtraInfo) and synthesizes the storage-set edge
    // into the graphml during the header-stitching rewrite.
    it('Set-Cookie response header is tagged source=set-cookie-header',
      async () => {
        const testDir = await _createTempOutputDir()
        try {
          await _crawlUrl(setCookieUrl, testDir)
          const files = await _readGraphs(testDir)
          assert.equal(files.length, 1)

          const graphML = await readFile(join(testDir, files[0]), 'UTF-8')

          assert.ok(graphML.includes(`${setCookieName}=${setCookieValue}`))
          assert.ok(graphML.includes(`attr.name="${COOKIE_SCHEMA.sourceAttr}"`))
          assert.ok(graphML.includes(`>${COOKIE_SCHEMA.sourceSetCookieHeader}<`))
        } finally {
          await _cleanupTempOutputDir(testDir)
        }
      })

    it('crypto/encoding-derived value is set via JS', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(makeTestUrl('cookie-derived.html'), testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 1)

        const graphML = await readFile(join(testDir, files[0]), 'UTF-8')

        // The digest of a random seed is non-deterministic, so assert on the
        // cookie name, not the value. The value is written via document.cookie,
        // so it carries source=js. The data + encoding that produced the value
        // (TextEncoder.encode -> crypto.subtle.digest -> btoa) are recoverable
        // from the WebAPI call/result edges PageGraph records for the same
        // script, ordered by timestamp — i.e. read from the graph, not a
        // dedicated attribute.
        assert.ok(graphML.includes('derived-cookie='))
        assert.ok(graphML.includes(`attr.name="${COOKIE_SCHEMA.sourceAttr}"`))
        assert.ok(graphML.includes(`>${COOKIE_SCHEMA.sourceJs}<`))

        // The encoding boundary is now instrumented (btoa / TextEncoder added
        // to the WebAPI tracked-items whitelist), so the graph records those
        // calls and their results. This is what makes the pre-cipher value
        // observable for scripts that hand-roll serialization instead of using
        // JSON.stringify.
        assert.ok(graphML.includes('btoa'), 'btoa WebAPI call is recorded')
        assert.ok(
          graphML.includes('TextEncoder'),
          'TextEncoder.encode WebAPI call is recorded')

        // Provenance linkage: the exact value written to the cookie is the
        // output of btoa(), which is now captured as a WebAPI result edge. The
        // same base64 string therefore appears at least twice — once as the
        // btoa result, once in the cookie write — proving the value can be
        // traced back to the encoding boundary without decrypting anything.
        const derived = graphML.match(/derived-cookie=([A-Za-z0-9+/=]+)/)
        assert.ok(derived, 'derived-cookie value present')
        const occurrences = graphML.split(derived[1]).length - 1
        assert.ok(
          occurrences >= 2,
          `derived value linked to btoa result (saw ${occurrences})`)
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('records a JS stack trace on cookie-write edges', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(makeTestUrl('cookie-async-stacks.html'), testDir)
        const files = await _readGraphs(testDir)
        assert.equal(files.length, 1)

        const graphML = await readFile(join(testDir, files[0]), 'UTF-8')

        // The engine declares the "stack trace" edge attribute and emits it on
        // every edge produced by executing script.
        assert.ok(
          graphML.includes('attr.name="stack trace"'),
          'stack trace attribute is declared')

        // The synchronous nested write (outerSetter -> innerSetter ->
        // document.cookie) should carry a stack naming both functions.
        assert.ok(
          graphML.includes('innerSetter'),
          'stack trace names innerSetter')
        assert.ok(
          graphML.includes('outerSetter'),
          'stack trace names outerSetter')

        // The cookie writes from the timer and promise callbacks should carry an
        // async parent chain, recovered because async call-stack depth is forced
        // on isolate-wide.
        assert.ok(
          graphML.includes('"parent"'),
          'stack trace includes an async parent chain')
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })
  })

  // Instrumentation added to the PageGraph engine itself (brave_page_graph).
  // These fail against an engine build that predates those changes.
  describe('engine instrumentation', () => {
    it('records a script position on cookie READ edges', async () => {
      const testDir = await _createTempOutputDir()
      try {
        // page-cookie-consumers.js reads `document.cookie` into a local.
        await _crawlUrl(makeTestUrl('cookie-consumers.html'), testDir)
        const files = await _readGraphs(testDir)
        const graphML = await readFile(join(testDir, files[0]), 'UTF-8')

        const posKey = edgeAttrKey(graphML, 'script position')
        assert.ok(posKey, 'the script position attribute is declared')

        // Reads previously carried no offset at all, forcing consumers to
        // recover the call site from the stack trace — which fails whenever a
        // frame's script has no recorded source.
        const readEdges = edgesOfType(graphML, 'read storage call')
        assert.ok(readEdges.length >= 1, 'a cookie read edge was recorded')
        const withPosition = readEdges.filter(
          (body) => dataValue(body, posKey) !== null)
        assert.equal(withPosition.length, readEdges.length,
          'every read edge carries a script position')

        // The offset must point at the reading statement, not merely exist.
        const source = await readFile(
          './test/pages/resources/page-cookie-consumers.js', 'UTF-8')
        const offset = Number(dataValue(withPosition[0], posKey))
        assert.ok(offset > 0, 'the offset is non-zero')
        assert.ok(source.slice(offset).startsWith('cookie'),
          `offset ${offset} lands on the .cookie read, not elsewhere`)
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('emits the response body hash on request complete edges', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(makeTestUrl('har-subresources.html'), testDir)
        const files = await _readGraphs(testDir)
        const graphML = await readFile(join(testDir, files[0]), 'UTF-8')

        const hashKey = edgeAttrKey(graphML, 'response hash')
        assert.ok(hashKey, 'the response hash attribute is declared')

        // The engine has always computed this SHA-256 and handed it to the edge,
        // but never emitted it, so the attribute had no producer.
        const completeEdges = edgesOfType(graphML, 'request complete')
        assert.ok(completeEdges.length >= 1, 'a request completed')
        const hashed = completeEdges
          .map((body) => dataValue(body, hashKey))
          .filter((v) => v)
        assert.ok(hashed.length >= 1, 'at least one response carries a hash')
        assert.ok(hashed.every((h) => /^[A-Za-z0-9+/]+=*$/.test(h)),
          'hashes are base64')
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('records postMessage payloads across every messaging surface',
      async () => {
        const testDir = await _createTempOutputDir()
        try {
          await _crawlUrl(makeTestUrl('post-message.html'), testDir)
          const files = await _readGraphs(testDir)
          const graphML = await readFile(join(testDir, files[0]), 'UTF-8')

          // Cross-frame identifier passing was previously invisible: "cross DOM"
          // edges are the frame-owner-to-document structural link and carry no
          // payload at all.
          const argsKey = edgeAttrKey(graphML, 'args')
          const posKey = edgeAttrKey(graphML, 'script position')
          const webApiNames = webApiMethodsByNode(graphML)

          const sends = new Map()
          for (const edge of edgeElements(graphML)) {
            const method = webApiNames.get(edge.target)
            if (!method || !method.includes('postMessage')) continue
            sends.set(method, {
              args: dataValue(edge.body, argsKey),
              position: dataValue(edge.body, posKey)
            })
          }

          for (const surface of [
            'Window.postMessage', 'MessagePort.postMessage',
            'Worker.postMessage', 'BroadcastChannel.postMessage'
          ]) {
            const send = sends.get(surface)
            assert.ok(send, `${surface} was recorded`)
            assert.ok(send.args, `${surface} carries its arguments`)
            // The payload is an object, so this also proves structured data
            // serializes as real JSON rather than degrading to [object Object].
            assert.ok(send.args.includes(postMessageSyncId),
              `${surface} payload contains the identifier`)
            assert.ok(!send.args.includes('[object Object]'),
              `${surface} payload is not stringified to [object Object]`)
            assert.ok(Number(send.position) > 0,
              `${surface} carries a call-site offset`)
          }
        } finally {
          await _cleanupTempOutputDir(testDir)
        }
      })
  })

  describe('capture modes', () => {
    it('--save-cookies writes a cookie inventory sidecar', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(makeTestUrl('cookie-document.html'), testDir, {
          '--save-cookies': null
        })
        const files = await _readCrawlResults(testDir)
        const cookiesFile = files.find((f) => f.endsWith('.cookies.json'))
        assert.ok(cookiesFile, 'a .cookies.json sidecar was written')

        const inventory = JSON.parse(
          await readFile(join(testDir, cookiesFile), 'UTF-8'))
        assert.ok(Array.isArray(inventory), 'inventory is an array')
        assert.ok(
          inventory.some((c) => c.name === 'doc-cookie'),
          'inventory includes the JS-set cookie')
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('--save-cookies writes a per-cookie network map', async () => {
      const testDir = await _createTempOutputDir()
      try {
        // page-cookies.js sets `test-cookie` (CookieStore) then makes an image
        // request to document.svg that carries it in the outgoing Cookie header.
        await _crawlUrl(makeTestUrl('cookies.html'), testDir, {
          '--save-cookies': null
        })
        const files = await _readCrawlResults(testDir)
        const netFile = files.find((f) => f.endsWith('.cookie-network.json'))
        assert.ok(netFile, 'a .cookie-network.json sidecar was written')

        const network = JSON.parse(
          await readFile(join(testDir, netFile), 'UTF-8'))
        const entry = network['test-cookie']
        assert.ok(entry, 'network map includes test-cookie')
        assert.ok(
          Array.isArray(entry.sentTo) && entry.sentTo.length >= 1,
          'test-cookie was carried by at least one request')
        assert.ok(
          entry.sentTo.some((s) => s.url && s.url.includes('document.svg')),
          'a request carrying test-cookie names the resource URL')
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('records request bodies, proving a cookie value left in a POST',
      async () => {
        const testDir = await _createTempOutputDir()
        try {
          await _crawlUrl(makeTestUrl('cookie-exfil-post.html'), testDir)
          const files = await _readCrawlResults(testDir)
          const bodiesFile = files.find((f) => f.endsWith('.bodies.ndjson'))
          assert.ok(bodiesFile, 'a .bodies.ndjson sidecar was written')

          const records = (await readFile(join(testDir, bodiesFile), 'UTF-8'))
            .trim().split('\n').map((line) => JSON.parse(line))
          assert.ok(records.length > 0, 'the sidecar has records')

          // The value only ever appears in a request body, never in a URL,
          // header, or JS argument, so this is unprovable from the graph alone.
          const leaks = records.filter((r) =>
            r.kind === 'request' && r.body && r.body.includes(exfilCookieValue))
          assert.ok(
            leaks.length >= 2,
            'the cookie value was captured leaving in the JSON and beacon ' +
            `bodies (found ${leaks.length})`)
          assert.ok(
            leaks.every((r) => r.url.includes('/collect')),
            'every leak names the sink URL')
          assert.ok(
            leaks.every((r) => r.method === 'POST'),
            'every leak was a POST')

          // Encoded variants must be caught too, so check the base64 channel
          // separately: it does not contain the raw value at all.
          const b64 = Buffer.from(exfilCookieValue).toString('base64')
          assert.ok(
            records.some((r) => r.kind === 'request' && r.body &&
              r.body.includes(b64)),
            'the base64-encoded exfiltration channel was captured')

          // Every record carries identity even when content was not kept, so a
          // dropped body is never confused with an unobserved request.
          assert.ok(
            records.every((r) => typeof r.size === 'number'),
            'every record has a size')
          assert.ok(
            records.every((r) => r.body === undefined || r.sha256),
            'every stored body has a hash')
        } finally {
          await _cleanupTempOutputDir(testDir)
        }
      })

    it('--no-save-bodies suppresses the body sidecar', async () => {
      const testDir = await _createTempOutputDir()
      try {
        await _crawlUrl(makeTestUrl('cookie-exfil-post.html'), testDir, {
          '--no-save-bodies': null
        })
        const files = await _readCrawlResults(testDir)
        assert.ok(
          !files.some((f) => f.includes('.bodies.ndjson')),
          'no body sidecar is written when bodies are disabled')
      } finally {
        await _cleanupTempOutputDir(testDir)
      }
    })

    it('attributes each redirect hop\'s Set-Cookie to the hop that sent it',
      async () => {
        const testDir = await _createTempOutputDir()
        try {
          // A subresource redirect chain: all hops share one request id, and
          // each of the first two hops sets its own cookie. Storing response
          // metadata per request id rather than per hop loses one cookie
          // entirely and blames the other on the chain's final URL.
          await _crawlUrl(
            makeTestUrl('redirect-subresource-chain.html'), testDir, {
              '--save-cookies': null
            })
          const files = await _readCrawlResults(testDir)

          const redirectsFile = files.find((f) => f.endsWith('.redirects.json'))
          assert.ok(redirectsFile, 'a .redirects.json sidecar was written')
          const chains = JSON.parse(
            await readFile(join(testDir, redirectsFile), 'UTF-8'))
          const chain = Object.values(chains).find((hops) =>
            hops.some((h) => h.url.includes('/hop1')))
          assert.ok(chain, 'the chain starting at /hop1 was recorded')
          assert.strictEqual(chain.length, 3, 'all three hops were kept')
          assert.ok(chain[0].url.endsWith('/hop1'), 'hop 0 is /hop1')
          assert.strictEqual(chain[0].status, 302, 'hop 0 answered 302')
          assert.strictEqual(chain[1].status, 302, 'hop 1 answered 302')
          assert.strictEqual(chain[2].status, 200, 'the last hop answered 200')

          const netFile = files.find((f) => f.endsWith('.cookie-network.json'))
          const network = JSON.parse(
            await readFile(join(testDir, netFile), 'UTF-8'))

          // Both cookies survive, and each names its own setter rather than the
          // chain's final URL.
          for (const [name, hopPath] of [
            [hopCookieName, '/hop1'], [hop2CookieName, '/hop2']
          ]) {
            const entry = network[name]
            assert.ok(entry, `network map includes ${name}`)
            assert.ok(
              entry.setBy.length >= 1, `${name} has a recorded setter`)
            assert.ok(
              entry.setBy.some((s) => s.url && s.url.endsWith(hopPath)),
              `${name} is attributed to ${hopPath}, not the chain's final URL`)
          }
        } finally {
          await _cleanupTempOutputDir(testDir)
        }
      })
  })

  describe('graph analysis', () => {
    it('cookie-reads.mjs reports read sites + network and non-network consumers',
      async () => {
        const testDir = await _createTempOutputDir()
        try {
          // page-cookie-consumers.js reads `consumed` then feeds the value into
          // fetch(url+value) (network sink) and JSON.parse (plain consumer).
          await _crawlUrl(makeTestUrl('cookie-consumers.html'), testDir)
          const files = await _readCrawlResults(testDir)
          const graphml = files.find((f) => f.endsWith('.graphml'))
          assert.ok(graphml, 'a graphml was produced')

          const out = execFileSync('node',
            ['analysis/cookie-reads.mjs', join(testDir, graphml), 'consumed'],
            { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
          const detail = JSON.parse(out)

          assert.ok(detail.readers.length >= 1,
            'the reading script is reported')
          const net = detail.consumers.find((c) => c.isNetworkSink)
          assert.ok(net, 'a network-sink consumer is reported')
          assert.ok(/fetch/i.test(net.method), 'network sink is a fetch')
          const plain = detail.consumers.find(
            (c) => !c.isNetworkSink && /json/i.test(c.method))
          assert.ok(plain, 'a non-network consumer (JSON.parse) is reported')
        } finally {
          await _cleanupTempOutputDir(testDir)
        }
      })

    it('cookie-exfiltration.mjs proves a cookie value left in a request body',
      async () => {
        const testDir = await _createTempOutputDir()
        try {
          await _crawlUrl(makeTestUrl('cookie-exfil-post.html'), testDir)
          const files = await _readCrawlResults(testDir)
          const graphml = files.find((f) => f.endsWith('.graphml'))
          const bodies = files.find((f) => f.endsWith('.bodies.ndjson'))
          assert.ok(graphml, 'a graphml was produced')
          assert.ok(bodies, 'a bodies sidecar was produced')

          const out = execFileSync('node', [
            'analysis/cookie-exfiltration.mjs',
            join(testDir, graphml), join(testDir, bodies), '--json'
          ], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
          const report = JSON.parse(out)

          const hits = report.findings['exfil-cookie']
          assert.ok(hits, 'exfil-cookie is reported as leaking')
          // Three channels: a JSON fetch, sendBeacon, and a base64 XHR.
          assert.ok(hits.length >= 3,
            `all exfiltration channels are found (got ${hits.length})`)
          assert.ok(hits.every((h) => h.kind === 'request'),
            'only outbound bodies are reported by default')
          assert.ok(hits.every((h) => h.url.includes('/collect')),
            'every hit names the collector URL')
          assert.ok(hits.some((h) => h.encoding === 'base64'),
            'the base64-encoded channel is decoded and matched')
          assert.ok(hits.some((h) => h.encoding === 'raw'),
            'the raw channels are matched')
          assert.ok(hits.every((h) => h.value === exfilCookieValue),
            'the reported value is the cookie value, not the whole jar')
        } finally {
          await _cleanupTempOutputDir(testDir)
        }
      })
  })
})
