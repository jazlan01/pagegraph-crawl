/* global describe, before, after, it */

import assert from 'node:assert'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { gunzipSync } from 'node:zlib'

import kill from 'tree-kill'

import {
  startServer, createTempOutputDir, cleanupTempOutputDir,
  validateHAR, crawlUrl, readCrawlResults, getExpectedFilename,
  startSetCookieServer, stopSetCookieServer, setCookieName, setCookieValue
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
        const files = await _readCrawlResults(testDir)
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
        const files = await _readCrawlResults(testDir)
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
        const files = await _readCrawlResults(testDir)
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
        const files = await _readCrawlResults(testDir)
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
        const files = await _readCrawlResults(testDir)
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
        const files = await _readCrawlResults(testDir)
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
            const files = await _readCrawlResults(testDir)
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
        const files = await _readCrawlResults(testDir)
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
        const files = await _readCrawlResults(testDir)
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
        const files = await _readCrawlResults(testDir)
        assert.equal(files.length, 2)

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
        const files = await _readCrawlResults(testDir)
        assert.equal(files.length, 2)

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
        const files = await _readCrawlResults(testDir)
        assert.equal(files.length, 2)

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
        const files = await _readCrawlResults(testDir)
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
        const files = await _readCrawlResults(testDir)
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

    // The Set-Cookie HTTP channel (CookieSource::kHTTP / "set-cookie-header")
    // is defined in the engine schema but not yet wired to the network-response
    // path, so this is skipped until that instrumentation lands. The fixture
    // server (setCookieUrl) is in place so the test can be enabled then.
    it.skip('Set-Cookie response header is tagged source=set-cookie-header',
      async () => {
        const testDir = await _createTempOutputDir()
        try {
          await _crawlUrl(setCookieUrl, testDir)
          const files = await _readCrawlResults(testDir)
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
        const files = await _readCrawlResults(testDir)
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
  })
})
