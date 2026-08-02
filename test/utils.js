import assert from 'node:assert'
import { spawn } from 'node:child_process'
import { rm, readdir } from 'node:fs/promises'
import { createServer } from 'node:http'
import { join } from 'node:path'

import { createTempDir } from '../built/brave/files.js'

export const crawlUrl = (url, outputDir, args = null, binaryPath = null, debug = false) => {
  const crawlCommand = ['run', 'crawl', '--']
  const crawlFlags = {
    '-u': url,
    '-t': 15,
    '-o': outputDir
  }

  if (binaryPath !== null) {
    crawlFlags['--binary'] = binaryPath
  }

  if (debug === true) {
    crawlFlags['--logging'] = 'info'
  }

  if (args !== null) {
    for (const [key, value] of Object.entries(args)) {
      crawlFlags[key] = value
    }
  }

  for (const [cmdKey, cmdValue] of Object.entries(crawlFlags)) {
    crawlCommand.push(cmdKey)
    if (cmdValue) {
      crawlCommand.push(cmdValue)
    }
  }

  if (debug) {
    console.log('Launching crawl child process: npm ' + crawlCommand.join(' '))
  }

  const crawlProcess = spawn('npm', crawlCommand, {
    stdio: debug ? 'inherit' : 'ignore'
  })

  return new Promise(resolve => {
    crawlProcess.on('exit', resolve)
  })
}

export const createTempOutputDir = async (debug = false) => {
  const tempDirPath = await createTempDir()
  if (debug) {
    console.log(`Created temporary directory: ${tempDirPath}`)
  }
  return tempDirPath
}

export const cleanupTempOutputDir = async (outputPath, debug = false) => {
  if (debug) {
    console.log(`Removing temporary directory: ${outputPath}`)
  }
  return await rm(outputPath, { recursive: true, force: true })
}

export const readCrawlResults = async (outputPath, debug = false) => {
  const files = await readdir(outputPath)
  if (debug) {
    const fileNames = JSON.stringify(files)
    console.log(`readCrawlResults: Contents of ${outputPath}: ${fileNames}`)
  }
  return files
}

export const startServer = (port = 8080, debug = false) => {
  const testPagesPath = join(new URL('.', import.meta.url).pathname, 'pages')
  const httpServerCmd = ['http-server', testPagesPath, '-p', port]

  const spawnOptions = {
    stdio: ['ignore', 'pipe', 'inherit']
  }
  if (debug === false) {
    // This is kinda a lot, but unless we're in debug mode, we suppress
    // all warnings from the http-server, in order to suppress
    // the not-helpful-at-all deprecation error.
    const currentEnv = JSON.parse(JSON.stringify(process.env))
    currentEnv.NODE_NO_WARNINGS = '1'
    spawnOptions.env = currentEnv
  }

  const serverProcess = spawn('npx', httpServerCmd, spawnOptions)

  return new Promise((resolve) => {
    let hasResolved = false
    const bootMsg = 'Hit CTRL-C to stop the server'

    serverProcess.stdout.on('data', data => {
      const msg = data.toString()
      const isFirstBootMsg = msg.includes(bootMsg)
      if (debug) {
        process.stdout.write(msg)
      }
      if (isFirstBootMsg && hasResolved === false) {
        hasResolved = true
        resolve(serverProcess)
      }
    })
  })
}

// The static http-server cannot emit a per-response Set-Cookie header, so we
// run a tiny built-in node:http listener on a separate port to exercise the
// server Set-Cookie cookie-set channel. The token below is what tests look
// for in the resulting graphml.
export const setCookieName = 'server-cookie'
export const setCookieValue = 'srvval-91237'

// A cookie set on an intermediate 302 hop. Tests assert this survives into the
// graph, which proves per-hop response metadata is no longer collapsed to the
// last hop of a redirect chain.
export const hopCookieName = 'hop-cookie'
export const hopCookieValue = 'hopval-91238'

// The identifier page-post-message.js hands to every postMessage surface.
export const postMessageSyncId = 'pmsync-91241-zzz'

// The cookie value that page-cookie-exfil.js leaks in request bodies only. Kept
// here so the fixture and its assertions cannot drift apart.
export const exfilCookieName = 'exfil-cookie'
export const exfilCookieValue = 'exval-91239-abcdef'

// A second cookie, set on the SECOND hop. With last-wins per-request-id storage
// only one of the two survives, so asserting on both proves hops accumulate.
export const hop2CookieName = 'hop2-cookie'
export const hop2CookieValue = 'hopval-91240'

export const startSetCookieServer = (port = 8081, debug = false) => {
  const server = createServer((req, res) => {
    if (debug) {
      console.log(`Set-Cookie server request: ${req.method} ${req.url}`)
    }

    // The exfiltration sink. Answers any method, sets no cookie, and permits
    // cross-origin POSTs so the fixture's fetch/sendBeacon actually leave the
    // browser (the fixture is served from a different port, so this is a
    // cross-origin request and would otherwise be blocked at preflight).
    if (req.url.startsWith('/collect')) {
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'content-type'
      }
      if (req.method === 'OPTIONS') {
        res.writeHead(204, corsHeaders)
        res.end()
        return
      }
      // Drain the body so the request completes.
      req.on('data', (chunk) => {
        if (debug) {
          console.log(`  /collect body chunk: ${chunk.toString()}`)
        }
      })
      req.on('end', () => {
        res.writeHead(200, { ...corsHeaders, 'Content-Type': 'application/json' })
        res.end('{"ok":true}')
      })
      return
    }

    // A real HTTP redirect chain: /hop1 -> /hop2 -> /final, with a Set-Cookie on
    // the FIRST hop. All three hops share one CDP request id, which is what makes
    // this different from the JS-redirect fixtures (those are separate
    // navigations) and what exercises per-hop metadata retention.
    if (req.url.startsWith('/hop1')) {
      res.writeHead(302, {
        Location: '/hop2',
        'Access-Control-Allow-Origin': '*',
        'Set-Cookie': `${hopCookieName}=${hopCookieValue}; Path=/`
      })
      res.end()
      return
    }
    if (req.url.startsWith('/hop2')) {
      res.writeHead(302, {
        Location: '/final',
        'Access-Control-Allow-Origin': '*',
        'Set-Cookie': `${hop2CookieName}=${hop2CookieValue}; Path=/`
      })
      res.end()
      return
    }
    if (req.url.startsWith('/final')) {
      // A 1x1 transparent GIF, so the chain can be driven by an <img> — which is
      // not subject to CORS, so the redirect is actually followed rather than
      // blocked at the first hop.
      const gif = Buffer.from(
        'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
        'base64'
      )
      res.writeHead(200, {
        'Content-Type': 'image/gif',
        'Access-Control-Allow-Origin': '*',
        'Content-Length': gif.length
      })
      res.end(gif)
      return
    }

    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Set-Cookie': `${setCookieName}=${setCookieValue}; Path=/`
    })
    res.end('<html><body>set-cookie-test</body></html>')
  })

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      if (debug) {
        console.log(`Set-Cookie server listening on port ${port}`)
      }
      resolve(server)
    })
  })
}

export const stopSetCookieServer = (server) => {
  if (server === undefined || server === null) {
    return Promise.resolve()
  }
  // Drop any lingering keep-alive sockets so close() resolves promptly.
  if (typeof server.closeAllConnections === 'function') {
    server.closeAllConnections()
  }
  return new Promise((resolve) => {
    server.close(() => { resolve() })
  })
}

export const validateHAR = (har) => {
  let parsedHAR
  try {
    parsedHAR = JSON.parse(har)
  } catch (err) {
    throw new Error(`Invalid JSON in file: ${har}`)
  }

  assert.equal(typeof parsedHAR, 'object')
  assert.ok(parsedHAR.log.pages !== undefined)
  assert.ok(parsedHAR.log.entries !== undefined)

  const entries = parsedHAR.log.entries
  assert.ok(Array.isArray(entries))
  assert.ok(entries.length > 0)

  for (const entry of entries) {
    assert.ok(entry.request !== undefined)
    assert.ok(entry.response !== undefined)
    assert.ok(entry.timings !== undefined)

    const request = entry.request
    assert.ok(request.method !== undefined)
    assert.ok(request.url !== undefined)
    assert.ok(request.headers !== undefined)
    assert.ok(Array.isArray(request.headers))
    assert.ok(request.headers.length > 0)

    const response = entry.response
    assert.ok(response.status !== undefined)
    assert.equal(typeof response.status, 'number')
    assert.ok(response.content !== undefined)
    assert.ok(response.content.mimeType !== undefined)
    assert.ok(response.content.size !== undefined)

    const timings = entry.timings
    assert.ok(timings.blocked !== undefined)
    assert.ok(timings.dns !== undefined)
    assert.ok(timings.connect !== undefined)
    assert.ok(timings.send !== undefined)
    assert.ok(timings.wait !== undefined)
    assert.ok(timings.receive !== undefined)
  }

  return parsedHAR
}

export const getExpectedFilename = (url) => {
  const fileNameSafeUrl = url?.replace(/[^\w]/g, '_')
  return `page_graph_${fileNameSafeUrl}`
}
