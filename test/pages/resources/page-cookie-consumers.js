// Sets a cookie, reads it back via document.cookie, then feeds the read value
// into two consumers: a network sink (fetch, value in the URL) and a plain
// consumer function (JSON.parse). Exercises analysis/cookie-reads.mjs.
(() => {
  const D = window.document
  D.cookie = 'consumed=abc123def456; path=/'

  // Read the whole jar and extract this cookie's value.
  const jar = D.cookie
  const match = jar.match(/consumed=([^;]+)/)
  const value = match ? match[1] : ''

  // Network-sink consumer: the read value goes into a request URL.
  fetch('/resources/document.svg?leak=' + value)

  // Non-network consumer: an ordinary function that receives the read value.
  try {
    JSON.parse('{"copied":"' + value + '"}')
  } catch (_) { /* ignore */ }
})()
