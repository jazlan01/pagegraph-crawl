// Exercises per-edge JS stack-trace capture. The PageGraph engine records a
// full stack trace (sync frames + async parent chain) on every graph edge that
// is produced by executing script. This fixture drives cookie writes through:
//
//   1. named nested synchronous functions        -> outerSetter -> innerSetter
//   2. a setTimeout callback                      -> async "setTimeout" parent
//   3. a fetch().then() promise-chain callback    -> async "Promise.then" parent
//
// and reads a cookie whose value flows into an outgoing request URL (the
// read -> exfiltration path), so the enriched graph can be walked from a
// storage-read result edge to the request edge that carried it.

function innerSetter(name, value) {
  // The document.cookie write happens here; its stack should name both
  // innerSetter and outerSetter.
  window.document.cookie = `${name}=${value}`
}

function outerSetter(name, value) {
  innerSetter(name, value)
}

const randInt = Math.floor(Math.random() * 100000)

// 1. Synchronous nested call.
outerSetter('sync-cookie', `syncval-${randInt}`)

// 2. Cookie set from inside a timer callback (async "setTimeout" parent).
setTimeout(() => {
  outerSetter('timer-cookie', `timerval-${randInt}`)
}, 0)

// 3. Cookie set from inside a promise-chain callback (async parent).
fetch('/simple.html')
  .then((response) => {
    return response.text()
  })
  .then(() => {
    outerSetter('promise-cookie', `promiseval-${randInt}`)
  })
  .catch(() => {
    // Ignore fetch failures; the crawl still records what ran.
  })

// 4. Read a cookie and send it out in a request URL (read -> exfil).
const readValue = window.document.cookie
void fetch(`/simple.html?leak=${encodeURIComponent(readValue)}`).catch(() => {})
