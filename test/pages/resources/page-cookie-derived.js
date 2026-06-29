// Exercises a crypto/encoding-derived cookie value. The value written to the
// cookie is the base64 encoding of a SHA-256 digest of a seed string. The
// PageGraph engine should record the encoding/crypto WebAPI calls
// (TextEncoder.encode -> crypto.subtle.digest -> btoa) performed by this
// script before the cookie write, so the provenance path into the cookie
// value is reconstructable.
//
// Note: a SHA-256 digest of a random seed is non-deterministic across runs,
// so tests assert on the cookie *name* (`derived-cookie`) and on the presence
// of the crypto/encoding provenance, not on the exact value.
(async () => {
  const D = window.document

  const randInt = Math.floor(Math.random() * 100000)
  const seed = `derived-seed-${randInt}`

  const seedBytes = new TextEncoder().encode(seed)
  const digest = await window.crypto.subtle.digest('SHA-256', seedBytes)
  const digestBytes = new Uint8Array(digest)
  const b64 = window.btoa(String.fromCharCode(...digestBytes))

  D.cookie = `derived-cookie=${b64}`
})()
