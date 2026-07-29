// Exercises the "pass 2 needed" case: a cookie whose value is produced by a
// HAND-ROLLED cipher (XOR + hex, entirely in JS — never touches btoa /
// TextEncoder / crypto.subtle). So the plaintext never crosses a Web API
// boundary and cannot be recovered from the graph's call/result edges: pass 1
// sees only the ciphertext + provenance (source=js, built by encryptSecret),
// and only a pass-2 breakpoint that reads scope can recover the plaintext.

function toHex(bytes) {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes.charCodeAt(i).toString(16).padStart(2, '0')
  }
  return hex
}

function encryptSecret(plaintext, key) {
  let xored = ''
  for (let i = 0; i < plaintext.length; i++) {
    xored += String.fromCharCode(
      plaintext.charCodeAt(i) ^ key.charCodeAt(i % key.length),
    )
  }
  return toHex(xored)
}

(() => {
  // This plaintext only ever exists as a JS local; the cookie gets the cipher.
  const secret = 'user-12345-plaintext'
  const ciphertext = encryptSecret(secret, 'k3y')
  document.cookie = 'enc-cookie=' + ciphertext
})()
