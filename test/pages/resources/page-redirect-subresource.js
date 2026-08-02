// A subresource that redirects through a chain, with a Set-Cookie on the FIRST
// hop — the cookie-syncing pattern: a tracker pixel bounces through partners,
// each dropping an identifier on the way.
//
// Driven by an <img> rather than fetch() on purpose. An image load is not subject
// to CORS, so the browser actually follows the 302s; a cross-origin fetch without
// CORS headers is aborted at the first hop and never redirects at all.
//
// All hops share a single CDP request id, because the network stack follows
// subresource redirects internally. That makes this the fixture where per-hop
// response metadata would be collapsed to the last hop.
// The redirecting listener runs one port above the static server, the same
// convention the test harness uses, so this fixture works under any test port.
const pixel = document.createElement('img')
pixel.src = `http://127.0.0.1:${Number(location.port) + 1}/hop1`
document.body.appendChild(pixel)
