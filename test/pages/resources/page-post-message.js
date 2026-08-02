// Passes an identifier across every postMessage surface.
//
// Cross-frame identifier passing used to be invisible: "cross DOM" edges are the
// frame-owner-to-document structural link and carry no payload, so a value handed
// to another frame left no trace. Each send below should now appear as a `js call`
// edge whose `args` attribute contains the syncId.
//
// The payload is an object, not a string, on purpose: it checks that structured
// data serializes to real JSON rather than degrading to "[object Object]".

const syncId = 'pmsync-91241-zzz'

// 1. window.postMessage to self.
window.postMessage({ channel: 'window', id: syncId }, '*')

// 2. window.postMessage into a same-origin child frame.
const frame = document.getElementById('child')
frame.addEventListener('load', () => {
  frame.contentWindow.postMessage({ channel: 'iframe', id: syncId }, '*')
})

// 3. MessageChannel port.
const channel = new MessageChannel()
channel.port1.postMessage({ channel: 'port', id: syncId })

// 4. Dedicated worker.
const workerSource =
  'self.onmessage = (e) => { self.postMessage(e.data) }'
const workerUrl = URL.createObjectURL(
  new Blob([workerSource], { type: 'text/javascript' }))
const worker = new Worker(workerUrl)
worker.postMessage({ channel: 'worker', id: syncId })

// 5. BroadcastChannel.
new BroadcastChannel('pg-test').postMessage({ channel: 'broadcast', id: syncId })
