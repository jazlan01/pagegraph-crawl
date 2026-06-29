// Exercises the `document.cookie` setter channel for cookie-provenance
// instrumentation. The PageGraph engine should record this synchronous write
// as a cookie set tagged with source=js.
(() => {
  const D = window.document

  const randInt = Math.floor(Math.random() * 100000)
  const cookieName = 'doc-cookie'
  const cookieValue = `docval-${randInt}`

  D.cookie = `${cookieName}=${cookieValue}`
})()
