// Exercises the Cookie Store API channel (window.cookieStore.set) for
// cookie-provenance instrumentation. The PageGraph engine should record this
// async write as a cookie set tagged with source=cookie-store.
(async () => {
  const CS = window.cookieStore

  const randInt = Math.floor(Math.random() * 100000)
  const cookieName = 'store-cookie'
  const cookieValue = `storeval-${randInt}`

  await CS.set(cookieName, cookieValue)
})()
