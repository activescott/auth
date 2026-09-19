/**
 * The URL of the page a request is for, with React Router's single-fetch
 * details taken back out. Anything that sends the browser back to "this page"
 * (a login `redirectTo`, a pagination link) has to start from here rather
 * than `request.url`.
 *
 * React Router 8 hands loaders and actions the raw request (v7 did too under
 * `future.v8_passThroughRequests`), so a client-side navigation to
 * `/docs/coach` arrives as `/docs/coach.data?_routes=...`. Returning a
 * visitor to that URL serves them the turbo-stream payload instead of the
 * page. The loader's `url` argument holds the clean URL, but these helpers
 * only receive the request, so this repeats React Router's own
 * normalization (`getNormalizedPath` and `createDataFunctionUrl`, which it
 * does not export):
 *
 * - `/a/b.data` → `/a/b`
 * - `/a/b/_.data` → `/a/b/` and `/_.data` → `/` (v8, and v7 with
 *   `future.v8_trailingSlashAwareDataRequests`)
 * - `/_root.data` → `/`, and `/base/_root.data` → `/base/` under a basename
 *   (v7 without that flag)
 * - drops `_routes`, and the valueless `index` React Router adds for index
 *   routes; `index=<value>` is the app's own and stays
 *
 * A plain document URL comes back unchanged, byte for byte: the query is
 * only rebuilt when there is something to drop.
 */
export function pageUrl(request: Request): URL {
  const url = new URL(request.url)

  const { pathname } = url
  if (pathname.endsWith("/_.data")) {
    url.pathname = pathname.slice(0, -"_.data".length)
  } else if (pathname.endsWith("/_root.data")) {
    url.pathname = pathname.slice(0, -"_root.data".length)
  } else if (pathname.endsWith(".data")) {
    url.pathname = pathname.slice(0, -".data".length)
  }

  const params = url.searchParams
  const indexValues = params.getAll("index")
  if (params.has("_routes") || indexValues.includes("")) {
    params.delete("_routes")
    params.delete("index")
    for (const value of indexValues) {
      if (value) params.append("index", value)
    }
  }

  return url
}
