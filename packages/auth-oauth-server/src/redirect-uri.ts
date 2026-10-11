import type { OAuthApplicationType } from "./types.js"

/** Most redirect URIs a client may register. */
export const MAX_REDIRECT_URIS = 10
const MAX_REDIRECT_URI_LENGTH = 2000

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"])

/**
 * Whether a URL's host is loopback: `127.0.0.1`, `[::1]` or `localhost`.
 * OAuth 2.1 §8.4.2 does not recommend `localhost`, since it can resolve off
 * the machine, but the MCP spec's own example uses it.
 */
export function isLoopbackUrl(url: URL): boolean {
  return LOOPBACK_HOSTS.has(url.hostname)
}

/** Parse a URL, or null if it is not one. */
export function parseUrl(value: string): URL | null {
  try {
    return new URL(value)
  } catch {
    return null
  }
}

/**
 * Check one redirect URI a client registers, against the rules for its
 * application type. Returns an error description, or null if it is
 * acceptable.
 */
export function redirectUriProblem(
  value: string,
  applicationType: OAuthApplicationType,
): string | null {
  if (value.length > MAX_REDIRECT_URI_LENGTH) {
    return "redirect_uri is too long"
  }
  const url = parseUrl(value)
  if (!url) return `redirect_uri is not an absolute URL: ${value}`
  if (url.hash || value.includes("#")) {
    return `redirect_uri must not contain a fragment: ${value}`
  }
  if (url.username || url.password) {
    return `redirect_uri must not contain userinfo: ${value}`
  }
  if (applicationType === "native") {
    if (url.protocol !== "http:" || !isLoopbackUrl(url)) {
      return `a native client may only register loopback http redirect URIs: ${value}`
    }
  } else if (url.protocol !== "https:" || isLoopbackUrl(url)) {
    return `a web client may only register https redirect URIs: ${value}`
  }
  return null
}

/**
 * The application type a client's redirect URIs imply, for clients that do
 * not send `application_type`: all loopback is `native`, all https is
 * `web`. Null for a mix, which is refused.
 */
export function inferApplicationType(
  redirectUris: string[],
): OAuthApplicationType | null {
  const urls = redirectUris.map(parseUrl)
  if (urls.every((url) => url !== null && isLoopbackUrl(url))) return "native"
  if (
    urls.every(
      (url) => url !== null && url.protocol === "https:" && !isLoopbackUrl(url),
    )
  ) {
    return "web"
  }
  return null
}

/**
 * Whether a redirect URI sent to the authorization endpoint matches one the
 * client registered. Matching is exact, except that a loopback registration
 * matches on scheme, host, path and query and ignores the port, because a
 * native client picks an ephemeral port per run (OAuth 2.1 §4.1.1, §8.4.2).
 * A requested URI with userinfo or a fragment never matches.
 */
export function matchesRegisteredRedirectUri(
  requested: string,
  registered: string[],
): boolean {
  const url = parseUrl(requested)
  if (!url || url.username || url.password || requested.includes("#")) {
    return false
  }
  return registered.some((candidate) => {
    if (candidate === requested) return true
    const registeredUrl = parseUrl(candidate)
    if (!registeredUrl || !isLoopbackUrl(registeredUrl)) return false
    return (
      url.protocol === registeredUrl.protocol &&
      url.hostname === registeredUrl.hostname &&
      url.pathname === registeredUrl.pathname &&
      url.search === registeredUrl.search
    )
  })
}
