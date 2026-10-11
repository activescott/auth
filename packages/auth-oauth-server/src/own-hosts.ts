/** Lowercase host without a trailing dot, so `Example.com.` equals `example.com`. */
export function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.+$/, "")
}

/**
 * Parse an `ownHosts` entry the way the issuer's host is parsed, so an
 * internationalized name becomes its `xn--` form and `Files.Example.`
 * becomes `files.example`. Throws on anything but a bare host name: a
 * scheme, port, path, userinfo, query, wildcard, leading dot or surrounding
 * space would otherwise leave an entry that never matches.
 */
export function parseOwnHost(entry: string): string {
  const refuse = () =>
    new Error(
      `ownHosts entry ${JSON.stringify(entry)} must be a bare host name, such as files.example`,
    )
  if (
    entry.trim() !== entry ||
    entry.startsWith(".") ||
    /[*/?#@\\]/.test(entry) ||
    entry.replace(/^\[[^\]]*\]/, "").includes(":")
  ) {
    throw refuse()
  }
  let url: URL
  try {
    url = new URL(`https://${entry}`)
  } catch {
    throw refuse()
  }
  if (
    url.port ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    !url.hostname
  ) {
    throw refuse()
  }
  return normalizeHost(url.hostname)
}

/**
 * Whether a host is one of the app's own or a subdomain of one. Subdomains
 * count because apps often serve user content on them (`pages.example.com`),
 * and a client hosted there could borrow the app's name on the consent page.
 */
export function isOwnHost(
  host: string,
  ownHosts: ReadonlySet<string>,
): boolean {
  const normalized = normalizeHost(host)
  for (const own of ownHosts) {
    if (normalized === own || normalized.endsWith(`.${own}`)) return true
  }
  return false
}
