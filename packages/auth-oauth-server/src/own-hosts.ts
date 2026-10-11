/** Lowercase host without a trailing dot, so `Example.com.` equals `example.com`. */
export function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.+$/, "")
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
