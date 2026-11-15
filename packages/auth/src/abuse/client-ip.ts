/** Default number of proxies that append to X-Forwarded-For */
const DEFAULT_TRUSTED_PROXY_HOPS = 1

/**
 * How to determine the client IP of a request.
 */
export interface ClientIpOptions {
  /**
   * How many proxies append to `X-Forwarded-For` between the client and the
   * app (default 1). The address that many hops from the right is the one the
   * nearest trusted proxy observed; anything left of it is client-supplied and
   * spoofable.
   */
  trustedProxyHops?: number
  /**
   * Read the client IP from `cf-connecting-ip` first (default false). Set it
   * only when every request reaches the app through Cloudflare: any other
   * proxy forwards the header exactly as the client sent it, so trusting it
   * there lets a caller pick a fresh IP per request. Without it, the
   * address comes from `x-forwarded-for`, which Cloudflare also appends to.
   */
  trustCloudflare?: boolean
  /**
   * Determine the client IP yourself, bypassing header inspection entirely.
   * Use this when the runtime exposes the peer address (e.g. a Node server
   * that tracks `socket.remoteAddress`).
   */
  getClientIp?: (request: Request) => string | null
}

/**
 * Best-effort client IP from the usual proxy headers: `cf-connecting-ip`
 * (only with `trustCloudflare`), then `x-forwarded-for`, then `x-real-ip`.
 * A header value comes back lowercase with any `:port`, IPv6 brackets, and
 * IPv6 zone removed; a `getClientIp` option's result comes back as is. Per-IP
 * limits then count the address under {@link ipRateLimitKey}, which groups
 * IPv6 by /64.
 *
 * These headers are trivially spoofable unless a proxy in front of the app
 * overwrites them, so IP-derived limits are one layer among several — never
 * the only one. Returns null when no header is present. Initiate routes then
 * skip their per-IP limits (per-identifier limits still apply); routes marked
 * `rateLimitByIp` count the call against one shared "unknown" bucket.
 */
export function getClientIp(
  request: Request,
  options: ClientIpOptions = {},
): string | null {
  if (options.getClientIp) return options.getClientIp(request)

  if (options.trustCloudflare) {
    const cloudflare = request.headers.get("cf-connecting-ip")
    if (cloudflare?.trim()) return normalizeAddress(cloudflare)
  }

  const forwardedFor = request.headers.get("x-forwarded-for")
  if (forwardedFor) {
    const hops = forwardedFor
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean)
    if (hops.length > 0) {
      const trustedHops = options.trustedProxyHops ?? DEFAULT_TRUSTED_PROXY_HOPS
      const index = hops.length - trustedHops
      const hop = hops[index] ?? hops[0]
      return hop ? normalizeAddress(hop) : null
    }
  }

  const realIp = request.headers.get("x-real-ip")
  if (realIp?.trim()) return normalizeAddress(realIp)

  return null
}

const IPV6_HEXTETS = 8
/** Hextets in an IPv6 /64 prefix */
const IPV6_PREFIX_HEXTETS = 4
const IPV4_MAPPED_PREFIX = "::ffff:"
const IPV4_WITH_PORT = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/
const BRACKETED_IPV6 = /^\[([^\]]+)\](?::\d+)?$/
const HEXTET = /^[0-9a-f]{1,4}$/

/**
 * One header value as a bare, lowercase address: drops a `:port` suffix
 * (IIS/ARR, Azure App Service and Front Door append one to
 * `X-Forwarded-For`), IPv6 brackets, and an IPv6 zone. A bare IPv6 address
 * keeps its colons; they are not a port separator.
 */
function normalizeAddress(raw: string): string {
  const value = raw.trim().toLowerCase()
  const bracketed = BRACKETED_IPV6.exec(value)
  const address = bracketed?.[1] ?? IPV4_WITH_PORT.exec(value)?.[1] ?? value
  return address.split("%")[0] ?? address
}

/**
 * The hextets of an IPv6 address, expanded to eight, or null if it is not
 * one. Expects a lowercase address with no port, zone, or embedded IPv4.
 */
function ipv6Hextets(address: string): string[] | null {
  const halves = address.split("::")
  if (halves.length > 2) return null
  const [head = "", tail] = halves
  const left = head ? head.split(":") : []
  const right = tail ? tail.split(":") : []
  const missing = IPV6_HEXTETS - left.length - right.length
  if (tail === undefined ? missing !== 0 : missing < 1) return null
  const hextets = [...left, ...Array<string>(missing).fill("0"), ...right]
  if (!hextets.every((hextet) => HEXTET.test(hextet))) return null
  return hextets.map((hextet) => parseInt(hextet, 16).toString(16))
}

/**
 * The key a per-IP rate limit counts an address under. IPv6 addresses key
 * on their /64, because one host or customer is usually handed a whole /64
 * and could otherwise rotate through 2^64 buckets; every spelling of an
 * address in it (case, zero compression) gets the same key. An
 * IPv4-mapped IPv6 address (`::ffff:203.0.113.7`, how a dual-stack Node
 * listener reports IPv4 peers) keys as its IPv4 address. Anything else,
 * IPv4 included, keys as its normalized self.
 */
export function ipRateLimitKey(ip: string): string {
  const address = normalizeAddress(ip)
  if (address.startsWith(IPV4_MAPPED_PREFIX)) {
    const ipv4 = address.slice(IPV4_MAPPED_PREFIX.length)
    if (ipv4.includes(".")) return ipv4
  }
  if (!address.includes(":")) return address
  const hextets = ipv6Hextets(address)
  if (!hextets) return address
  return `${hextets.slice(0, IPV6_PREFIX_HEXTETS).join(":")}::/64`
}
