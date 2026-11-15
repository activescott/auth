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
    if (cloudflare) return cloudflare.trim()
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
      return hops[index] ?? hops[0] ?? null
    }
  }

  const realIp = request.headers.get("x-real-ip")
  if (realIp) return realIp.trim()

  return null
}
