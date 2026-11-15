import { describe, it, expect } from "vitest"
import { getClientIp, ipRateLimitKey } from "../abuse/client-ip.js"

function requestWith(headers: Record<string, string>): Request {
  return new Request("https://example.com/auth/email/initiate", {
    method: "POST",
    headers,
  })
}

describe("getClientIp", () => {
  it("prefers cf-connecting-ip when trustCloudflare is set", () => {
    const request = requestWith({
      "cf-connecting-ip": "203.0.113.7",
      "x-forwarded-for": "198.51.100.1",
      "x-real-ip": "198.51.100.2",
    })

    expect(getClientIp(request, { trustCloudflare: true })).toBe("203.0.113.7")
  })

  it("ignores cf-connecting-ip by default", () => {
    // Any proxy other than Cloudflare forwards the header as the client sent it
    const request = requestWith({
      "cf-connecting-ip": "203.0.113.7",
      "x-forwarded-for": "198.51.100.1",
    })

    expect(getClientIp(request)).toBe("198.51.100.1")
    expect(
      getClientIp(requestWith({ "cf-connecting-ip": "203.0.113.7" })),
    ).toBeNull()
  })

  it("takes the rightmost x-forwarded-for hop by default", () => {
    // A client that spoofs the header still lands left of what the proxy
    // appended
    const request = requestWith({
      "x-forwarded-for": "1.2.3.4, 203.0.113.7",
    })

    expect(getClientIp(request)).toBe("203.0.113.7")
  })

  it("honors trustedProxyHops", () => {
    const request = requestWith({
      "x-forwarded-for": "1.2.3.4, 203.0.113.7, 10.0.0.1",
    })

    expect(getClientIp(request, { trustedProxyHops: 2 })).toBe("203.0.113.7")
  })

  it("falls back to x-real-ip", () => {
    expect(getClientIp(requestWith({ "x-real-ip": "203.0.113.9" }))).toBe(
      "203.0.113.9",
    )
  })

  it("returns null when no header identifies the client", () => {
    expect(getClientIp(requestWith({}))).toBeNull()
  })

  it("uses a supplied getClientIp instead of headers", () => {
    const request = requestWith({ "cf-connecting-ip": "203.0.113.7" })

    expect(getClientIp(request, { getClientIp: () => "10.1.2.3" })).toBe(
      "10.1.2.3",
    )
  })

  it("strips a port from the x-forwarded-for hop", () => {
    // IIS/ARR, Azure App Service and Front Door append ip:port, which would
    // otherwise give every connection its own bucket
    expect(
      getClientIp(
        requestWith({ "x-forwarded-for": "1.2.3.4, 203.0.113.7:51234" }),
      ),
    ).toBe("203.0.113.7")
    expect(
      getClientIp(requestWith({ "x-forwarded-for": "[2001:DB8::1]:443" })),
    ).toBe("2001:db8::1")
  })

  it("lowercases IPv6 and keeps a bare IPv6 address whole", () => {
    // Its colons are not a port separator
    expect(getClientIp(requestWith({ "x-forwarded-for": "2001:DB8::A" }))).toBe(
      "2001:db8::a",
    )
    expect(getClientIp(requestWith({ "x-real-ip": "[2001:db8::1]" }))).toBe(
      "2001:db8::1",
    )
  })

  it("strips a port from x-real-ip", () => {
    expect(getClientIp(requestWith({ "x-real-ip": "203.0.113.9:8080" }))).toBe(
      "203.0.113.9",
    )
  })
})

describe("ipRateLimitKey", () => {
  it("keeps an IPv4 address as is", () => {
    expect(ipRateLimitKey("203.0.113.7")).toBe("203.0.113.7")
  })

  it("keys every IPv6 spelling in one /64 the same", () => {
    // One host usually holds a whole /64, so per-address keys let it rotate
    // through 2^64 buckets
    const key = ipRateLimitKey("2001:db8:0:0:1::5")

    expect(key).toBe("2001:db8:0:0::/64")
    expect(ipRateLimitKey("2001:DB8::1")).toBe(key)
    expect(ipRateLimitKey("2001:0db8:0000:0000:ffff::1")).toBe(key)
    expect(ipRateLimitKey("2001:db8::")).toBe(key)
    expect(ipRateLimitKey("2001:db8:0:1::1")).not.toBe(key)
  })

  it("keys an IPv4-mapped IPv6 address as its IPv4 address", () => {
    // Node's socket.remoteAddress reports IPv4 peers this way on a dual-stack
    // listener; a /64 key would put every IPv4 client in one bucket
    expect(ipRateLimitKey("::ffff:203.0.113.7")).toBe("203.0.113.7")
    expect(ipRateLimitKey("::FFFF:203.0.113.7")).toBe("203.0.113.7")
  })

  it("passes through a value it cannot parse, lowercased", () => {
    expect(ipRateLimitKey("Unknown")).toBe("unknown")
    expect(ipRateLimitKey("2001:db8::1::2")).toBe("2001:db8::1::2")
  })
})
