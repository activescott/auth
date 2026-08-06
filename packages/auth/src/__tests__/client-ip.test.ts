import { describe, it, expect } from "vitest"
import { getClientIp } from "../abuse/client-ip.js"

function requestWith(headers: Record<string, string>): Request {
  return new Request("https://example.com/auth/email/initiate", {
    method: "POST",
    headers,
  })
}

describe("getClientIp", () => {
  it("prefers cf-connecting-ip", () => {
    const request = requestWith({
      "cf-connecting-ip": "203.0.113.7",
      "x-forwarded-for": "198.51.100.1",
      "x-real-ip": "198.51.100.2",
    })

    expect(getClientIp(request)).toBe("203.0.113.7")
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
})
