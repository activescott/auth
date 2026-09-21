import { describe, expect, it, vi } from "vitest"
import { applyOriginGate, isCrossOriginMutation } from "../origin-gate.js"

const APP_ORIGIN = "https://app.example.com"
const DEVELOPMENT_ORIGIN = "http://localhost:3000"

function post(url: string, origin?: string): Request {
  const headers = new Headers()
  if (origin !== undefined) headers.set("origin", origin)
  return new Request(url, { method: "POST", headers })
}

describe("isCrossOriginMutation", () => {
  // A proxy that terminates TLS forwards plain HTTP, so the app's socket sees
  // http. The app trusts the proxy, express reads X-Forwarded-Proto: https,
  // and @react-router/express builds request.url from req.protocol, so the URL
  // below is what a real sign-in post arrives as.
  it("admits the browser's own post behind TLS termination", () => {
    expect(
      isCrossOriginMutation(
        post(`${APP_ORIGIN}/auth/email/initiate`, APP_ORIGIN),
      ),
    ).toBe(false)
  })

  // No proxy in dev: the scheme on both sides is http and the port is part of
  // the origin on both sides.
  it("admits the browser's own post in development", () => {
    expect(
      isCrossOriginMutation(
        post(`${DEVELOPMENT_ORIGIN}/auth/email/initiate`, DEVELOPMENT_ORIGIN),
      ),
    ).toBe(false)
  })

  // Without trust proxy the URL stays http while the browser sends https, and
  // every legitimate post looks like an attack. The check cannot tell the two
  // apart, so the app has to keep trusting the proxy.
  it("refuses the browser's own post when the scheme is not forwarded", () => {
    expect(
      isCrossOriginMutation(
        post("http://app.example.com/auth/email/initiate", APP_ORIGIN),
      ),
    ).toBe(true)
  })

  it("refuses a sibling subdomain", () => {
    expect(
      isCrossOriginMutation(
        post(
          `${APP_ORIGIN}/auth/email/initiate`,
          "https://grafana.example.com",
        ),
      ),
    ).toBe(true)
  })

  it("refuses a lookalike host and a different port", () => {
    expect(
      isCrossOriginMutation(
        post(`${APP_ORIGIN}/logout`, "https://app.example.com.evil.test"),
      ),
    ).toBe(true)
    expect(
      isCrossOriginMutation(
        post(`${DEVELOPMENT_ORIGIN}/logout`, "http://localhost:3001"),
      ),
    ).toBe(true)
  })

  it("refuses an opaque or unparseable origin", () => {
    expect(isCrossOriginMutation(post(`${APP_ORIGIN}/logout`, "null"))).toBe(
      true,
    )
    expect(
      isCrossOriginMutation(post(`${APP_ORIGIN}/logout`, "not a url")),
    ).toBe(true)
  })

  it("admits a request with no Origin at all", () => {
    expect(isCrossOriginMutation(post(`${APP_ORIGIN}/logout`))).toBe(false)
  })

  it("ignores GET, so the sign-out link still works", () => {
    const request = new Request(`${APP_ORIGIN}/logout`, {
      headers: { origin: "https://grafana.example.com" },
    })
    expect(isCrossOriginMutation(request)).toBe(false)
  })
})

describe("applyOriginGate", () => {
  it("answers 400, the same as react-router's own check", () => {
    const response = applyOriginGate(
      post(`${APP_ORIGIN}/logout`, "https://grafana.example.com"),
    )
    expect(response?.status).toBe(400)
  })

  it("logs the origin it refused", () => {
    const warn = vi.fn()
    applyOriginGate(
      post(`${APP_ORIGIN}/logout`, "https://grafana.example.com"),
      {
        warn,
      },
    )
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0]?.[1]).toMatchObject({
      origin: "https://grafana.example.com",
    })
  })

  it("falls through on a same-origin post", () => {
    const warn = vi.fn()
    expect(
      applyOriginGate(post(`${APP_ORIGIN}/logout`, APP_ORIGIN), { warn }),
    ).toBeNull()
    expect(warn).not.toHaveBeenCalled()
  })
})
