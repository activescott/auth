import { constantTimeEqual } from "@activescott/auth"

const HTTP_BAD_REQUEST = 400
const HTTP_NOT_FOUND = 404

/** Request header that carries the shared secret */
export const CAPTURE_READBACK_SECRET_HEADER = "x-e2e-secret"

/**
 * What the loader needs from an email capture transport. `CaptureEmailTransport`
 * from `@activescott/auth-provider-email/testing` satisfies it.
 */
export interface EmailCaptureReadback {
  getCapturedEmail(to: string): object | null
}

/**
 * What the loader needs from an SMS capture transport. `CaptureSmsTransport`
 * from `@activescott/auth-provider-sms/testing` satisfies it.
 */
export interface SmsCaptureReadback {
  getCapturedSms(to: string): object | null
}

/** Options for `createCaptureReadbackLoader` */
export interface CaptureReadbackOptions {
  /**
   * The capture transports to read from. Leave one out (or pass null) when it
   * is not wrapped, e.g. SMS through a hosted verification service where the
   * code never reaches this process; lookups for it then answer 404.
   */
  transports: {
    email?: EmailCaptureReadback | null
    sms?: SmsCaptureReadback | null
  }
  /**
   * Serve codes only when this is exactly `true`. Derive it from a flag that
   * only the e2e environment sets, such as `E2E_TEST_MODE === "true"`.
   */
  enabled: boolean
  /**
   * Shared secret the test runner sends in the `x-e2e-secret` header. Required
   * when `enabled` is true; creating the loader throws without one.
   */
  secret: string | undefined
}

/**
 * Create a resource-route loader that returns the last sign-in message a
 * capture transport recorded, so e2e tests can sign in without an inbox or a
 * phone: `GET ?email=<address>` returns `{ magicLink, code }`, `GET
 * ?phone=<E.164>` returns `{ message, code }`, each only with the secret in
 * the `x-e2e-secret` header.
 *
 * Threat model: the response is a live sign-in credential for anyone the
 * attacker names, so this route is account takeover if it is ever reachable
 * in production. It stays closed unless `enabled` is exactly true, and then
 * also requires the secret, compared in constant time. Disabled, wrong-secret
 * and missing-secret requests all get the same bare 404 rather than a 401 or
 * 403, so the route does not advertise itself as a guarded endpoint. `NODE_ENV` is not used as a gate because e2e suites
 * usually run the production build; keep the flag out of production config
 * and only wrap transports in capture transports under the same flag, so a
 * leaked flag alone still has nothing to read.
 *
 * @example
 * ```typescript
 * // app/routes/e2e.otp-code.tsx
 * import { createCaptureReadbackLoader } from "@activescott/auth-adapter-react-router/testing"
 *
 * export const loader = createCaptureReadbackLoader({
 *   transports: { email: captureEmailTransport, sms: captureSmsTransport },
 *   enabled: process.env.E2E_TEST_MODE === "true",
 *   secret: process.env.E2E_MAGIC_LINK_SECRET,
 * })
 * ```
 */
export function createCaptureReadbackLoader(
  options: CaptureReadbackOptions,
): (args: { request: Request }) => Promise<Response> {
  const enabled = options.enabled === true
  const { email, sms } = options.transports
  const secret = options.secret

  if (enabled && !secret) {
    throw new Error(
      "createCaptureReadbackLoader: `secret` is required when `enabled` is true",
    )
  }

  return async ({ request }) => {
    if (!enabled || !secret) return notFound("Not Found")

    const submitted = request.headers.get(CAPTURE_READBACK_SECRET_HEADER)
    if (submitted === null || !(await secretsMatch(submitted, secret))) {
      return notFound("Not Found")
    }

    const url = new URL(request.url)
    const address = url.searchParams.get("email")
    const phone = url.searchParams.get("phone")

    if (address) {
      if (!email) return notFound("Email is not captured in this configuration")
      const captured = email.getCapturedEmail(address)
      if (!captured) return notFound("No email captured for that address")
      return Response.json(captured, { headers: noStore() })
    }

    if (phone) {
      if (!sms) return notFound("SMS is not captured in this configuration")
      const captured = sms.getCapturedSms(phone)
      if (!captured) return notFound("No SMS captured for that number")
      return Response.json(captured, { headers: noStore() })
    }

    return new Response("email or phone query param is required", {
      status: HTTP_BAD_REQUEST,
      headers: noStore(),
    })
  }
}

/**
 * Compare SHA-256 digests rather than the raw strings: `constantTimeEqual`
 * returns early on a length mismatch, which would leak the secret's length.
 */
async function secretsMatch(submitted: string, expected: string) {
  const [a, b] = await Promise.all([sha256Hex(submitted), sha256Hex(expected)])
  return constantTimeEqual(a, b)
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  )
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")
}

function notFound(body: string): Response {
  return new Response(body, { status: HTTP_NOT_FOUND, headers: noStore() })
}

/** Captured codes are credentials; keep them out of every cache */
function noStore(): HeadersInit {
  return { "Cache-Control": "no-store" }
}
