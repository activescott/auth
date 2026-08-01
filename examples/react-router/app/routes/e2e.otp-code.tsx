import { getCapturedEmail } from "~/lib/capture-email-transport.server"
import { getCapturedSms } from "~/lib/capture-sms-transport.server"
import type { Route } from "./+types/e2e.otp-code"

/**
 * E2E-only endpoint returning the last captured message for a recipient
 * (`?email=` for the emailed OTP code + magic link, `?phone=` for the
 * texted code), so tests can read codes without an inbox or a phone.
 * Returns 404 unless E2E_TEST_MODE=true and the shared secret header
 * matches — never enable E2E_TEST_MODE in production.
 */
export async function loader({ request }: Route.LoaderArgs) {
  if (process.env.E2E_TEST_MODE !== "true") {
    throw new Response("Not Found", { status: 404 })
  }

  const expectedSecret =
    process.env.E2E_MAGIC_LINK_SECRET ?? "e2e_test_magic_link_secret"
  if (request.headers.get("x-e2e-secret") !== expectedSecret) {
    throw new Response("Not Found", { status: 404 })
  }

  const url = new URL(request.url)
  const email = url.searchParams.get("email")
  const phone = url.searchParams.get("phone")

  if (email) {
    const captured = getCapturedEmail(email)
    if (!captured) {
      throw new Response("No email captured for that address", { status: 404 })
    }
    return Response.json(captured)
  }

  if (phone) {
    const captured = getCapturedSms(phone)
    if (!captured) {
      throw new Response("No SMS captured for that number", { status: 404 })
    }
    return Response.json(captured)
  }

  throw new Response("email or phone query param is required", { status: 400 })
}
