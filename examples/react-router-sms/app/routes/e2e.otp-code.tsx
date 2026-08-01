import { getCapturedSms } from "~/lib/capture-transport.server"
import type { Route } from "./+types/e2e.otp-code"

/**
 * E2E-only endpoint returning the last captured SMS (message + code) for
 * a phone number, so tests can read the code without a phone. Returns 404
 * unless E2E_TEST_MODE=true and the shared secret header matches — never
 * enable E2E_TEST_MODE in production.
 */
export async function loader({ request }: Route.LoaderArgs) {
  if (process.env.E2E_TEST_MODE !== "true") {
    throw new Response("Not Found", { status: 404 })
  }

  const expectedSecret = process.env.E2E_SECRET ?? "e2e_test_secret"
  if (request.headers.get("x-e2e-secret") !== expectedSecret) {
    throw new Response("Not Found", { status: 404 })
  }

  const url = new URL(request.url)
  const phone = url.searchParams.get("phone")
  if (!phone) {
    throw new Response("phone query param is required", { status: 400 })
  }

  const captured = getCapturedSms(phone)
  if (!captured) {
    throw new Response("No SMS captured for that number", { status: 404 })
  }

  return Response.json(captured)
}
