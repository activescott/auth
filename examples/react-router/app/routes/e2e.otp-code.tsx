import { createCaptureReadbackLoader } from "@activescott/auth-adapter-react-router/testing"
import { captureEmailTransport, captureSmsTransport } from "~/lib/auth.server"

/**
 * E2E-only endpoint returning the last captured message for a recipient
 * (`?email=` for the emailed OTP code + magic link, `?phone=` for the
 * texted code), so tests can read codes without an inbox or a phone.
 * Returns 404 unless E2E_TEST_MODE=true and the `x-e2e-secret` header
 * matches — never enable E2E_TEST_MODE in production. With Twilio Verify
 * configured, `captureSmsTransport` is null (the vendor owns the code), so
 * phone lookups answer 404.
 */
export const loader = createCaptureReadbackLoader({
  transports: { email: captureEmailTransport, sms: captureSmsTransport },
  enabled: process.env.E2E_TEST_MODE === "true",
  secret: process.env.E2E_MAGIC_LINK_SECRET ?? "e2e_test_magic_link_secret",
})
