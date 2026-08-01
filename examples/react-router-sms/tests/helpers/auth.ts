import { type Page, expect } from "@playwright/test"

/**
 * E2E auth helpers — drive the real SMS flow using the app's
 * code-readback route (`/e2e/otp-code`, enabled by E2E_TEST_MODE) instead
 * of a phone. The shared secret gates the route; see
 * `app/routes/e2e.otp-code.tsx`.
 */
const E2E_SECRET = process.env.E2E_SECRET ?? "e2e_test_secret"

interface CapturedSms {
  message: string
  code?: string
}

/**
 * Request a sign-in code via the login form, then return the captured
 * SMS for the phone number
 */
export async function requestSignInCode(
  page: Page,
  phone: string,
): Promise<CapturedSms> {
  await page.goto("/login")
  await page.getByLabel(/mobile phone number/i).fill(phone)
  await page.getByRole("button", { name: /text me a code/i }).click()
  await expect(page.getByLabel(/enter the code/i)).toBeVisible()

  const response = await page.request.get(
    `/e2e/otp-code?phone=${encodeURIComponent(phone)}`,
    { headers: { "x-e2e-secret": E2E_SECRET } },
  )
  if (!response.ok()) {
    throw new Error(`No captured SMS for ${phone}: ${response.status()}`)
  }
  return (await response.json()) as CapturedSms
}

/**
 * Log in by requesting a code and submitting it through the code form —
 * the same path a real user takes from their messages
 */
export async function loginAs(page: Page, phone: string): Promise<void> {
  const { code } = await requestSignInCode(page, phone)
  if (!code) throw new Error("no code captured")

  await page.getByLabel(/enter the code/i).fill(code)
  await Promise.all([
    page.waitForURL("**/dashboard"),
    page.getByRole("button", { name: /sign in with code/i }).click(),
  ])
}
