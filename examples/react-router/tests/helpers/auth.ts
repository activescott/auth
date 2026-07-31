import { type Page, expect } from "@playwright/test"

/**
 * E2E auth helpers — drive the real email flow using the app's
 * code-readback route (`/e2e/otp-code`, enabled by E2E_TEST_MODE) instead
 * of an SMTP server or inbox polling. The shared secret gates the route;
 * see `app/routes/e2e.otp-code.tsx`.
 */
const E2E_SECRET =
  process.env.E2E_MAGIC_LINK_SECRET ?? "e2e_test_magic_link_secret"

interface CapturedEmail {
  magicLink: string
  code?: string
}

/**
 * Request a sign-in email via the login form, then return the captured
 * magic link and code for the recipient
 */
export async function requestSignInEmail(
  page: Page,
  email: string,
): Promise<CapturedEmail> {
  await page.goto("/login")
  await page.getByLabel(/email/i).fill(email)
  await page.getByRole("button", { name: /send magic link/i }).click()
  await expect(page.getByLabel(/enter the code/i)).toBeVisible()

  const response = await page.request.get(
    `/e2e/otp-code?email=${encodeURIComponent(email)}`,
    { headers: { "x-e2e-secret": E2E_SECRET } },
  )
  if (!response.ok()) {
    throw new Error(`No captured email for ${email}: ${response.status()}`)
  }
  return (await response.json()) as CapturedEmail
}

/**
 * Log in by clicking the magic link and confirming on the interstitial
 * page — the same path a real user takes from their inbox
 */
export async function loginAs(page: Page, email: string): Promise<void> {
  const { magicLink } = await requestSignInEmail(page, email)

  await page.goto(magicLink)
  await page.getByRole("button", { name: /confirm sign-in/i }).click()
  await page.waitForURL("**/dashboard")
}
