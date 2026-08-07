import { type Page, expect } from "@playwright/test"

/**
 * E2E auth helpers — drive the real email flow using the app's
 * code-readback route (`/e2e/otp-code`, enabled by E2E_TEST_MODE) instead
 * of an SMTP server or inbox polling. The shared secret gates the route;
 * see `app/routes/e2e.otp-code.tsx`.
 */
const E2E_SECRET =
  process.env.E2E_MAGIC_LINK_SECRET ?? "e2e_test_magic_link_secret"

/**
 * The app rejects sign-in requests submitted faster than a human could fill
 * the form (abuse protection; `abuse.minFormFillSeconds` in auth.server.ts).
 * A blocked request looks exactly like a sent one, so a test that skips this
 * wait fails later, at the missing code — wait it out before submitting.
 */
export async function waitForMinimumFormFill(page: Page): Promise<void> {
  await page.waitForTimeout(MIN_FORM_FILL_MS)
}

const MIN_FORM_FILL_MS = 1200

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
  await waitForMinimumFormFill(page)
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

interface CapturedSms {
  message: string
  code?: string
}

/**
 * Request a sign-in code via the phone tab of the login form, then return
 * the captured SMS. Takes the full E.164 number (e.g. "+14155550100");
 * the login UI fixes the +1 prefix, so only the national part is typed
 * into the form — that translation happens here, at the UI boundary, and
 * nowhere else.
 */
export async function requestSignInCode(
  page: Page,
  phone: string,
): Promise<CapturedSms> {
  const nationalNumber = phone.replace(/^\+1/, "")
  await page.goto("/login?via=sms")
  await page.getByLabel(/mobile phone number/i).fill(nationalNumber)
  await waitForMinimumFormFill(page)
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
 * Log in with an E.164 phone number by requesting a texted code and
 * submitting it through the code form — the same path a real user takes
 * from their messages
 */
export async function loginWithSms(page: Page, phone: string): Promise<void> {
  const { code } = await requestSignInCode(page, phone)
  if (!code) throw new Error("no code captured")

  // The code form submits itself once the last digit lands, so filling it is
  // the whole interaction — no button click
  await page.getByLabel(/enter the code/i).fill(code)
  await page.waitForURL("**/dashboard")
}
