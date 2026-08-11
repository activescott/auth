import { test, expect } from "@playwright/test"
import {
  requestSignInCode,
  loginWithSms,
  waitForMinimumFormFill,
} from "./helpers/auth"

test.describe("sms auth", () => {
  test("the phone tab renders the phone form with the +1 prefix", async ({
    page,
  }) => {
    await page.goto("/login?via=sms")
    await expect(page.getByRole("heading", { name: /sign in/i })).toBeVisible()
    await expect(page.getByText("+1")).toBeVisible()
    await expect(page.getByLabel(/mobile phone number/i)).toBeVisible()
    await expect(
      page.getByRole("button", { name: /text me a code/i }),
    ).toBeVisible()
  })

  test("submitting the form returns a success message on the phone tab", async ({
    page,
  }) => {
    await page.goto("/login?via=sms")
    await page.getByLabel(/mobile phone number/i).fill("4155550111")
    await waitForMinimumFormFill(page)
    await page.getByRole("button", { name: /text me a code/i }).click()
    await expect(page).toHaveURL(/via=sms/)
    await expect(page.getByText(/we texted you a sign-in code/i)).toBeVisible()
  })

  test("an invalid phone number shows an error", async ({ page }) => {
    await page.goto("/login?via=sms")
    await page.getByLabel(/mobile phone number/i).fill("notaphone")
    await waitForMinimumFormFill(page)
    await page.getByRole("button", { name: /text me a code/i }).click()
    await expect(page).toHaveURL(/error=/)
    await expect(page.getByText(/error:/i)).toBeVisible()
  })

  test("signing in with the texted code reaches the dashboard", async ({
    page,
  }) => {
    await loginWithSms(page, "+14155550201")
    await expect(
      page.getByRole("heading", { name: /dashboard/i }),
    ).toBeVisible()
    // The identifier appears in the header and the sign-in-methods list
    await expect(page.getByText("+14155550201").first()).toBeVisible()
  })

  test("a wrong code shows an error and does not sign in", async ({ page }) => {
    const { code } = await requestSignInCode(page, "+14155550202")
    const wrongCode = code === "000000" ? "111111" : "000000"

    await page.getByLabel(/enter the code/i).fill(wrongCode)

    await expect(page).toHaveURL(/error=/)
    await expect(page.getByText(/error:/i)).toBeVisible()

    // The error belongs to the phone tab, so the phone tab stays selected —
    // the redirect returns to the submitting page rather than a bare /login
    await expect(page).toHaveURL(/via=sms/)
    await expect(page.getByLabel(/mobile phone number/i)).toBeVisible()

    await page.goto("/dashboard")
    await expect(page).toHaveURL(/\/login/)
  })

  test("the code cannot be replayed after a successful sign-in", async ({
    page,
  }) => {
    const { code } = await requestSignInCode(page, "+14155550203")
    if (!code) throw new Error("no code captured")

    await page.getByLabel(/enter the code/i).fill(code)
    await page.waitForURL("**/dashboard")

    // New browser state, same code: the challenge was consumed
    await page.context().clearCookies()
    await requestSignInCode(page, "+14155550203")
    await page.getByLabel(/enter the code/i).fill(code)
    await expect(page).toHaveURL(/error=/)
  })

  test("the phone number is normalized before texting", async ({ page }) => {
    // Typed punctuation is stripped by the provider's normalization; the
    // message is captured under the clean E.164 form. This drives the raw
    // form (not the E.164 helpers) because messy input is the point.
    await page.goto("/login?via=sms")
    await page.getByLabel(/mobile phone number/i).fill("(415) 555-0204")
    await waitForMinimumFormFill(page)
    await page.getByRole("button", { name: /text me a code/i }).click()
    await expect(page.getByLabel(/enter the code/i)).toBeVisible()

    const response = await page.request.get(
      `/e2e/otp-code?phone=${encodeURIComponent("+14155550204")}`,
      {
        headers: {
          "x-e2e-secret":
            process.env.E2E_MAGIC_LINK_SECRET ?? "e2e_test_magic_link_secret",
        },
      },
    )
    expect(response.ok()).toBe(true)
    const { code } = (await response.json()) as { code?: string }
    expect(code).toMatch(/^[0-9]{6}$/)
  })

  test("logout clears an sms session", async ({ page }) => {
    await loginWithSms(page, "+14155550133")
    await page.goto("/dashboard")
    await Promise.all([
      page.waitForURL("**/"),
      page.getByRole("button", { name: /log out/i }).click(),
    ])
    await page.goto("/dashboard")
    await expect(page).toHaveURL(/\/login/)
  })

  test("the sms code endpoint is hidden without the shared secret", async ({
    request,
  }) => {
    const response = await request.get("/e2e/otp-code?phone=%2B14155550100")
    expect(response.status()).toBe(404)
  })
})
