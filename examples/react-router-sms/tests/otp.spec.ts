import {
  test,
  expect,
  type Page,
  type APIRequestContext,
} from "@playwright/test"

const E2E_SECRET = process.env.E2E_SECRET ?? "e2e_test_secret"

async function requestCode(page: Page, phone: string): Promise<void> {
  await page.goto("/login")
  await page.getByLabel(/mobile phone number/i).fill(phone)
  await page.getByRole("button", { name: /text me a code/i }).click()
  await expect(page.getByLabel(/enter the code/i)).toBeVisible()
}

async function fetchTextedCode(
  request: APIRequestContext,
  phone: string,
): Promise<string> {
  const response = await request.get(
    `/e2e/otp-code?phone=${encodeURIComponent(phone)}`,
    { headers: { "x-e2e-secret": E2E_SECRET } },
  )
  expect(response.ok()).toBe(true)
  const { code } = (await response.json()) as { code?: string }
  if (!code) throw new Error("no code captured")
  return code
}

test.describe("sms OTP code", () => {
  test("signing in with the texted code reaches the dashboard", async ({
    page,
    request,
  }) => {
    const phone = "+14155550201"
    await requestCode(page, phone)

    const code = await fetchTextedCode(request, phone)
    await page.getByLabel(/enter the code/i).fill(code)
    await Promise.all([
      page.waitForURL("**/dashboard"),
      page.getByRole("button", { name: /sign in with code/i }).click(),
    ])
    await expect(page.getByText(phone)).toBeVisible()
  })

  test("a wrong code shows an error and does not sign in", async ({
    page,
    request,
  }) => {
    const phone = "+14155550202"
    await requestCode(page, phone)

    const code = await fetchTextedCode(request, phone)
    const wrongCode = code === "000000" ? "111111" : "000000"

    await page.getByLabel(/enter the code/i).fill(wrongCode)
    await page.getByRole("button", { name: /sign in with code/i }).click()

    await expect(page).toHaveURL(/\/login\?error=/)
    await expect(page.getByText(/error:/i)).toBeVisible()

    await page.goto("/dashboard")
    await expect(page).toHaveURL(/\/login/)
  })

  test("the code cannot be replayed after a successful sign-in", async ({
    page,
    request,
  }) => {
    const phone = "+14155550203"
    await requestCode(page, phone)
    const code = await fetchTextedCode(request, phone)

    await page.getByLabel(/enter the code/i).fill(code)
    await Promise.all([
      page.waitForURL("**/dashboard"),
      page.getByRole("button", { name: /sign in with code/i }).click(),
    ])

    // New browser state, same code: the challenge was consumed
    await page.context().clearCookies()
    await requestCode(page, phone)
    await page.getByLabel(/enter the code/i).fill(code)
    await page.getByRole("button", { name: /sign in with code/i }).click()
    await expect(page).toHaveURL(/\/login\?error=/)
  })

  test("the phone number is normalized before texting", async ({
    page,
    request,
  }) => {
    await page.goto("/login")
    await page.getByLabel(/mobile phone number/i).fill("+1 (415) 555-0204")
    await page.getByRole("button", { name: /text me a code/i }).click()
    await expect(page.getByLabel(/enter the code/i)).toBeVisible()

    // Captured under the normalized E.164 form
    const code = await fetchTextedCode(request, "+14155550204")
    expect(code).toMatch(/^[0-9]{6}$/)
  })

  test("the code endpoint is hidden without the shared secret", async ({
    request,
  }) => {
    const response = await request.get("/e2e/otp-code?phone=%2B14155550100")
    expect(response.status()).toBe(404)
  })
})
