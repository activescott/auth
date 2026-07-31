import {
  test,
  expect,
  type Page,
  type APIRequestContext,
} from "@playwright/test"

const E2E_SECRET =
  process.env.E2E_MAGIC_LINK_SECRET ?? "e2e_test_magic_link_secret"

async function requestCode(page: Page, email: string): Promise<void> {
  await page.goto("/login")
  await page.getByLabel(/email/i).fill(email)
  await page.getByRole("button", { name: /send magic link/i }).click()
  await expect(page.getByLabel(/enter the code/i)).toBeVisible()
}

async function fetchEmailedCode(
  request: APIRequestContext,
  email: string,
): Promise<string> {
  const response = await request.get(
    `/e2e/otp-code?email=${encodeURIComponent(email)}`,
    { headers: { "x-e2e-secret": E2E_SECRET } },
  )
  expect(response.ok()).toBe(true)
  const { code } = (await response.json()) as { code?: string }
  if (!code) throw new Error("no code captured")
  return code
}

test.describe("email OTP code", () => {
  test("signing in with the emailed code reaches the dashboard", async ({
    page,
    request,
  }) => {
    const email = "otp-happy@example.com"
    await requestCode(page, email)

    const code = await fetchEmailedCode(request, email)
    await page.getByLabel(/enter the code/i).fill(code)
    await Promise.all([
      page.waitForURL("**/dashboard"),
      page.getByRole("button", { name: /sign in with code/i }).click(),
    ])
    await expect(page.getByText(email)).toBeVisible()
  })

  test("a wrong code shows an error and does not sign in", async ({
    page,
    request,
  }) => {
    const email = "otp-wrong@example.com"
    await requestCode(page, email)

    const code = await fetchEmailedCode(request, email)
    const wrongCode = code === "000000" ? "111111" : "000000"

    await page.getByLabel(/enter the code/i).fill(wrongCode)
    await page.getByRole("button", { name: /sign in with code/i }).click()

    await expect(page).toHaveURL(/\/login\?error=/)
    await expect(page.getByText(/error:/i)).toBeVisible()

    await page.goto("/dashboard")
    await expect(page).toHaveURL(/\/login/)
  })

  test("the magic link shows a confirm page, then signs in on confirm", async ({
    page,
    request,
  }) => {
    const email = "otp-link@example.com"
    await requestCode(page, email)

    const response = await request.get(
      `/e2e/otp-code?email=${encodeURIComponent(email)}`,
      { headers: { "x-e2e-secret": E2E_SECRET } },
    )
    const { magicLink } = (await response.json()) as { magicLink: string }

    // A security scanner prefetching the link (GET) must not consume it
    const scannerFetch = await request.get(magicLink)
    expect(scannerFetch.ok()).toBe(true)

    await page.goto(magicLink)
    await expect(
      page.getByRole("button", { name: /confirm sign-in/i }),
    ).toBeVisible()
    await Promise.all([
      page.waitForURL("**/dashboard"),
      page.getByRole("button", { name: /confirm sign-in/i }).click(),
    ])

    // Single use: revisiting the consumed link shows an error, not a session
    await page.context().clearCookies()
    await page.goto(magicLink)
    await expect(page).toHaveURL(/\/login\?error=/)
  })

  test("the code endpoint is hidden without the shared secret", async ({
    request,
  }) => {
    const response = await request.get("/e2e/otp-code?email=x@example.com")
    expect(response.status()).toBe(404)
  })
})
