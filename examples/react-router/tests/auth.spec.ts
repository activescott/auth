import { test, expect } from "@playwright/test"
import { loginAs } from "./helpers/auth"

test.describe("auth", () => {
  test("login page renders the email form", async ({ page }) => {
    await page.goto("/login")
    await expect(page.getByRole("heading", { name: /sign in/i })).toBeVisible()
    await expect(page.getByLabel(/email/i)).toBeVisible()
    await expect(
      page.getByRole("button", { name: /send magic link/i }),
    ).toBeVisible()
  })

  test("submitting the form returns a success message", async ({ page }) => {
    await page.goto("/login")
    await page.getByLabel(/email/i).fill("alice@example.com")
    await page.getByRole("button", { name: /send magic link/i }).click()
    await expect(page.getByText(/check your email/i)).toBeVisible()
  })

  test("invalid magic link redirects to login with an error", async ({
    page,
  }) => {
    await page.goto("/auth/email/verify?token=not-a-real-token")
    await expect(page).toHaveURL(/\/login\?error=/)
    await expect(page.getByText(/error:/i)).toBeVisible()
  })

  test("dashboard requires auth and redirects to login", async ({ page }) => {
    await page.goto("/dashboard")
    await expect(page).toHaveURL(/\/login/)
  })

  test("e2e helper logs in and grants access to the dashboard", async ({
    page,
  }) => {
    await loginAs(page, "bob@example.com")
    await page.goto("/dashboard")
    await expect(
      page.getByRole("heading", { name: /dashboard/i }),
    ).toBeVisible()
    await expect(page.getByText("bob@example.com")).toBeVisible()
  })

  test("logout clears the session", async ({ page }) => {
    await loginAs(page, "carol@example.com")
    await page.goto("/dashboard")
    await Promise.all([
      page.waitForURL("**/"),
      page.getByRole("button", { name: /log out/i }).click(),
    ])
    await page.goto("/dashboard")
    await expect(page).toHaveURL(/\/login/)
  })
})

test.describe("input preservation", () => {
  test("the email survives the sent round trip for resend", async ({
    page,
  }) => {
    await page.goto("/login")
    await page.getByLabel(/email/i).fill("keep-me@example.com")
    await page.getByRole("button", { name: /send magic link/i }).click()
    await expect(page.getByText(/check your email/i)).toBeVisible()
    await expect(page.getByLabel("Email", { exact: true })).toHaveValue(
      "keep-me@example.com",
    )
  })

  test("the phone number survives an error round trip", async ({ page }) => {
    await page.goto("/login?via=sms")
    await page.getByLabel(/mobile phone number/i).fill("notaphone")
    await page.getByRole("button", { name: /text me a code/i }).click()
    await expect(page).toHaveURL(/error=/)
    await expect(page.getByLabel(/mobile phone number/i)).toHaveValue(
      "notaphone",
    )
  })
})
