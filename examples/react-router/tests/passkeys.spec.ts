import { test, expect, type Page } from "@playwright/test"
import { loginAs } from "./helpers/auth"

/**
 * Passkey specs drive real WebAuthn ceremonies against a CDP virtual
 * authenticator (ctap2/internal, resident keys, user verified,
 * automatic presence) — no mocking above the authenticator.
 */
async function addVirtualAuthenticator(page: Page): Promise<void> {
  const client = await page.context().newCDPSession(page)
  await client.send("WebAuthn.enable")
  await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  })
}

test("add a passkey on the dashboard, then sign in with it", async ({
  page,
}) => {
  await addVirtualAuthenticator(page)

  await loginAs(page, "passkey-user@example.com")
  await page.getByRole("button", { name: /add a passkey/i }).click()
  await expect(page.getByText(/passkey added/i)).toBeVisible()

  await page.getByRole("button", { name: /log out/i }).click()
  await page.waitForURL(/\/$/)

  await page.goto("/login")
  await page.getByRole("button", { name: /sign in with a passkey/i }).click()
  await page.waitForURL("**/dashboard")
  await expect(page.getByText("passkey-user@example.com")).toBeVisible()
})

test("passkey sign-in fails without a registered credential", async ({
  page,
}) => {
  await addVirtualAuthenticator(page)

  await page.goto("/login")
  await page.getByRole("button", { name: /sign in with a passkey/i }).click()

  await expect(page.getByTestId("passkey-error")).toBeVisible()
})

test("adding a passkey requires being signed in", async ({ page }) => {
  const response = await page.request.post("/auth/passkey/register-options")
  expect(response.status()).toBe(401)
})
