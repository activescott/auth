import { test, expect, type Page } from "@playwright/test"
import { loginAs } from "./helpers/auth"

/** Same virtual authenticator as passkeys.spec.ts: real WebAuthn ceremonies */
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

async function addPasskey(page: Page): Promise<void> {
  await page.getByRole("button", { name: /add a passkey/i }).click()
  await expect(page.getByTestId("passkey-item")).toHaveCount(1)
}

/** Log out, then sign in with the passkey on the virtual authenticator */
async function signInWithPasskey(page: Page): Promise<void> {
  await page.getByRole("button", { name: /log out/i }).click()
  await page.waitForURL(/\/$/)
  await page.goto("/login")
  // Conditional UI may sign in on page load before the click lands; see
  // passkeys.spec.ts
  const autoSignedIn = await page
    .waitForURL("**/dashboard", { timeout: 3000 })
    .then(() => true)
    .catch(() => false)
  if (!autoSignedIn) {
    await page.getByRole("button", { name: /sign in with a passkey/i }).click()
    await page.waitForURL("**/dashboard")
  }
}

test.describe("removing a sign-in method", () => {
  test("a user signed in by email can remove their passkey", async ({
    page,
  }) => {
    await addVirtualAuthenticator(page)
    await loginAs(page, "unlink-passkey@example.com")
    await addPasskey(page)

    await page.getByRole("button", { name: /^remove passkey/i }).click()

    await expect(page).toHaveURL(/removed=passkey/)
    await expect(page.getByTestId("remove-success")).toHaveText(
      "Passkey removed.",
    )
    await expect(page.getByTestId("passkey-item")).toHaveCount(0)
    await expect(page.getByTestId("sign-in-method")).toHaveCount(1)
  })

  test("a passkey-only account cannot be left behind", async ({ page }) => {
    const email = "unlink-last@example.com"
    await addVirtualAuthenticator(page)
    await loginAs(page, email)
    await addPasskey(page)
    await signInWithPasskey(page)

    // Signed in by passkey, so the email is the only removable identity, and
    // removing it would leave a passkey on one device as the only way in
    await page.getByRole("button", { name: `Remove ${email}` }).click()
    await expect(page).toHaveURL(/removeError=LAST_SIGN_IN_METHOD/)
    await expect(page.getByTestId("remove-error")).toContainText(
      "last way to recover",
    )
    await expect(page.getByTestId("sign-in-method")).toHaveCount(1)

    // And the passkey is the one this session signed in with
    await page.getByRole("button", { name: /^remove passkey/i }).click()
    await expect(page).toHaveURL(/removeError=IDENTITY_IN_USE/)
    await expect(page.getByTestId("passkey-item")).toHaveCount(1)
  })

  test("the method the session signed in with stays", async ({ page }) => {
    const email = "unlink-in-use@example.com"
    await loginAs(page, email)

    await page.getByRole("button", { name: `Remove ${email}` }).click()

    await expect(page).toHaveURL(/removeError=IDENTITY_IN_USE/)
    await expect(page.getByTestId("remove-error")).toContainText(
      "signed in with that sign-in method",
    )
    await expect(page.getByTestId("sign-in-method")).toHaveCount(1)
  })

  test("removing requires being signed in", async ({ page }) => {
    const response = await page.request.post("/auth/email/unlink", {
      data: { identifier: "someone@example.com" },
    })
    expect(response.status()).toBe(401)
  })
})
