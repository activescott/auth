import { test, expect, type Page } from "@playwright/test"
import { loginAs, loginWithSms, waitForMinimumFormFill } from "./helpers/auth"

const E2E_SECRET =
  process.env.E2E_MAGIC_LINK_SECRET ?? "e2e_test_magic_link_secret"

/**
 * From the dashboard, open the "add a phone number" flow, request the code,
 * and submit it. Ends on the verify redirect (?linked=1 on success,
 * ?error=IDENTITY_CONFLICT on a conflict).
 */
async function addPhoneFromDashboard(page: Page, phone: string): Promise<void> {
  const nationalNumber = phone.replace(/^\+1/, "")
  await page.goto("/dashboard?link=sms")
  await page.getByLabel(/mobile phone number to add/i).fill(nationalNumber)
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
  const { code } = (await response.json()) as { code?: string }
  if (!code) throw new Error("no code captured")

  // The code form submits itself once the last digit lands
  await page.getByLabel(/enter the code/i).fill(code)
  await page.waitForURL(/linked=1|error=/)
}

async function logout(page: Page): Promise<void> {
  await page.goto("/dashboard")
  await page.getByRole("button", { name: /log out/i }).click()
  await page.waitForURL((url) => !url.pathname.startsWith("/dashboard"))
}

test.describe("identity linking", () => {
  test("a signed-in user can add a phone number as a second sign-in method", async ({
    page,
  }) => {
    await loginAs(page, "link-add@example.com")

    await addPhoneFromDashboard(page, "+14155550401")

    await expect(page).toHaveURL(/linked=1/)
    await expect(page.getByTestId("link-success")).toBeVisible()
    const methods = page.getByTestId("sign-in-method")
    await expect(methods).toHaveCount(2)
    await expect(methods.filter({ hasText: "+14155550401" })).toBeVisible()

    // The linked number now signs in to the SAME account
    await logout(page)
    await loginWithSms(page, "+14155550401")
    await expect(
      page.getByTestId("sign-in-method").filter({
        hasText: "link-add@example.com",
      }),
    ).toBeVisible()
  })

  test("linking a number owned by another account offers a merge that unifies them", async ({
    page,
  }) => {
    const phone = "+14155550402"
    const email = "link-merge@example.com"

    // User B exists with only this phone number
    await loginWithSms(page, phone)
    await logout(page)

    // User A signs in by email and tries to add B's number
    await loginAs(page, email)
    await addPhoneFromDashboard(page, phone)

    // Not an error dead-end: the possession proof mints a merge ticket and
    // the page offers to merge B into A
    await expect(page).toHaveURL(/error=IDENTITY_CONFLICT/)
    await expect(page.getByTestId("merge-prompt")).toBeVisible()
    await expect(page.getByTestId("sign-in-method")).toHaveCount(1)

    await page.getByRole("button", { name: /merge accounts/i }).click()
    await page.waitForURL(/merged=1/)
    await expect(page).not.toHaveURL(/error=/)
    await expect(page.getByTestId("merge-success")).toBeVisible()

    const methods = page.getByTestId("sign-in-method")
    await expect(methods).toHaveCount(2)
    await expect(methods.filter({ hasText: phone })).toBeVisible()
    await expect(methods.filter({ hasText: email })).toBeVisible()

    // Signing in with the absorbed number lands on the merged account
    await logout(page)
    await loginWithSms(page, phone)
    await expect(
      page.getByTestId("sign-in-method").filter({ hasText: email }),
    ).toBeVisible()
  })

  test("the merge ticket is single-use", async ({ page }) => {
    const phone = "+14155550403"

    await loginWithSms(page, phone)
    await logout(page)

    await loginAs(page, "link-once@example.com")
    await addPhoneFromDashboard(page, phone)
    await expect(page.getByTestId("merge-prompt")).toBeVisible()

    await page.getByRole("button", { name: /merge accounts/i }).click()
    await page.waitForURL(/merged=1/)

    // Replaying the merge POST without a fresh ticket is refused
    const replay = await page.request.post("/auth/sms/link-merge", {
      headers: { "Content-Type": "application/json" },
      data: "{}",
    })
    expect(replay.status()).toBe(401)
  })
})
