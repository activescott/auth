import { test, expect } from "@playwright/test"
import { loginAs } from "./helpers/auth"

/**
 * Allowlisted addresses; see AUTH_ADMIN_IDENTIFIERS in playwright.config.ts.
 * One per test that signs in — the per-identifier abuse limit is 3 sign-ins
 * per hour, so sharing an address across tests throttles the later ones.
 */
const USERS_ADMIN = "admin-users@example.com"
const CONFIG_ADMIN = "admin-config@example.com"
const FILTER_ADMIN = "admin-filter@example.com"
const NON_ADMIN = "notanadmin@example.com"

/** The dev-only session secret the example falls back to when JWT_SECRET is unset */
const DEV_SESSION_SECRET = "dev-only-session-secret-do-not-use-in-production"

/**
 * The whole suite shares one in-memory store, so the users table holds every
 * account the other specs created. Ask for the largest allowed page so the row
 * under test is on it regardless of how many others exist.
 */
const ALL_USERS = "/admin/users?limit=100"

test.describe("admin dashboard", () => {
  test("redirects a signed-out visitor to login", async ({ page }) => {
    await page.goto("/admin/users")
    await expect(page).toHaveURL(/\/login/)
  })

  test("answers a signed-in non-admin with 404, not 403", async ({ page }) => {
    await loginAs(page, NON_ADMIN)

    // Asserted on the response rather than the rendered page: a 403 would
    // confirm the admin area exists, which is the thing 404 is hiding.
    const response = await page.request.get("/admin/users")
    expect(response.status()).toBe(404)
  })

  test("lists users with their identities and sorts by link", async ({
    page,
  }) => {
    await loginAs(page, USERS_ADMIN)
    await page.goto(ALL_USERS)

    await expect(page.getByRole("heading", { name: "Users" })).toBeVisible()

    // Scoped to the row: the address appears in both the metadata column and
    // the identity column, so a cell-level locator matches twice.
    const row = page.getByRole("row", { name: new RegExp(USERS_ADMIN) })
    await expect(row).toBeVisible()
    // The identity column: provider badge plus when it was last used
    await expect(row.getByText(/last used \d{4}-\d{2}-\d{2}/)).toBeVisible()

    await page.getByRole("link", { name: /^Signed up as/ }).click()
    await expect(page).toHaveURL(/sortBy=identifier&sortOrder=desc/)

    // Clicking the active column flips the direction
    await page.getByRole("link", { name: /^Signed up as/ }).click()
    await expect(page).toHaveURL(/sortBy=identifier&sortOrder=asc/)
  })

  test("filters server-side and keeps the filter across a sort click", async ({
    page,
  }) => {
    await loginAs(page, FILTER_ADMIN)

    // This account signed up by email, so the email view always has a row —
    // no dependence on what the other specs happened to create.
    await page.goto("/admin/users?filter.signedUpWith=email&limit=100")
    await expect(
      page.getByRole("row", { name: new RegExp(FILTER_ADMIN) }),
    ).toBeVisible()

    // The filter survives a sort click: links carry foreign params through
    await page.getByRole("link", { name: /^Signed up as/ }).click()
    await expect(page).toHaveURL(/filter\.signedUpWith=email/)
    await expect(page).toHaveURL(/sortBy=identifier/)
    await expect(
      page.getByRole("row", { name: new RegExp(FILTER_ADMIN) }),
    ).toBeVisible()

    // ?filter.* reaches the store rather than trimming a fetched page, so an
    // account that does not match is absent entirely
    await page.goto("/admin/users?filter.signedUpWith=sms&limit=100")
    await expect(
      page.getByRole("row", { name: new RegExp(FILTER_ADMIN) }),
    ).toHaveCount(0)
  })

  test("shows the config without leaking secrets, and links between pages", async ({
    page,
  }) => {
    await loginAs(page, CONFIG_ADMIN)
    await page.goto("/admin/config")

    await expect(
      page.getByRole("heading", { name: "Configuration" }),
    ).toBeVisible()
    await expect(page.getByText("<redacted>")).toBeVisible()
    await expect(page.getByText("Provider: Email (email)")).toBeVisible()

    const html = await page.content()
    expect(html).not.toContain(DEV_SESSION_SECRET)

    await page.getByRole("link", { name: "Users" }).click()
    await expect(page).toHaveURL(/\/admin\/users/)
    await page.getByRole("link", { name: "Configuration" }).click()
    await expect(page).toHaveURL(/\/admin\/config/)
  })
})
