import { defineConfig, devices } from "@playwright/test"

/**
 * Override with E2E_PORT when something else already owns 3200 — otherwise
 * Playwright's `reuseExistingServer` happily drives whatever is listening
 * there, and the failures look like application bugs rather than a port clash.
 */
const PORT = Number(process.env.E2E_PORT) || 3200

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts$/,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: "list",
  timeout: 15_000,
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // Build and start the sibling app workspace.
    command: "npm run build && npm run start",
    cwd: "..",
    url: `http://localhost:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      // The example hardcodes dev secrets in app/lib/auth.server.ts, so the
      // server has everything it needs. We only override what's specific to
      // the test run (port, prod mode for `react-router-serve`).
      NODE_ENV: "production",
      PORT: String(PORT),
      // Enables the /e2e/otp-code readback route so specs can fetch the
      // OTP code without an inbox or a phone. Also forces the console SMS
      // transport so e2e never texts real messages even when Twilio env
      // vars are present in the shell environment.
      E2E_TEST_MODE: "true",
      // Admin allowlist for admin.spec.ts. Empty by default in the app, so
      // the spec has to opt addresses in to exercise both sides of the gate.
      // One per test that signs in: the per-identifier abuse limit is 3/hour,
      // so reusing a single address across tests would silently throttle them.
      AUTH_ADMIN_IDENTIFIERS:
        "admin-users@example.com, admin-config@example.com",
    },
  },
})
