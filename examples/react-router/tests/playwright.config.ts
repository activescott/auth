import { defineConfig, devices } from "@playwright/test"

const PORT = 3200

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
      // Console transport regardless of the developer's .env — e2e must
      // never text real messages
      SMS_TRANSPORT: "console",
      // Enables the /e2e/otp-code readback route so specs can fetch the
      // OTP code without an inbox or a phone
      E2E_TEST_MODE: "true",
    },
  },
})
