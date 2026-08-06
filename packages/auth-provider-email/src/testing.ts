import type {
  EmailProviderConfig,
  EmailTransport,
  SendMagicLinkOptions,
} from "./types.js"

/**
 * The last sign-in email sent to one address
 */
export interface CapturedEmail {
  magicLink: string
  code?: string
}

/**
 * Records the last sign-in email per recipient and delegates to the real
 * transport, so an end-to-end test can read the magic link and code back
 * from the app instead of polling an inbox or running an SMTP server.
 *
 * Wire it only when a test-mode flag is set, and gate whatever route reads
 * `getCapturedEmail` on that same flag plus a shared secret — the captured
 * values are live sign-in credentials for as long as the challenge lives.
 * Exported from `@activescott/auth-provider-email/testing` rather than the
 * package root so it stays out of an application's default import graph.
 *
 * @example
 * ```typescript
 * import { CaptureEmailTransport } from "@activescott/auth-provider-email/testing"
 *
 * const transport = process.env.E2E_TEST_MODE === "true"
 *   ? new CaptureEmailTransport(new NodemailerTransport())
 *   : new NodemailerTransport()
 * ```
 */
export class CaptureEmailTransport implements EmailTransport {
  private readonly captured = new Map<string, CapturedEmail>()

  public constructor(private readonly inner: EmailTransport) {}

  public sendMagicLink(
    to: string,
    magicLink: string,
    config: EmailProviderConfig,
    options?: SendMagicLinkOptions,
  ): Promise<boolean> {
    this.captured.set(to.toLowerCase(), { magicLink, code: options?.code })
    return this.inner.sendMagicLink(to, magicLink, config, options)
  }

  /**
   * The last email sent to this address, or null if none was captured
   */
  public getCapturedEmail(to: string): CapturedEmail | null {
    return this.captured.get(to.toLowerCase()) ?? null
  }

  /**
   * Forget everything captured so far (e.g. between test runs)
   */
  public clear(): void {
    this.captured.clear()
  }
}
