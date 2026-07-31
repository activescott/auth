import type {
  EmailProviderConfig,
  EmailTransport,
  SendMagicLinkOptions,
} from "@activescott/auth-provider-email"

/**
 * Wraps the real transport and records the last email per recipient so the
 * e2e code-readback route (`/e2e/otp-code`) can fetch the OTP code without
 * an inbox. Harmless outside tests; the route itself is gated on
 * E2E_TEST_MODE.
 */
export interface CapturedEmail {
  magicLink: string
  code?: string
}

const capturedEmails = new Map<string, CapturedEmail>()

export function getCapturedEmail(to: string): CapturedEmail | null {
  return capturedEmails.get(to.toLowerCase()) ?? null
}

export class CaptureTransport implements EmailTransport {
  public constructor(private readonly inner: EmailTransport) {}

  public sendMagicLink(
    to: string,
    magicLink: string,
    config: EmailProviderConfig,
    options?: SendMagicLinkOptions,
  ): Promise<boolean> {
    capturedEmails.set(to.toLowerCase(), { magicLink, code: options?.code })
    return this.inner.sendMagicLink(to, magicLink, config, options)
  }
}
