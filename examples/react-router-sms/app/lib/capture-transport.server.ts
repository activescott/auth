import type { SmsTransport } from "@activescott/auth-provider-sms"

/**
 * Wraps the real transport and records the last message per phone number
 * so the e2e code-readback route (`/e2e/otp-code`) can fetch the code
 * without a phone. Harmless outside tests; the route itself is gated on
 * E2E_TEST_MODE.
 */
export interface CapturedSms {
  message: string
  code?: string
}

const capturedMessages = new Map<string, CapturedSms>()

export function getCapturedSms(phone: string): CapturedSms | null {
  return capturedMessages.get(phone) ?? null
}

export class CaptureTransport implements SmsTransport {
  public constructor(private readonly inner: SmsTransport) {}

  public sendMessage(to: string, message: string): Promise<boolean> {
    const code = message.match(/code is: (\d+)/)?.[1]
    capturedMessages.set(to, { message, code })
    return this.inner.sendMessage(to, message)
  }
}
