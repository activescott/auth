import type { SmsTransport } from "./types.js"

/** Matches the code in this provider's default message template */
const CODE_PATTERN = /code is: (\d+)/

/**
 * The last message texted to one number
 */
export interface CapturedSms {
  message: string
  code?: string
}

/**
 * Records the last message per phone number and delegates to the real
 * transport, so an end-to-end test can read the code back from the app
 * instead of needing a phone (or paying for the text).
 *
 * Wire it only when a test-mode flag is set, and gate whatever route reads
 * `getCapturedSms` on that same flag plus a shared secret — a captured code
 * is a live credential until the challenge expires. Exported from
 * `@activescott/auth-provider-sms/testing` rather than the package root so it
 * stays out of an application's default import graph.
 *
 * `code` is parsed from the default message template; supply `parseCode` when
 * the provider is configured with a custom `messageTemplate`.
 */
export class CaptureSmsTransport implements SmsTransport {
  private readonly captured = new Map<string, CapturedSms>()

  public constructor(
    private readonly inner: SmsTransport,
    private readonly parseCode: (message: string) => string | undefined = (
      message,
    ) => CODE_PATTERN.exec(message)?.[1],
  ) {}

  public sendMessage(to: string, message: string): Promise<boolean> {
    this.captured.set(to, { message, code: this.parseCode(message) })
    return this.inner.sendMessage(to, message)
  }

  /**
   * The last message sent to this number, or null if none was captured
   */
  public getCapturedSms(to: string): CapturedSms | null {
    return this.captured.get(to) ?? null
  }

  /**
   * Forget everything captured so far (e.g. between test runs)
   */
  public clear(): void {
    this.captured.clear()
  }
}
