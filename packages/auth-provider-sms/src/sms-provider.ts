import type {
  AuthProvider,
  AuthContext,
  AuthResult,
  AuthInitResult,
  ProviderRoute,
} from "@activescott/auth"
import {
  AuthErrors,
  generateOtpCode,
  hashOtpCode,
  verifyOtpChallenge,
  parseRequestBody,
  isBrowserFormPost,
  buildReturnUrl,
  buildChallengeCookie,
  buildChallengeClearingCookie,
  readCookie,
  parseDuration,
  authenticateWithIdentifier,
  initiateAccepted,
} from "@activescott/auth"
import type { SmsProviderConfig, SmsTransport } from "./types.js"

const MS_PER_SECOND = 1000

const CHALLENGE_TYPE = "sms"
const DEFAULT_EXPIRY = "10m"
const DEFAULT_OTP_LENGTH = 6
const DEFAULT_OTP_MAX_ATTEMPTS = 5
const DEFAULT_OTP_COOKIE_NAME = "auth_sms_challenge"
const DEFAULT_APP_NAME = "App"

/** E.164: +, non-zero leading digit, 2-15 digits total */
const E164_PATTERN = /^\+[1-9]\d{1,14}$/

/**
 * SMS one-time-code authentication provider. Each initiate creates one
 * server-side challenge, texts a numeric code to the phone number, and
 * binds the challenge to the browser with an HttpOnly cookie; verify
 * redeems the code against that challenge.
 *
 * Vendor delivery (Twilio, AWS, ...) is injected via SmsTransport, so
 * this package has no vendor dependencies.
 */
export class SmsProvider implements AuthProvider {
  public readonly id = "sms"
  public readonly name = "SMS"
  public readonly initiateSentMessage = "Code sent. Check your phone."

  public constructor(
    private readonly config: SmsProviderConfig,
    private readonly transport: SmsTransport,
  ) {}

  /**
   * Create a challenge and text the code. Browser form posts (urlencoded
   * + Accept: text/html) are answered with a redirect back to the
   * submitting page (?sent=1) so login forms can post directly to
   * /auth/sms/initiate; other callers get JSON. Both carry the challenge
   * cookie.
   */
  public async initiate(
    request: Request,
    context: AuthContext,
  ): Promise<AuthInitResult | Response> {
    try {
      const body = await parseRequestBody(request)
      const rawPhone = body.phone

      if (!rawPhone || typeof rawPhone !== "string") {
        return this.initiateFailure(
          request,
          AuthErrors.invalidCredentials({
            reason: "Phone number is required",
          }),
        )
      }

      const phone = normalizePhoneNumber(rawPhone)
      if (!phone) {
        return this.initiateFailure(
          request,
          AuthErrors.invalidCredentials({
            reason:
              "Enter the phone number in international format, e.g. +14155550100",
          }),
        )
      }

      // Cap how many texts one number receives regardless of source IP.
      // A throttled request gets the same answer as a sent one.
      const decision = await context.abuse?.checkIdentifier(this.id, phone)
      if (decision?.allowed === false) {
        return initiateAccepted(request, this.initiateSentMessage)
      }

      const challengeId = crypto.randomUUID()
      const code = generateOtpCode(
        this.config.otp?.length ?? DEFAULT_OTP_LENGTH,
      )
      const expirySeconds = parseDuration(this.config.expiry ?? DEFAULT_EXPIRY)

      await context.challengeStore.create({
        id: challengeId,
        type: CHALLENGE_TYPE,
        identifier: phone,
        hashedCode: await hashOtpCode(challengeId, code),
        maxAttempts: this.config.otp?.maxAttempts ?? DEFAULT_OTP_MAX_ATTEMPTS,
        expiresAt: new Date(Date.now() + expirySeconds * MS_PER_SECOND),
      })

      const sent = await this.transport.sendMessage(
        phone,
        this.buildMessage(code),
      )

      if (!sent) {
        return this.initiateFailure(
          request,
          AuthErrors.providerError("Failed to send the code"),
        )
      }

      const challengeCookie = buildChallengeCookie(
        this.cookieName(),
        challengeId,
        expirySeconds,
        context.baseUrl,
      )

      return initiateAccepted(request, this.initiateSentMessage, [
        challengeCookie,
      ])
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("Error in sms provider initiate:", error)
      return this.initiateFailure(
        request,
        AuthErrors.providerError(
          error instanceof Error ? error.message : "Unknown error",
        ),
      )
    }
  }

  /**
   * POST with a code redeems it against the challenge cookie
   */
  public async verify(
    request: Request,
    context: AuthContext,
  ): Promise<AuthResult | Response> {
    try {
      const body = await parseRequestBody(request)

      if (typeof body.code !== "string" || body.code.length === 0) {
        return {
          success: false,
          error: AuthErrors.invalidCredentials({ reason: "Code is required" }),
        }
      }

      const challengeId = readCookie(request, this.cookieName())
      if (!challengeId) {
        return {
          success: false,
          error: AuthErrors.invalidCredentials({
            reason:
              "No verification in progress in this browser. Request a new code.",
          }),
        }
      }

      const outcome = await verifyOtpChallenge(
        context.challengeStore,
        challengeId,
        CHALLENGE_TYPE,
        body.code,
      )

      if (!outcome.ok) {
        return { success: false, error: this.otpFailureError(outcome.reason) }
      }

      const result = await authenticateWithIdentifier(
        this.id,
        outcome.challenge.identifier,
        context,
      )
      if (!result.success) return result

      return {
        ...result,
        setCookies: [
          buildChallengeClearingCookie(this.cookieName(), context.baseUrl),
        ],
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("Error in sms provider verify:", error)
      return {
        success: false,
        error: AuthErrors.providerError(
          error instanceof Error ? error.message : "Unknown error",
        ),
      }
    }
  }

  public canHandle(request: Request): boolean {
    const url = new URL(request.url)
    return url.pathname.startsWith("/auth/sms")
  }

  public getRoutes(): ProviderRoute[] {
    return [
      { method: "POST", path: "/sms/initiate", handler: "initiate" },
      { method: "POST", path: "/sms/verify", handler: "verify" },
    ]
  }

  /**
   * The message text. When webOtpDomain is set, the WebOTP autofill line
   * (`@domain #code`) goes on the last line as the spec requires.
   */
  private buildMessage(code: string): string {
    const appName = this.config.appName ?? DEFAULT_APP_NAME
    const text =
      this.config.messageTemplate?.(code, appName) ??
      `Your ${appName} sign-in code is: ${code}`

    if (this.config.webOtpDomain) {
      return `${text}\n\n@${this.config.webOtpDomain} #${code}`
    }
    return text
  }

  /**
   * Map a shared OTP redemption failure to this provider's error responses
   */
  private otpFailureError(
    reason: "not_found" | "expired" | "rate_limited" | "invalid_code",
  ): ReturnType<typeof AuthErrors.invalidCredentials> {
    switch (reason) {
      case "not_found": {
        return AuthErrors.invalidCredentials({
          reason: "Verification not found. Request a new code.",
        })
      }
      case "expired": {
        return AuthErrors.expiredToken({ reason: "Code has expired" })
      }
      case "rate_limited": {
        return AuthErrors.rateLimited({ reason: "Too many attempts" })
      }
      case "invalid_code": {
        return AuthErrors.invalidCredentials({ reason: "Incorrect code" })
      }
    }
  }

  /**
   * Failure counterpart of the browser-form redirect: send the browser
   * back with ?error=<code>; other callers get the AuthInitResult.
   */
  private initiateFailure(
    request: Request,
    error: ReturnType<typeof AuthErrors.invalidCredentials>,
  ): AuthInitResult | Response {
    if (isBrowserFormPost(request)) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: buildReturnUrl(request, { error: error.code }),
        },
      })
    }
    return { success: false, error }
  }

  /**
   * The configured challenge cookie name
   */
  private cookieName(): string {
    return this.config.otp?.cookieName ?? DEFAULT_OTP_COOKIE_NAME
  }
}

/**
 * Normalize user input to E.164: strips spaces, dashes, dots, and
 * parentheses and converts a leading 00 to +. Returns null when the
 * result is not a valid E.164 number — a country code is required (we
 * never guess a default country).
 */
export function normalizePhoneNumber(input: string): string | null {
  let phone = input.trim().replaceAll(/[\s().-]/g, "")
  if (phone.startsWith("00")) {
    phone = `+${phone.slice(2)}`
  }
  return E164_PATTERN.test(phone) ? phone : null
}
