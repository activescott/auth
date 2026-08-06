import type {
  BotCheckInput,
  BotCheckProvider,
  BotCheckResult,
} from "@activescott/auth"

const DEFAULT_VERIFY_URL =
  "https://challenges.cloudflare.com/turnstile/v0/siteverify"
/** Field the Turnstile widget adds to the form */
const DEFAULT_FIELD_NAME = "cf-turnstile-response"
const DEFAULT_TIMEOUT_MS = 5000

/**
 * Cloudflare Turnstile configuration
 */
export interface TurnstileConfig {
  /** Turnstile secret key (server side; never the site key) */
  secretKey: string
  /** Form field carrying the widget token (default "cf-turnstile-response") */
  fieldName?: string
  /** siteverify endpoint; override for tests or a proxy */
  verifyUrl?: string
  /** How long to wait for siteverify (default 5000ms) */
  timeoutMs?: number
  /**
   * Let the request through when siteverify is unreachable or times out
   * (default true). Rate limits still apply, so an outage at
   * Cloudflare degrades protection rather than locking every user out of
   * sign-in. Set false to fail closed.
   */
  failOpen?: boolean
}

/** Shape of the siteverify response this check reads */
interface SiteVerifyResponse {
  success: boolean
  "error-codes"?: string[]
}

/**
 * Bot check backed by Cloudflare Turnstile.
 *
 * Server side, pass it to the auth config:
 *
 * ```typescript
 * new Auth({
 *   // ...
 *   abuse: {
 *     botChecks: [new TurnstileBotCheck({ secretKey: process.env.TURNSTILE_SECRET_KEY })],
 *   },
 * })
 * ```
 *
 * Client side, render the widget inside the login form so it posts the
 * `cf-turnstile-response` field:
 *
 * ```html
 * <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
 * <div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
 * ```
 */
export class TurnstileBotCheck implements BotCheckProvider {
  public readonly id = "turnstile"

  public constructor(private readonly config: TurnstileConfig) {}

  public async verify(input: BotCheckInput): Promise<BotCheckResult> {
    const token = input.body[this.config.fieldName ?? DEFAULT_FIELD_NAME]
    if (typeof token !== "string" || token === "") {
      return { ok: false, reason: "missing_token" }
    }

    const form = new URLSearchParams({
      secret: this.config.secretKey,
      response: token,
    })
    if (input.ip) form.set("remoteip", input.ip)

    let result: SiteVerifyResponse
    try {
      const response = await fetch(
        this.config.verifyUrl ?? DEFAULT_VERIFY_URL,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: form.toString(),
          signal: AbortSignal.timeout(
            this.config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
          ),
        },
      )
      if (!response.ok) {
        return this.unavailable(`http_${response.status}`)
      }
      result = await this.parseResponse(response)
    } catch (error) {
      return this.unavailable(
        error instanceof Error ? error.name.toLowerCase() : "fetch_failed",
      )
    }

    if (result.success) return { ok: true }

    const codes = result["error-codes"]?.join(",") ?? "unknown"
    return { ok: false, reason: codes }
  }

  /**
   * Turnstile could not be reached or answered unusably. failOpen decides
   * whether the sign-in continues; either way the caller logs the reason.
   */
  private unavailable(detail: string): BotCheckResult {
    if (this.config.failOpen === false) {
      return { ok: false, reason: `unavailable:${detail}` }
    }
    // eslint-disable-next-line no-console -- an unverifiable request that is
    // allowed through has to be visible in the logs
    console.warn(`[auth] turnstile unavailable (${detail}); allowing request`)
    return { ok: true }
  }

  /**
   * Read the siteverify JSON, treating anything unparseable as unavailable
   */
  private async parseResponse(response: Response): Promise<SiteVerifyResponse> {
    const body: unknown = await response.json()
    if (typeof body !== "object" || body === null || !("success" in body)) {
      throw new TypeError("malformed siteverify response")
    }
    const errorCodes = "error-codes" in body ? body["error-codes"] : undefined
    return {
      success: body.success === true,
      "error-codes": Array.isArray(errorCodes)
        ? errorCodes.filter((code): code is string => typeof code === "string")
        : undefined,
    }
  }
}
