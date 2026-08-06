import { constantTimeEqual } from "../otp.js"

const MS_PER_SECOND = 1000
const RADIX_DECIMAL = 10
/** Form-token parts: issued-at seconds and signature */
const FORM_TOKEN_PARTS = 2

/** Field name carrying the signed form token */
export const FORM_TOKEN_FIELD = "authFormToken"
/** Default minimum seconds between rendering the form and submitting it */
export const DEFAULT_MIN_FORM_FILL_SECONDS = 2
/** Default age past which a form token is ignored rather than enforced */
const DEFAULT_FORM_TOKEN_MAX_AGE_SECONDS = 86_400

/**
 * What a bot check sees: the initiate request, its parsed body, the client IP
 * (null when undeterminable), and the provider being initiated.
 */
export interface BotCheckInput {
  request: Request
  body: Record<string, unknown>
  ip: string | null
  providerId: string
}

/**
 * Verdict from a bot check. `reason` is recorded in the abuse log and is
 * never shown to the caller.
 */
export type BotCheckResult = { ok: true } | { ok: false; reason: string }

/**
 * A check that decides whether an initiate request came from a human.
 *
 * Implement this to plug in a hosted service (Cloudflare Turnstile, hCaptcha,
 * ...). Vendor implementations live in their own packages so applications only
 * install the one they use.
 */
export interface BotCheckProvider {
  /** Short identifier used in logs (e.g. "turnstile") */
  readonly id: string
  verify(input: BotCheckInput): Promise<BotCheckResult> | BotCheckResult
}

/**
 * Rejects submissions that arrive faster than a human could fill the form.
 *
 * The form carries a token minted by createFormToken when the page rendered;
 * this check verifies the signature and the elapsed time. A submission with no
 * token is allowed so applications that have not added the field keep working.
 * A token older than `maxAgeSeconds` is also allowed rather than rejected —
 * a login page left open in a tab is a human, not a bot.
 */
export class FormTokenBotCheck implements BotCheckProvider {
  public readonly id = "form-token"

  public constructor(
    private readonly secret: string,
    private readonly minAgeSeconds: number = DEFAULT_MIN_FORM_FILL_SECONDS,
    private readonly maxAgeSeconds: number = DEFAULT_FORM_TOKEN_MAX_AGE_SECONDS,
  ) {}

  public async verify(input: BotCheckInput): Promise<BotCheckResult> {
    const token = input.body[FORM_TOKEN_FIELD]
    if (typeof token !== "string" || token === "") return { ok: true }

    const outcome = await verifyFormToken(this.secret, token, {
      minAgeSeconds: this.minAgeSeconds,
      maxAgeSeconds: this.maxAgeSeconds,
    })

    // An expired token means a page that sat open, not a bot
    if (outcome.ok || outcome.reason === "expired") return { ok: true }
    return { ok: false, reason: outcome.reason }
  }
}

/**
 * Mint a signed timestamp to embed in a login form as a hidden
 * `authFormToken` field. The signature is what makes the elapsed-time check
 * meaningful — an unsigned timestamp is just another field for a bot to
 * forge.
 *
 * @param secret - HMAC key; the session secret is a reasonable choice
 */
export async function createFormToken(secret: string): Promise<string> {
  const issuedAt = Math.floor(Date.now() / MS_PER_SECOND)
  const signature = await signFormToken(secret, issuedAt)
  return `${issuedAt}.${signature}`
}

/** Why a form token was rejected */
export type FormTokenFailure =
  "malformed" | "invalid_signature" | "too_fast" | "expired"

export type FormTokenResult =
  { ok: true; issuedAt: Date } | { ok: false; reason: FormTokenFailure }

/**
 * Verify a token from createFormToken: signature first, then age.
 *
 * @param options.minAgeSeconds - reject anything submitted sooner than this
 * @param options.maxAgeSeconds - reject anything older than this
 */
export async function verifyFormToken(
  secret: string,
  token: string,
  options: { minAgeSeconds: number; maxAgeSeconds: number },
): Promise<FormTokenResult> {
  const parts = token.split(".")
  if (parts.length !== FORM_TOKEN_PARTS) {
    return { ok: false, reason: "malformed" }
  }

  const [issuedAtText, signature] = parts
  if (!issuedAtText || !signature) return { ok: false, reason: "malformed" }

  const issuedAt = Number.parseInt(issuedAtText, RADIX_DECIMAL)
  if (!Number.isFinite(issuedAt)) return { ok: false, reason: "malformed" }

  const expected = await signFormToken(secret, issuedAt)
  if (!constantTimeEqual(signature, expected)) {
    return { ok: false, reason: "invalid_signature" }
  }

  const ageSeconds = Math.floor(Date.now() / MS_PER_SECOND) - issuedAt
  if (ageSeconds < options.minAgeSeconds) {
    return { ok: false, reason: "too_fast" }
  }
  if (ageSeconds > options.maxAgeSeconds) {
    return { ok: false, reason: "expired" }
  }

  return { ok: true, issuedAt: new Date(issuedAt * MS_PER_SECOND) }
}

/**
 * HMAC-SHA-256 of the issued-at timestamp, hex encoded
 */
async function signFormToken(
  secret: string,
  issuedAt: number,
): Promise<string> {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(String(issuedAt)),
  )
  return [...new Uint8Array(signature)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
}
