import { parseRequestBody } from "../provider-util.js"
import { InMemoryRateLimitStore } from "../stores/in-memory-rate-limit-store.js"
import type { BotCheckInput, BotCheckProvider } from "./bot-check.js"
import {
  DEFAULT_MIN_FORM_FILL_SECONDS,
  FormTokenBotCheck,
} from "./bot-check.js"
import { getClientIp } from "./client-ip.js"
import type { ClientIpOptions } from "./client-ip.js"
import { RateLimiter } from "./rate-limiter.js"
import type { RateLimitRule } from "./rate-limiter.js"
import type { RateLimitStore } from "./rate-limit-store.js"

const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600
const SECONDS_PER_DAY = 86_400

/** Per-IP defaults: a small burst, then a hard hourly cap */
const DEFAULT_PER_IP_RULES: RateLimitRule[] = [
  { windowSeconds: SECONDS_PER_MINUTE, max: 3 },
  { windowSeconds: SECONDS_PER_HOUR, max: 10 },
]

/** Per-recipient defaults, enforced regardless of source IP */
const DEFAULT_PER_IDENTIFIER_RULES: RateLimitRule[] = [
  { windowSeconds: SECONDS_PER_HOUR, max: 3 },
  { windowSeconds: SECONDS_PER_DAY, max: 10 },
]

/** Why an initiate request was blocked */
export type AbuseReason =
  "ip_rate_limited" | "identifier_rate_limited" | "bot_check_failed"

/**
 * A blocked initiate attempt, as passed to `onBlocked` and written to the log
 */
export interface AbuseEvent {
  reason: AbuseReason
  /** Which check produced it (e.g. "too_fast", "turnstile:...") */
  detail?: string
  providerId: string
  ip: string | null
  /** The address/number the caller asked to send to, when known */
  identifier?: string
  /** The rule that was exceeded, for rate-limit blocks */
  rule?: RateLimitRule
  at: Date
}

export type AbuseDecision =
  | { allowed: true }
  | { allowed: false; event: AbuseEvent; retryAfterSeconds?: number }

/**
 * Abuse protection for the initiate endpoints. Every field is optional:
 * with no configuration at all, requests are limited per IP and per recipient
 * using an in-memory store, and the form-token check runs.
 */
export interface AbuseConfig {
  /** Turn all abuse protection off (default: enabled) */
  enabled?: boolean
  /** Counter storage (default: a new InMemoryRateLimitStore) */
  store?: RateLimitStore
  /** Limits per client IP (default: 3/minute and 10/hour) */
  perIp?: RateLimitRule[]
  /** Limits per recipient address/number (default: 3/hour and 10/day) */
  perIdentifier?: RateLimitRule[]
  /** Minimum seconds between form render and submit (default 2) */
  minFormFillSeconds?: number
  /**
   * Additional checks run after the built-in form-token one —
   * e.g. `[new TurnstileBotCheck({ secretKey })]`
   */
  botChecks?: BotCheckProvider[]
  /** How to determine the client IP */
  clientIp?: ClientIpOptions
  /** Called for every block, after it is logged */
  onBlocked?: (event: AbuseEvent) => void
  /**
   * What a blocked caller receives: "generic" (default) answers exactly as a
   * successful send would, so bots learn nothing and no enumeration signal
   * leaks; "rateLimited" returns the RATE_LIMITED error instead, which suits
   * API-only deployments with their own client-side handling.
   */
  respondWith?: "generic" | "rateLimited"
}

/**
 * The subset of the guard that providers use: per-recipient throttling, which
 * can only run once the provider has parsed and normalized the identifier out
 * of the request body.
 */
export interface AbuseContext {
  checkIdentifier(
    providerId: string,
    identifier: string,
  ): Promise<AbuseDecision>
}

/**
 * Runs the abuse checks and logs every rejection.
 *
 * Auth calls checkInitiate before dispatching an initiate/send action;
 * providers call checkIdentifier through AuthContext once they know the
 * recipient.
 */
export class AbuseGuard {
  private readonly limiter: RateLimiter
  private readonly ownedStore: InMemoryRateLimitStore | null
  private readonly botChecks: BotCheckProvider[]
  private readonly config: AbuseConfig

  public constructor(config: AbuseConfig | undefined, formTokenSecret: string) {
    this.config = config ?? {}

    if (this.config.store) {
      this.ownedStore = null
      this.limiter = new RateLimiter(this.config.store)
    } else {
      this.ownedStore = new InMemoryRateLimitStore()
      this.limiter = new RateLimiter(this.ownedStore)
    }

    this.botChecks = [
      new FormTokenBotCheck(
        formTokenSecret,
        this.config.minFormFillSeconds ?? DEFAULT_MIN_FORM_FILL_SECONDS,
      ),
      ...(this.config.botChecks ?? []),
    ]
  }

  /** True when protection is switched off entirely */
  public get enabled(): boolean {
    return this.config.enabled !== false
  }

  /** How a blocked caller should be answered */
  public get respondWith(): "generic" | "rateLimited" {
    return this.config.respondWith ?? "generic"
  }

  /**
   * Release resources owned by the guard (the default in-memory store)
   */
  public destroy(): void {
    this.ownedStore?.destroy()
  }

  /**
   * Bot checks plus per-IP limits, before the provider does any work. Reads a
   * clone of the request so the provider can still consume the body.
   */
  public async checkInitiate(
    request: Request,
    providerId: string,
  ): Promise<AbuseDecision> {
    if (!this.enabled) return { allowed: true }

    const ip = getClientIp(request, this.config.clientIp)
    const body = await this.readBody(request)

    for (const check of this.botChecks) {
      const result = await this.runBotCheck(check, {
        request,
        body,
        ip,
        providerId,
      })
      if (!result.ok) {
        return this.blocked({
          reason: "bot_check_failed",
          detail: `${check.id}:${result.reason}`,
          providerId,
          ip,
          at: new Date(),
        })
      }
    }

    if (ip) {
      const verdict = await this.limiter.check(
        `ip:${providerId}:${ip}`,
        this.config.perIp ?? DEFAULT_PER_IP_RULES,
      )
      if (!verdict.allowed) {
        return this.blocked(
          {
            reason: "ip_rate_limited",
            providerId,
            ip,
            rule: verdict.rule,
            at: new Date(),
          },
          verdict.retryAfterSeconds,
        )
      }
    }

    return { allowed: true }
  }

  /**
   * Per-recipient limits: caps how many messages one address or number
   * receives no matter how many IPs ask for them.
   */
  public async checkIdentifier(
    request: Request,
    providerId: string,
    identifier: string,
  ): Promise<AbuseDecision> {
    if (!this.enabled) return { allowed: true }

    const normalized = identifier.trim().toLowerCase()
    const verdict = await this.limiter.check(
      `identifier:${providerId}:${normalized}`,
      this.config.perIdentifier ?? DEFAULT_PER_IDENTIFIER_RULES,
    )
    if (verdict.allowed) return { allowed: true }

    return this.blocked(
      {
        reason: "identifier_rate_limited",
        providerId,
        ip: getClientIp(request, this.config.clientIp),
        identifier: normalized,
        rule: verdict.rule,
        at: new Date(),
      },
      verdict.retryAfterSeconds,
    )
  }

  /**
   * The AbuseContext handed to providers for a specific request
   */
  public contextFor(request: Request): AbuseContext {
    return {
      checkIdentifier: (providerId, identifier) =>
        this.checkIdentifier(request, providerId, identifier),
    }
  }

  /**
   * Log the block, notify onBlocked, and return the decision. Blocks are
   * always logged: a burst of abuse has to be visible in the app's logs.
   */
  private blocked(
    event: AbuseEvent,
    retryAfterSeconds?: number,
  ): AbuseDecision {
    const parts = [
      `reason=${event.reason}`,
      event.detail ? `detail=${event.detail}` : null,
      `provider=${event.providerId}`,
      `ip=${event.ip ?? "unknown"}`,
      event.identifier ? `identifier=${event.identifier}` : null,
      event.rule ? `rule=${event.rule.max}/${event.rule.windowSeconds}s` : null,
      retryAfterSeconds ? `retryAfter=${retryAfterSeconds}s` : null,
    ].filter(Boolean)

    // eslint-disable-next-line no-console
    console.warn(`[auth] blocked initiate: ${parts.join(" ")}`)

    this.config.onBlocked?.(event)

    return { allowed: false, event, retryAfterSeconds }
  }

  /**
   * A check that throws blocks the request rather than letting the error
   * bubble into a 500 — but the error is logged so a misconfigured vendor
   * check is visible.
   */
  private async runBotCheck(
    check: BotCheckProvider,
    input: BotCheckInput,
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    try {
      return await check.verify(input)
    } catch (error) {
      // eslint-disable-next-line no-console
      console.warn(`[auth] bot check ${check.id} threw:`, error)
      return { ok: false, reason: "error" }
    }
  }

  /**
   * Parse the body without consuming the caller's request
   */
  private async readBody(request: Request): Promise<Record<string, unknown>> {
    if (request.method === "GET" || request.method === "HEAD") return {}
    try {
      return await parseRequestBody(request.clone())
    } catch {
      return {}
    }
  }
}
