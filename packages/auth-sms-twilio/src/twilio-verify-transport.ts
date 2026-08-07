import type {
  VerificationCheck,
  VerificationStart,
  VerificationTransport,
} from "@activescott/auth-provider-sms"

/** Channels Twilio Verify can deliver a code over */
export type TwilioVerifyChannel = "sms" | "call" | "whatsapp" | "email"

export interface TwilioVerifyTransportConfig {
  /** Twilio Account SID (starts with AC) */
  accountSid: string
  /** Twilio Auth Token */
  authToken: string
  /**
   * Verify Service SID (starts with VA). Create one in the Twilio console
   * under Verify > Services; the service's friendly name is what appears in
   * the message, so name it after your app.
   */
  serviceSid: string
  /** Delivery channel (default "sms") */
  channel?: TwilioVerifyChannel
  /** Message language, e.g. "es". Defaults to Twilio's automatic selection. */
  locale?: string
  /**
   * Android app hash for SMS Retriever autofill. Twilio Verify composes the
   * message, so the SmsProvider `webOtpDomain` option does not apply here.
   */
  appHash?: string
  /** Message template SID (starts with HJ) configured in the Verify service */
  templateSid?: string
  /** Injectable fetch for tests; defaults to globalThis.fetch */
  fetch?: typeof fetch
}

const TWILIO_VERIFY_API_BASE = "https://verify.twilio.com/v2"

const HTTP_NOT_FOUND = 404
const MAX_LOGGED_BODY_LENGTH = 500

/** Twilio's Verify log, where per-attempt delivery outcomes show up */
export const TWILIO_VERIFY_LOG_URL =
  "https://console.twilio.com/us1/monitor/logs/verify-logs"

/**
 * Twilio Verify transport: Twilio generates, delivers, and checks the code,
 * so your app never registers a US A2P 10DLC brand or campaign and never owns
 * a sending number — Verify uses senders Twilio already manages. That costs
 * about 4-6x a raw SMS ($0.05 per successful verification plus the channel
 * fee), which is usually still cheaper than 10DLC's fixed monthly fees at low
 * sign-in volume.
 *
 * Raw fetch, no Twilio SDK dependency, works on any WinterTC-compatible
 * runtime. Pass it to SmsProvider in place of TwilioTransport; nothing else
 * about the SMS provider changes.
 */
export class TwilioVerifyTransport implements VerificationTransport {
  private readonly fetchImpl: typeof fetch

  public constructor(private readonly config: TwilioVerifyTransportConfig) {
    if (!config.serviceSid) {
      throw new Error("TwilioVerifyTransport requires a `serviceSid`")
    }
    this.fetchImpl = config.fetch ?? globalThis.fetch
  }

  public async startVerification(to: string): Promise<VerificationStart> {
    const body = new URLSearchParams({
      To: to,
      Channel: this.config.channel ?? "sms",
    })
    if (this.config.locale) body.set("Locale", this.config.locale)
    if (this.config.appHash) body.set("AppHash", this.config.appHash)
    if (this.config.templateSid) {
      body.set("TemplateSid", this.config.templateSid)
    }

    try {
      const response = await this.post("Verifications", body)

      if (!response.ok) {
        const text = await response.text()
        // eslint-disable-next-line no-console
        console.error(
          `Twilio Verify start failed (${response.status}): ${text.slice(0, MAX_LOGGED_BODY_LENGTH)}\nVerify log: ${TWILIO_VERIFY_LOG_URL}`,
        )
        return { ok: false, message: "Failed to send the code" }
      }

      const sid = readStringField(await response.json(), "sid")
      return { ok: true, reference: sid }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("Twilio Verify start failed:", error)
      return { ok: false, message: "Failed to send the code" }
    }
  }

  /**
   * Twilio checks by phone number, so the reference from startVerification is
   * not needed here; it is kept on the challenge for support and log lookups.
   */
  public async checkVerification(
    to: string,
    _reference: string | undefined,
    code: string,
  ): Promise<VerificationCheck> {
    const body = new URLSearchParams({ To: to, Code: code })

    try {
      const response = await this.post("VerificationChecks", body)

      // Twilio returns 404 once a verification is consumed, canceled, or aged
      // out, which the user experiences as an expired code rather than an
      // error. A wrong service SID produces the same status, so log the body:
      // the alternative is an unexplained "expired" on a code just texted.
      if (response.status === HTTP_NOT_FOUND) {
        const text = await response.text()
        // eslint-disable-next-line no-console
        console.warn(
          `Twilio Verify check returned 404 — treating the code as expired. ` +
            `This is normal for a code that was already used or has aged out; ` +
            `if it happens on a freshly texted code, check that serviceSid is ` +
            `the same Verify service the code was sent from. Response: ` +
            `${text.slice(0, MAX_LOGGED_BODY_LENGTH)}\nVerify log: ${TWILIO_VERIFY_LOG_URL}`,
        )
        return { status: "expired" }
      }

      if (!response.ok) {
        const text = await response.text()
        return {
          status: "error",
          message: `Twilio Verify check failed (${response.status}): ${text.slice(0, MAX_LOGGED_BODY_LENGTH)}`,
        }
      }

      const status = readStringField(await response.json(), "status")
      if (status !== "approved") {
        // eslint-disable-next-line no-console
        console.warn(
          `Twilio Verify check returned status "${status}". Per-attempt ` +
            `outcomes: ${TWILIO_VERIFY_LOG_URL}`,
        )
      }
      return mapCheckStatus(status)
    } catch (error) {
      return {
        status: "error",
        message: error instanceof Error ? error.message : "Unknown error",
      }
    }
  }

  private post(path: string, body: URLSearchParams): Promise<Response> {
    const { accountSid, authToken, serviceSid } = this.config
    return this.fetchImpl(
      `${TWILIO_VERIFY_API_BASE}/Services/${serviceSid}/${path}`,
      {
        method: "POST",
        headers: {
          Authorization: `Basic ${btoa(`${accountSid}:${authToken}`)}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      },
    )
  }
}

/**
 * Map a Verify resource status onto a VerificationCheck. "pending" means the
 * code Twilio holds does not match the one submitted.
 */
function mapCheckStatus(status: string | undefined): VerificationCheck {
  switch (status) {
    case "approved": {
      return { status: "approved" }
    }
    case "max_attempts_reached": {
      return { status: "rate_limited" }
    }
    case "expired":
    case "canceled":
    case "deleted": {
      return { status: "expired" }
    }
    default: {
      return { status: "invalid_code" }
    }
  }
}

/** Read one string field out of a parsed JSON body of unknown shape */
function readStringField(payload: unknown, field: string): string | undefined {
  if (typeof payload !== "object" || payload === null) return undefined
  const value = Object.getOwnPropertyDescriptor(payload, field)?.value
  return typeof value === "string" ? value : undefined
}
