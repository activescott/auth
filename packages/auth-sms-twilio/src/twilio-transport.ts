import type { SmsTransport } from "@activescott/auth-provider-sms"

export interface TwilioTransportConfig {
  /** Twilio Account SID (starts with AC) */
  accountSid: string
  /** Twilio Auth Token */
  authToken: string
  /**
   * Sender phone number in E.164 (a number you own in Twilio). Provide
   * this or messagingServiceSid.
   */
  from?: string
  /**
   * Messaging Service SID (starts with MG). Preferred over `from`: a
   * Messaging Service picks the best sender, and one with an onboarded
   * RCS sender delivers via RCS with automatic SMS fallback — no code
   * changes here.
   */
  messagingServiceSid?: string
  /** Injectable fetch for tests; defaults to globalThis.fetch */
  fetch?: typeof fetch
}

const TWILIO_API_BASE = "https://api.twilio.com/2010-04-01"

/**
 * Twilio's per-message delivery log. A message the API accepted can still be
 * filtered by carriers (e.g. error 30034, unregistered A2P 10DLC number);
 * that failure only shows here.
 */
export const TWILIO_DELIVERY_LOG_URL =
  "https://console.twilio.com/us1/monitor/logs/sms"

/**
 * Sends messages through the Twilio Messages API with a raw fetch call —
 * no Twilio SDK dependency, works on any WinterTC-compatible runtime.
 */
export class TwilioTransport implements SmsTransport {
  private readonly fetchImpl: typeof fetch

  public constructor(private readonly config: TwilioTransportConfig) {
    if (!config.from && !config.messagingServiceSid) {
      throw new Error(
        "TwilioTransport requires either `from` or `messagingServiceSid`",
      )
    }
    this.fetchImpl = config.fetch ?? globalThis.fetch
  }

  public async sendMessage(to: string, message: string): Promise<boolean> {
    const { accountSid, authToken, from, messagingServiceSid } = this.config

    const body = new URLSearchParams({ To: to, Body: message })
    if (messagingServiceSid) {
      body.set("MessagingServiceSid", messagingServiceSid)
    } else if (from) {
      body.set("From", from)
    }

    try {
      const response = await this.fetchImpl(
        `${TWILIO_API_BASE}/Accounts/${accountSid}/Messages.json`,
        {
          method: "POST",
          headers: {
            Authorization: `Basic ${btoa(`${accountSid}:${authToken}`)}`,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: body.toString(),
        },
      )

      if (!response.ok) {
        const text = await response.text()
        // eslint-disable-next-line no-console
        console.error(
          `Twilio send failed (${response.status}): ${text.slice(0, 500)}\nDelivery log: ${TWILIO_DELIVERY_LOG_URL}`,
        )
        return false
      }

      return true
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("Twilio send failed:", error)
      return false
    }
  }
}
