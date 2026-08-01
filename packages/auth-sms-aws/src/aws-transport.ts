import {
  PinpointSMSVoiceV2Client,
  SendTextMessageCommand,
} from "@aws-sdk/client-pinpoint-sms-voice-v2"
import type { SmsTransport } from "@activescott/auth-provider-sms"

/**
 * The subset of PinpointSMSVoiceV2Client the transport uses. The real
 * client satisfies this structurally; tests can pass a plain object.
 */
export interface PinpointSmsClientLike {
  send(command: SendTextMessageCommand): Promise<unknown>
}

export interface AwsSmsTransportConfig {
  /**
   * The sender: a phone number ARN/E.164, sender ID, or phone pool
   * ID/ARN from AWS End User Messaging. Use a phone pool that contains
   * an approved RCS agent to deliver via RCS with SMS fallback.
   */
  originationIdentity: string
  /** Optional configuration set for event logging/metrics */
  configurationSetName?: string
  /** AWS region, e.g. "us-east-1"; defaults to the SDK's resolution chain */
  region?: string
  /**
   * Injectable client for tests. When omitted, a client is created from
   * `region` and the standard AWS credential chain (env vars, profile,
   * instance role).
   */
  client?: PinpointSmsClientLike
}

/**
 * Sends messages through AWS End User Messaging (Pinpoint SMS Voice v2)
 * with SendTextMessageCommand. Message type is TRANSACTIONAL (one-time
 * codes must not be throttled as promotional traffic).
 */
export class AwsSmsTransport implements SmsTransport {
  private readonly client: PinpointSmsClientLike

  public constructor(private readonly config: AwsSmsTransportConfig) {
    this.client =
      config.client ??
      new PinpointSMSVoiceV2Client(
        config.region ? { region: config.region } : {},
      )
  }

  public async sendMessage(to: string, message: string): Promise<boolean> {
    try {
      await this.client.send(
        new SendTextMessageCommand({
          DestinationPhoneNumber: to,
          OriginationIdentity: this.config.originationIdentity,
          MessageBody: message,
          MessageType: "TRANSACTIONAL",
          ...(this.config.configurationSetName
            ? { ConfigurationSetName: this.config.configurationSetName }
            : {}),
        }),
      )
      return true
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("AWS SMS send failed:", error)
      return false
    }
  }
}
