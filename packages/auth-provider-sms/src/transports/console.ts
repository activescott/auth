import type { SmsTransport } from "../types.js"

/**
 * Development transport: prints the message to the server console instead
 * of sending an SMS. Zero setup — the default for examples and local dev.
 */
export class ConsoleTransport implements SmsTransport {
  public async sendMessage(to: string, message: string): Promise<boolean> {
    // eslint-disable-next-line no-console
    console.info(`
📱 SMS (console transport, not sent):
To: ${to}
${message}
---
`)
    return true
  }
}
