import { describe, it, expect, vi } from "vitest"
import { SendTextMessageCommand } from "@aws-sdk/client-pinpoint-sms-voice-v2"
import { AwsSmsTransport } from "../aws-transport.js"
import type { PinpointSmsClientLike } from "../aws-transport.js"

const TEST_PHONE = "+14155550100"
const TEST_POOL = "pool-11111111222222223333333344444444"

function createClientMock(sendImpl?: () => Promise<unknown>): {
  client: PinpointSmsClientLike
  send: ReturnType<typeof vi.fn>
} {
  const send = vi.fn(sendImpl ?? (() => Promise.resolve({ MessageId: "m-1" })))
  return { client: { send }, send }
}

describe("AwsSmsTransport", () => {
  it("should send a TRANSACTIONAL text via SendTextMessageCommand", async () => {
    const { client, send } = createClientMock()
    const transport = new AwsSmsTransport({
      originationIdentity: TEST_POOL,
      client,
    })

    const sent = await transport.sendMessage(TEST_PHONE, "Your code is 123456")
    expect(sent).toBe(true)

    const command = send.mock.calls[0]?.[0]
    expect(command).toBeInstanceOf(SendTextMessageCommand)
    expect(command.input).toMatchObject({
      DestinationPhoneNumber: TEST_PHONE,
      OriginationIdentity: TEST_POOL,
      MessageBody: "Your code is 123456",
      MessageType: "TRANSACTIONAL",
    })
    expect(command.input.ConfigurationSetName).toBeUndefined()
  })

  it("should include the configuration set when configured", async () => {
    const { client, send } = createClientMock()
    const transport = new AwsSmsTransport({
      originationIdentity: TEST_POOL,
      configurationSetName: "auth-sms-events",
      client,
    })

    await transport.sendMessage(TEST_PHONE, "hi")

    expect(send.mock.calls[0]?.[0].input.ConfigurationSetName).toBe(
      "auth-sms-events",
    )
  })

  it("should return false when the client throws", async () => {
    const { client } = createClientMock(() =>
      Promise.reject(new Error("throttled")),
    )
    const transport = new AwsSmsTransport({
      originationIdentity: TEST_POOL,
      client,
    })

    expect(await transport.sendMessage(TEST_PHONE, "hi")).toBe(false)
  })
})
