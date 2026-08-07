# @activescott/auth-sms-twilio

[![npm version](https://img.shields.io/npm/v/@activescott/auth-sms-twilio.svg)](https://www.npmjs.com/package/@activescott/auth-sms-twilio)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Twilio transports for [`@activescott/auth-provider-sms`](https://www.npmjs.com/package/@activescott/auth-provider-sms), both raw `fetch` — **zero dependencies**, running on any WinterTC-compatible runtime (Node, Cloudflare Workers, Deno, Bun):

- **`TwilioTransport`** — you own the number and the code; sends through the Twilio Messages API. Cheapest per message (~$0.011–0.013 all-in for US SMS), but US traffic needs your own [A2P 10DLC](https://www.twilio.com/docs/messaging/compliance/a2p-10dlc) brand and campaign registration.
- **`TwilioVerifyTransport`** — Twilio generates, sends, and checks the code through the [Verify API](https://www.twilio.com/docs/verify). No number to buy and **no 10DLC registration**: Verify "procures and manages short codes, long codes, toll free, and global alpha-sender IDs" on your behalf. Costs $0.05 per successful verification plus the channel fee (~4–6x a raw SMS), which at low sign-in volume is often less than 10DLC's fixed monthly fees.

## Usage

```ts
import { SmsProvider } from "@activescott/auth-provider-sms"
import { TwilioTransport } from "@activescott/auth-sms-twilio"

new SmsProvider(
  { appName: "MyApp" },
  new TwilioTransport({
    accountSid: process.env.TWILIO_ACCOUNT_SID!,
    authToken: process.env.TWILIO_AUTH_TOKEN!,
    // one of:
    messagingServiceSid: process.env.TWILIO_SMS_MESSAGING_SERVICE_SID, // preferred
    from: process.env.TWILIO_SMS_FROM, // an E.164 number you own in Twilio
  }),
)
```

Or with Verify, which replaces the sender configuration entirely:

```ts
import { SmsProvider } from "@activescott/auth-provider-sms"
import { TwilioVerifyTransport } from "@activescott/auth-sms-twilio"

new SmsProvider(
  {}, // the message text, code length, and expiry are Twilio's here
  new TwilioVerifyTransport({
    accountSid: process.env.TWILIO_ACCOUNT_SID!,
    authToken: process.env.TWILIO_AUTH_TOKEN!,
    serviceSid: process.env.TWILIO_VERIFY_SERVICE_SID!, // starts with VA
  }),
)
```

## Provisioning, step by step

1. Create a Twilio account: https://www.twilio.com/try-twilio
2. Grab the **Account SID** and **Auth Token** from https://console.twilio.com
3. Buy an SMS-capable number (Console → Phone Numbers → Buy a Number).
4. **US traffic**: register for [A2P 10DLC](https://www.twilio.com/docs/messaging/compliance/a2p-10dlc) or complete toll-free verification — unregistered numbers get filtered by carriers. Console → Regulatory Compliance.
5. Set the env vars above; done.

Troubleshooting:

- A 401 ([error 20003](https://www.twilio.com/docs/errors/20003)) with credentials copied straight from the console usually means a **suspended account** (e.g. out of funds) — Twilio returns the same error as for wrong credentials. The suspension notice may only appear on the [project summary page](https://www.twilio.com/console/projects/summary).
- **Message "sent" but never arrives**: the API accepts messages that carriers later filter, so check the [per-message delivery log](https://console.twilio.com/us1/monitor/logs/sms) — the only place the failure shows. Error [30034](https://www.twilio.com/docs/api/errors/30034) means the number isn't A2P 10DLC registered (step 4 above).

## Verify, step by step

Steps 3 and 4 above are what Verify removes:

1. Create a Twilio account and grab the **Account SID** and **Auth Token** (steps 1–2 above).
2. Console → **Verify → Services → Create new**. The friendly name you give the service is what appears in the message ("Your _MyApp_ verification code is …"), so name it after your app.
3. Copy the service SID (starts with `VA`) into `serviceSid`. That's it — no number, no campaign registration, nothing to wait on.

Options:

| Option        | Default    | Description                                                                                                                                                                   |
| ------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `channel`     | `"sms"`    | `"sms"`, `"call"`, `"whatsapp"`, or `"email"`                                                                                                                                 |
| `locale`      | (Twilio's) | Message language, e.g. `"es"`                                                                                                                                                 |
| `appHash`     | (off)      | Android [SMS Retriever](https://developers.google.com/identity/sms-retriever/overview) hash — Verify's equivalent of the provider's `webOtpDomain`, which does not apply here |
| `templateSid` | (off)      | A message template (starts with `HJ`) configured in the Verify service                                                                                                        |

Verification outcomes are in the [Verify log](https://console.twilio.com/us1/monitor/logs/verify), not the SMS delivery log. Twilio's own rate limits and fraud guards (SMS pumping protection) are configured per service in that console section.

Cost note: you're billed $0.05 on **successful** verification, so failed and abandoned attempts cost only the channel fee. The provider counts attempts before calling Twilio, so a guesser can trigger at most `otp.maxAttempts` checks per challenge.

## RCS (branded, richer messages)

Twilio delivers RCS through a **Messaging Service** with an onboarded RCS sender — same Messages API, zero code changes here:

1. Create a Messaging Service (Console → Messaging → Services) and add your number to its sender pool.
2. Onboard an RCS sender to it: https://www.twilio.com/docs/rcs — brand/carrier approval is manual and takes **days to weeks**.
3. Use `messagingServiceSid` (not `from`). Twilio sends RCS where the recipient supports it and falls back to SMS automatically.

## Testing

Three levels, cheapest first:

1. **No Twilio at all** (recommended for app development): use the provider's `ConsoleTransport` — codes print to the server console. The [example app](https://github.com/activescott/auth/tree/main/examples/react-router) does this by default and its e2e suite captures messages at the `SmsTransport` seam, so full sign-in flows are tested without any SMS gateway.
2. **Exercise the real API without sending or charging**: Twilio's [test credentials](https://www.twilio.com/docs/iam/test-credentials) — a separate SID/token pair with magic numbers (`+15005550006` succeeds; others reproduce specific errors like invalid-number 21211). Note test-credential messages are never delivered and don't appear in the console's message logs, so they verify your API integration and error handling, not message content or delivery.
3. **Real delivery**: live credentials and a registered number; verify content and delivery in the [per-message log](https://console.twilio.com/us1/monitor/logs/sms).

For unit tests, the constructor accepts an injectable `fetch` (this package's own tests use it; apps usually don't need it):

```ts
new TwilioTransport({ accountSid, authToken, from, fetch: fetchMock })
new TwilioVerifyTransport({
  accountSid,
  authToken,
  serviceSid,
  fetch: fetchMock,
})
```

Level 1 is the same for Verify: develop against `ConsoleTransport` and swap the transport at the edge of your app, since a Verify integration cannot be exercised end to end without billable verifications.
