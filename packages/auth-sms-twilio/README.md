# @activescott/auth-sms-twilio

[![npm version](https://img.shields.io/npm/v/@activescott/auth-sms-twilio.svg)](https://www.npmjs.com/package/@activescott/auth-sms-twilio)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Twilio transport for [`@activescott/auth-provider-sms`](https://www.npmjs.com/package/@activescott/auth-provider-sms). Sends through the Twilio Messages API with a raw `fetch` call — **zero dependencies**, runs on any WinterTC-compatible runtime (Node, Cloudflare Workers, Deno, Bun).

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
    messagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID, // preferred
    from: process.env.TWILIO_FROM, // an E.164 number you own in Twilio
  }),
)
```

## Provisioning, step by step

1. Create a Twilio account: https://www.twilio.com/try-twilio
2. Grab the **Account SID** and **Auth Token** from https://console.twilio.com
3. Buy an SMS-capable number (Console → Phone Numbers → Buy a Number), or run the repo's interactive script which verifies steps 1–2 and does the purchase for you: [`./infra/twilio/setup-twilio.mts`](https://github.com/activescott/auth/tree/main/infra/twilio)
4. **US traffic**: register for [A2P 10DLC](https://www.twilio.com/docs/messaging/compliance/a2p-10dlc) or complete toll-free verification — unregistered numbers get filtered by carriers. Console → Regulatory Compliance.
5. Set the env vars above; done.

Troubleshooting:

- A 401 ([error 20003](https://www.twilio.com/docs/errors/20003)) with credentials copied straight from the console usually means a **suspended account** (e.g. out of funds) — Twilio returns the same error as for wrong credentials. The suspension notice may only appear on the [project summary page](https://www.twilio.com/console/projects/summary).
- **Message "sent" but never arrives**: the API accepts messages that carriers later filter, so check the [per-message delivery log](https://console.twilio.com/us1/monitor/logs/sms) — the only place the failure shows. Error [30034](https://www.twilio.com/docs/api/errors/30034) means the number isn't A2P 10DLC registered (step 4 above).

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
```
