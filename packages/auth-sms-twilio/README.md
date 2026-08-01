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
3. Buy an SMS-capable number (Console → Phone Numbers → Buy a Number), or run the repo's interactive script which does 1–3 checks and the purchase for you: [`./infra/twilio/setup-twilio.mts`](https://github.com/activescott/auth/tree/main/infra/twilio)
4. **US traffic**: register for A2P 10DLC or complete toll-free verification — unregistered numbers get filtered by carriers. Console → Regulatory Compliance.
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

The constructor accepts an injectable `fetch` for tests:

```ts
new TwilioTransport({ accountSid, authToken, from, fetch: fetchMock })
```

Twilio's [test credentials](https://www.twilio.com/docs/iam/test-credentials) (magic numbers like `+15005550006`) exercise the API without sending or charging.
