# @activescott/auth-sms-aws

[![npm version](https://img.shields.io/npm/v/@activescott/auth-sms-aws.svg)](https://www.npmjs.com/package/@activescott/auth-sms-aws)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AWS transport for [`@activescott/auth-provider-sms`](https://www.npmjs.com/package/@activescott/auth-provider-sms). Sends through [AWS End User Messaging](https://aws.amazon.com/end-user-messaging/) (Pinpoint SMS Voice v2) using `@aws-sdk/client-pinpoint-sms-voice-v2` — the only dependency.

## Usage

```ts
import { SmsProvider } from "@activescott/auth-provider-sms"
import { AwsSmsTransport } from "@activescott/auth-sms-aws"

new SmsProvider(
  { appName: "MyApp" },
  new AwsSmsTransport({
    // an E.164 number, sender ID, or phone pool ID from End User Messaging
    originationIdentity: process.env.AWS_SMS_ORIGINATION_IDENTITY!,
    region: "us-east-1",
    configurationSetName: "auth-sms-events", // optional
  }),
)
```

Credentials come from the standard AWS chain (env vars, `~/.aws` profile, SSO, instance role). Messages are sent `TRANSACTIONAL` so one-time codes aren't throttled as promotional traffic.

## Provisioning, step by step

1. Open **AWS End User Messaging** in the console: https://console.aws.amazon.com/sms-voice/home
2. Request a phone number (or sender ID where supported). US: 10DLC requires brand + campaign registration; toll-free requires verification — both take days.
3. **Sandbox**: new accounts can only text verified destination numbers until you request production access (Account → SMS sandbox).
4. Use the number (or a pool containing it) as `originationIdentity`. The example's interactive script lists your identities and writes `.env`: `./scripts/setup-aws.mts` in [`examples/react-router-sms`](https://github.com/activescott/auth/tree/main/examples/react-router-sms)

IAM: the sender needs `sms-voice:SendTextMessage` (plus `sms-voice:Describe*` for the setup script).

## RCS

AWS End User Messaging supports RCS via a registered **RCS agent** (approval is manual, days to weeks). Add the approved agent to a **phone pool** and use the pool ID as `originationIdentity` — delivery falls back to SMS automatically for recipients without RCS. No code changes in this transport.

## Testing

The constructor accepts an injectable client:

```ts
new AwsSmsTransport({ originationIdentity, client: clientMock })
```

`PinpointSmsClientLike` (exported) is the one-method subset the transport uses, so a plain `{ send: vi.fn() }` object satisfies it — no SDK mocking machinery needed.
