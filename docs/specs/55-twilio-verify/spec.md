# Spec — hosted verification transport for SMS sign-in

## Problem

US A2P 10DLC is the expensive part of SMS sign-in, and none of it is code. To
text a US number from a long code an app must register a brand and a campaign
through The Campaign Registry, which costs a one-time campaign fee plus monthly
fees per campaign and per number, and takes days to weeks. Until that clears,
carriers filter the messages — Twilio error 30034 — so the API accepts the send
and the code never arrives. That failure only shows up in the delivery log,
which is exactly the confusing experience the existing `TwilioMessagingTransport` docs
warn about.

A hosted verification service sidesteps registration entirely: the vendor sends
from senders it already owns and has already registered. Twilio states that
Verify "procures and manages short codes, long codes, toll free, and global
alpha-sender IDs" (https://www.twilio.com/en-us/verify). The app registers
nothing.

The trade is price and control. Twilio charges $0.05 per successful
verification plus the channel fee, versus roughly $0.011–0.013 all-in for a raw
US SMS through Programmable Messaging — about 4–6x. For low-volume auth the
fixed 10DLC monthly fees can exceed the whole Verify bill, which is the case
the issue makes.

## Vendor survey

The issue asks whether something cheaper or simpler than Twilio Verify exists,
particularly for SMS-only use.

| Vendor                       | Per-verification (US)                              | App registers its own 10DLC?           | Notes                                                                                                                                                                                                         |
| ---------------------------- | -------------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Twilio Verify                | $0.05 + channel fee (~$0.058 all-in)               | No — Twilio's own senders              | SMS, voice, email, WhatsApp, push, silent network auth. Cleanest REST API of the group; already a repo dependency for credentials and console.                                                                |
| Vonage Verify v2             | ~$0.05 per successful verification + channel rates | No                                     | `POST /v2/request` returns a `request_id`; check is against that id, not the phone number. Channel workflow with fallback is built in.                                                                        |
| Sinch Verification           | ~$0.05 at scale, contract-priced                   | No                                     | Enterprise sales motion; little self-serve signal for small teams.                                                                                                                                            |
| Bird (MessageBird) Verify    | ~$0.05, volume-tiered                              | No                                     | EU-centric; thinner US tooling.                                                                                                                                                                               |
| Message Central VerifyNow    | claims $0.005–$0.0085 bundled                      | No — claims pre-approved shared routes | The cheapest claim found, but the only source for it is the vendor's own comparison page, whose 10DLC claims about competitors do not match those vendors' own documentation. Treat the number as unverified. |
| AWS End User Messaging / SNS | ~$0.008–0.009 per SMS                              | Yes                                    | Cheapest per message, but it is a raw SMS API — the app keeps the 10DLC burden and builds the OTP flow itself. This is the existing `SmsTransport` path, not an alternative to it. Drafted in PR #37.         |

Conclusion: hosted verification is a commodity at roughly $0.05 across the
established vendors, and the differentiator is API quality and onboarding
friction, not price. Nothing found is both meaningfully cheaper and credibly
documented. Twilio Verify is the right first implementation because the repo
already carries a Twilio transport, credentials handling, and an example
wiring; a second vendor is a follow-up, not a blocker.

The design consequence of the survey: Vonage checks a code against an opaque
`request_id` while Twilio checks against the phone number. The transport
interface must carry both, or it will be a Twilio-shaped interface wearing a
neutral name.

## Interface

In `@activescott/auth-provider-sms`:

```ts
export interface VerificationTransport {
  /**
   * Ask the vendor to generate and deliver a code.
   * Returns an opaque reference to give back at check time (vendors that key
   * the check on the phone number return no reference), or a failure.
   */
  startVerification(to: string): Promise<VerificationStart>

  checkVerification(
    to: string,
    reference: string | undefined,
    code: string,
  ): Promise<VerificationCheck>
}

export type VerificationStart =
  { ok: true; reference?: string } | { ok: false; message?: string }

export type VerificationCheck =
  | { status: "approved" }
  | { status: "invalid_code" }
  | { status: "expired" }
  | { status: "rate_limited" }
  | { status: "error"; message?: string }
```

`SmsProvider` takes `SmsTransport | VerificationTransport` and branches on
`isVerificationTransport(transport)` — a `"startVerification" in transport`
type guard, exported so example and application code can branch the same way
without a cast.

## Flow (hosted path)

Initiate:

1. Parse and normalize the phone number to E.164 (shared with the local path).
2. `context.abuse?.checkIdentifier("sms", phone)`; a throttled request returns
   the same "code sent" response as a successful one.
3. `transport.startVerification(phone)`. On failure, the normal initiate error.
4. Create a `Challenge` with `type: "sms"`, `identifier: phone`, **no**
   `hashedCode`, and `data: { verificationReference }` when the vendor gave one.
5. Set the same HttpOnly challenge cookie and return the same accepted response.

Verify:

1. Read the challenge id from the cookie; missing → "request a new code".
2. `findById`; wrong type or missing → `not_found`. Past `expiresAt` → expired.
3. `incrementAttempts` **before** calling the vendor; over `maxAttempts` →
   rate-limited. This caps vendor calls per challenge locally.
4. `transport.checkVerification(phone, reference, code)`.
5. `approved` → `delete` the challenge (single use), then
   `authenticateWithIdentifier` and clear the cookie — identical to the local
   path from here. Any other status maps to the existing error responses.

The local expiry (`expiry`, default 10m) is a ceiling on our challenge record,
not the vendor's code lifetime; the vendor enforces its own (Twilio's default
is 10 minutes). Whichever fires first ends the attempt, which is the safe
direction.

## Inert configuration on the hosted path

`otp.length`, `messageTemplate`, and `webOtpDomain` describe a message this
package no longer composes — the vendor does. They are documented as
local-path-only rather than silently accepted. WebOTP autofill is still
available on Twilio Verify, but through Verify's own `AppHash` parameter and
message templates, not `webOtpDomain`.

`otp.maxAttempts` and `otp.cookieName` still apply: both are ours.

## Twilio Verify transport

`https://verify.twilio.com/v2/Services/{ServiceSid}`, Basic auth with Account
SID and Auth Token — the same credentials `TwilioMessagingTransport` already uses.

- Start: `POST /Verifications` with `To` and `Channel=sms`. Response `sid` is
  kept as the reference (Twilio checks by `To`, so it is diagnostic rather than
  required).
- Check: `POST /VerificationCheck` with `To` and `Code`. `status: "approved"`
  → approved. `max_attempts_reached` → rate_limited. `expired`/`canceled` →
  expired. Anything else pending/failed → invalid_code.
- Twilio returns HTTP 404 from `VerificationCheck` once a verification is
  consumed or has aged out; that maps to expired rather than a hard error.
  Log the body anyway — a wrong `serviceSid` and a wrong path produce the
  same 404, and silently calling either one "expired" is undiagnosable.

**The check resource is singular.** `POST .../VerificationCheck`, not
`VerificationChecks`. The plural is how the Twilio helper libraries name the
method (`verificationChecks.create()`); over raw HTTP it 404s with error 20404. Any vendor transport written from SDK docs rather than the HTTP
reference is exposed to this class of mistake, and unit tests written
alongside the implementation cannot catch it.

`channel` is configurable (`sms` default; `call` and `whatsapp` are the useful
others) and `locale`/`templateSid`/`appHash` are passed through when set.

Code length is a property of the Verify service (`code_length`, 4-10, default
6), not of the API call, and the start response does not return it. An app
that needs it for its UI must be told, or fetch `GET /v2/Services/{sid}`.

## Security notes

- The plaintext code never reaches this process on the hosted path, so there is
  nothing new at rest; the challenge record holds a phone number and a vendor
  reference.
- The attempt counter increments before the vendor call, so a guesser cannot
  spend our vendor budget beyond `maxAttempts` per challenge.
- Successful verification deletes the challenge, so a replayed code fails at
  step 2 rather than being re-approved by the vendor.
- The initiate response is identical whether the number was throttled, invalid
  at the vendor, or genuinely texted, preserving the existing non-enumeration
  behavior.
