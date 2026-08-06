# Plan — issue #55: hosted verification provider (Twilio Verify)

Issue: https://github.com/activescott/auth/issues/55

Goal: let an app do SMS sign-in without registering its own US A2P 10DLC brand
and campaign, by delegating code generation, delivery, and checking to a hosted
verification service (Twilio Verify first).

## Tasks

1. Save this plan to `docs/specs/55-twilio-verify/plan.md`.
2. Research alternatives to Twilio Verify and record the survey in `spec.md`
   (issue explicitly asks for this).
3. Add a `VerificationTransport` interface to `@activescott/auth-provider-sms`
   (`src/types.ts`) alongside the existing `SmsTransport`.
4. Branch `SmsProvider` on which transport kind it was constructed with, using
   an exported type guard. Routes, cookie binding, abuse checks, and the login
   form stay identical.
5. Add `TwilioVerifyTransport` to `@activescott/auth-sms-twilio` (raw fetch,
   zero deps, same shape as the existing `TwilioTransport`).
6. Tests: provider-side verification flow (initiate/verify, failure mapping,
   attempt cap, cookie binding) and transport-side fetch shape/status mapping.
7. Wire the example app so `TWILIO_VERIFY_SERVICE_SID` selects the Verify path;
   e2e keeps forcing `ConsoleTransport`.
8. Docs: root README feature + package table, `auth-provider-sms` README,
   `auth-sms-twilio` README, example `.env.example` / README.
9. Commit per package scope (commitlint `scope-enum`), open PR, note the PR must
   be merged with a merge commit — never squashed (multi-package).
10. Write `summary.md`.

## Design

`SmsProvider` today owns the secret: it generates the code, hashes it into a
`Challenge`, and compares on verify. A hosted verification service owns the
secret instead — it generates, delivers, and checks the code, and never gives
it to us. So the provider cannot reuse `verifyOtpChallenge`.

What still belongs to us in the hosted case:

- E.164 normalization (unchanged).
- The `AbuseGuard` identifier check on initiate (unchanged) — the local rate
  limit is what stops a caller burning money at $0.05 per successful
  verification.
- The challenge record + HttpOnly cookie. Still needed: `/auth/sms/verify`
  receives only a code, so the phone number has to be recovered from
  server-side state bound to this browser. The record holds no `hashedCode`;
  it holds the vendor's opaque reference in `Challenge.data`.
- A local attempt cap, so a guesser cannot make unbounded vendor calls.

Interface (vendor-neutral — shaped to fit Vonage Verify v2 as well as Twilio):

```ts
export interface VerificationTransport {
  startVerification(to: string): Promise<VerificationStart>
  checkVerification(
    to: string,
    reference: string | undefined,
    code: string,
  ): Promise<VerificationCheck>
}
```

`startVerification` returns an opaque `reference` because Vonage Verify v2
checks against a `request_id`, while Twilio Verify checks against the phone
number. Carrying both covers each vendor without a Twilio-shaped interface.

`checkVerification` returns a discriminated status
(`approved | invalid_code | expired | rate_limited | error`) that maps onto the
error responses `SmsProvider` already produces for the local-OTP path, so the
example login form needs no new error handling.

## Constraints

- No changes to `packages/auth`. Everything needed (`ChallengeStore.data`,
  optional `hashedCode`, `initiateAccepted`, cookie helpers) already exists and
  is exported.
- Zero runtime deps in both packages; raw `fetch` only.
- No `as` casts; discriminate with type guards.
- Config keys that the vendor owns (`otp.length`, `messageTemplate`,
  `webOtpDomain`, `expiry`) are inert on the hosted path — document, do not
  silently pretend they work.

## Out of scope

- A second vendor implementation (Vonage/Prelude). The interface is designed to
  accept one; shipping one is a follow-up.
- Extending `infra/twilio/setup-twilio.mts` to create a Verify service. Noted in
  docs as a two-click console step instead.
