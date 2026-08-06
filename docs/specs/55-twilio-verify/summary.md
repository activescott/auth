# Summary — issue #55 hosted verification (Twilio Verify)

Status: implemented and verified on branch `worktree-55-twilio-verify`.

## Resume commands

Run from the repo root (this was developed in a git worktree, which needs its
own `npm install` — it does not share the main checkout's `node_modules`):

```bash
npm install
npm run build && npm test && npm run lint

# e2e (needs the packages built first, which the build above does)
npm run install-browsers -w examples/react-router/tests   # once
npm run e2e -w examples/react-router/tests
```

## Commit layout (one per commitlint scope — do NOT squash-merge)

1. `feat(auth-provider-sms): accept a hosted VerificationTransport`
   - `packages/auth-provider-sms/src/{types,sms-provider,index}.ts`
   - `packages/auth-provider-sms/src/__tests__/sms-provider.test.ts`
   - `packages/auth-provider-sms/README.md`
2. `feat(auth-sms-twilio): add a Twilio Verify transport`
   - `packages/auth-sms-twilio/src/twilio-verify-transport.ts` (new)
   - `packages/auth-sms-twilio/src/index.ts`
   - `packages/auth-sms-twilio/src/__tests__/twilio-verify-transport.test.ts` (new)
   - `packages/auth-sms-twilio/README.md`
3. `docs(examples): wire Twilio Verify into the react-router example`
   - `examples/react-router/app/lib/auth.server.ts`, `.env.example`, `README.md`
4. `docs: document hosted verification` — root `README.md`, `AGENTS.md`

Both packages get a minor bump from `feat`. The multi-package PR must be merged
with a merge commit so each scope keeps its own commit, or neither package
publishes correctly.

## What was built

`SmsProvider` now accepts `SmsTransport | VerificationTransport`. The second is
for services that own the code end to end (Twilio Verify), which is what makes
US A2P 10DLC registration unnecessary. `TwilioVerifyTransport` implements it
against `https://verify.twilio.com/v2` with raw fetch and no new dependencies.

Design detail worth keeping: `checkVerification(to, reference, code)` carries
_both_ the phone number and an opaque vendor reference. Twilio checks by phone
number; Vonage Verify v2 checks by the `request_id` its start call returns.
Carrying only one would have made the interface Twilio-shaped. The reference is
persisted in `Challenge.data.verificationReference`.

The hosted path stores no `hashedCode`. `redeemVendorChallenge` in
`sms-provider.ts` is the counterpart to core's `verifyOtpChallenge`: same type,
expiry, attempt-cap, and single-use checks, with the comparison delegated. The
attempt counter increments **before** the vendor call, which is both the
guessing defense and the cap on billable vendor checks per challenge.

`packages/auth` was not touched — `Challenge.data`, optional `hashedCode`, and
the provider utilities already supported this.

## Vendor survey

Recorded in `spec.md`. Short version: hosted verification is ~$0.05 per
verification across Twilio, Vonage, Sinch, and Bird — the price is a commodity
and the differentiator is API quality and onboarding friction. The one cheaper
claim found (Message Central VerifyNow, $0.005–$0.0085) is sourced only to that
vendor's own comparison page, whose 10DLC claims about competitors do not match
those vendors' documentation, so it is recorded as unverified rather than
recommended.

## Verification performed

- `npm run build` — clean across all workspaces.
- `npm test` — 245 tests pass. New: 10 provider tests for the hosted path
  (`SmsProvider with a VerificationTransport`), 11 transport tests.
- `npm run lint` — prettier clean.
- `npm run e2e -w examples/react-router/tests` — 24 passed. E2e forces
  `ConsoleTransport`, so the Verify path is not exercised there by design.
- **Not** verified against a live Twilio Verify service — no billable
  verification was ever sent. The request/response shapes come from Twilio's
  API docs. Someone should run one real verification before relying on it.

## Gotchas found

- The example's `CaptureSmsTransport` (e2e code readback) only makes sense for
  `SmsTransport`; with Verify there is no code in-process to capture. Hence
  `wrapForE2eReadback` in `auth.server.ts`, which passes a verification
  transport straight through.
- `npm run typecheck` at the repo root fails on the nested
  `examples/react-router/tests` workspace with `Missing script: "typecheck"`.
  That is pre-existing, not caused by this work.
- The worktree needs its own `npm install`; it does not share the main
  checkout's `node_modules`.

## Follow-ups

- A live smoke test against a real Verify service.
- A second `VerificationTransport` (Vonage Verify v2 is the closest fit) to
  prove the interface is genuinely vendor-neutral.
- `infra/twilio/setup-twilio.mts` could create the Verify service
  (`POST /v2/Services`) instead of leaving it as a console step.
