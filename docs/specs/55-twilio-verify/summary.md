# Summary — issue #55 hosted verification (Twilio Verify)

Status: implemented, and verified end to end against a live Twilio Verify
service — a texted code signs in through the example app.

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

## Commit layout (one scope per commit — do NOT squash-merge)

Oldest first. The three `feat`/`fix` scopes are what drive releases; the
`docs:`/`chore:`/`refactor:` commits carry no scope and publish nothing.

1. `feat(auth-provider-sms): accept a hosted VerificationTransport`
2. `feat(auth-sms-twilio): add a Twilio Verify transport`
3. `docs(examples): wire Twilio Verify into the react-router example`
4. `docs: document hosted verification` — root `README.md`, `AGENTS.md`
5. `chore: remove the interactive Twilio provisioning script`
6. `refactor: namespace the Twilio SMS-only env vars as TWILIO_SMS_*`
7. `docs: present Twilio Verify and Twilio Messaging as two SMS setups`
8. `docs: link the Twilio console pages the SMS env vars come from`
9. `fix(auth-sms-twilio): correct the Verify log URL`
10. `docs(examples): correct the Verify log URL`
11. `fix(auth-sms-twilio): log why a Verify check was not approved`
12. `fix(auth-sms-twilio): use the singular VerificationCheck endpoint`
13. `docs: correct the Verify check endpoint in the spec`
14. `feat(auth-adapter-react-router): pass the request to errorRedirect`
15. `fix(examples): keep the tab on error, auto-submit codes, drop the load-time passkey prompt`
16. `docs: record what the live Verify run found`

Releases: `auth-provider-sms` and `auth-sms-twilio` take a minor bump from
their `feat` commits, `auth-adapter-react-router` a minor from #14. The
multi-package PR must be merged with a merge commit so each scope keeps its
own commit, or the packages do not all publish.

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
- **Live run against a real Twilio Verify service** — a texted code signs in
  through the example app. This is what caught the three defects in "Found
  only by running it live" below; every one of them survived a green unit
  suite.

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

## Found only by running it live

Three defects shipped through a green unit suite, all of the same kind: the
tests asserted what the implementation did, and the implementation was built
from a reading of Twilio's docs. A mock cannot disagree with you about what a
vendor's API looks like.

1. **The check endpoint was wrong.** The REST resource is
   `POST /v2/Services/{ServiceSid}/VerificationCheck` — singular. The plural
   `VerificationChecks` is the _helper library_ method name
   (`verificationChecks.create()`). Over raw HTTP the plural path returns 404
   with error 20404, and the transport mapped 404 to `expired`, so **every
   correct code was rejected as expired**. The 11 transport tests all passed,
   because they asserted the URL the implementation built.
2. **The Verify console log URL 404s.** It is
   `/us1/monitor/logs/verify-logs`, not `/us1/monitor/logs/verify`. That URL
   is printed on every failure, so the one link offered for diagnosis was
   itself broken.
3. **A 404 from the check was swallowed.** Mapping it straight to `expired`
   with nothing logged made a correct code look like an aged-out one, and hid
   both a wrong `serviceSid` and defect 1. Both non-approved paths now log.

Worth repeating for the next vendor transport: verify the REST path against
the vendor's HTTP reference, not its SDK surface, and never map an HTTP error
to a user-facing status without logging the body.

Also live-only, in the example app rather than the transport:

- A failed verification answered on the email tab even when submitted from
  the phone tab. The adapter built `"/login?error=<code>"` from scratch,
  discarding `?via=sms`. `errorRedirect` now takes `(error, request)` so the
  app can return `buildReturnUrl(request, ...)`.
- The code form now submits itself on the last digit, which is what makes
  Safari's autofill from Messages finish the sign-in. Digit count is a prop
  defaulting to 6: Verify's `code_length` (4-10) lives on the Verify service
  and is **not** in the start response, so it cannot be read at runtime
  without a separate `GET /v2/Services/{sid}`.
- The conditional-UI passkey request on page load reads as an unsolicited
  prompt, because password manager extensions answer it with their own dialog
  instead of the silent autofill the spec intends. Off by default now.

## Follow-ups

- A second `VerificationTransport` (Vonage Verify v2 is the closest fit) to
  prove the interface is genuinely vendor-neutral.
- Nothing exercises the Verify path in CI. A contract test against Twilio's
  API (or a recorded fixture taken from a live call) would have caught the
  endpoint defect; hand-written mocks structurally cannot.

## Changed during review

- `infra/twilio/setup-twilio.mts` (the whole `infra/` tree) was deleted. It
  automated buying a number and writing `.env`, but the cost of the raw-SMS
  path is A2P 10DLC registration — days to weeks of brand and campaign
  approval that no script can shorten. Verify is the actual "quick start", so
  the script promised a speed it could not deliver. Its `writeEnv` also
  stripped every `TWILIO_*` line from an existing `.env` before rewriting,
  which would have silently deleted a user's `TWILIO_VERIFY_SERVICE_SID`.
- `TwilioTransport` was renamed `TwilioMessagingTransport` (and
  `twilio-transport.ts` → `twilio-messaging-transport.ts`). Twilio sells two
  products that both text a code; once the docs started calling them "Twilio
  Verify" and "Twilio Messaging", a class named for neither was the odd one
  out. Breaking for `@activescott/auth-sms-twilio` consumers — published at
  0.1.1, so no deprecated alias was left behind.
- The SMS-only env vars were namespaced: `TWILIO_FROM` →
  `TWILIO_SMS_FROM`, `TWILIO_MESSAGING_SERVICE_SID` →
  `TWILIO_SMS_MESSAGING_SERVICE_SID`. `TWILIO_ACCOUNT_SID` and
  `TWILIO_AUTH_TOKEN` stay unprefixed because both transports use them;
  `TWILIO_VERIFY_SERVICE_SID` already followed the convention. The transport
  constructor options (`from`, `messagingServiceSid`, `serviceSid`) are
  unchanged — they are already scoped by which class you construct.
