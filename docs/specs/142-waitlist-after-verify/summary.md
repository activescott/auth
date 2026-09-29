# Waitlist after verify: summary

Issue #142. The waitlist ran in `gate.onInitiate`, before the address was verified, so anyone could create a PENDING user and an admin email for an address they don't own. It now runs in a new optional `gate.onVerified`, which `Auth.handleRequest` calls after a provider's verify succeeds and before the session is created.

## Decisions

- **`onVerified` lives on `InitiateGate`** rather than a new `AuthConfig` field, so apps keep passing `gate: waitlist`. It takes the initiate input plus `user`, `identity`, and `isNewUser`, and returns the same decisions. A redirect carries the provider's cookies (the cleared challenge) and no session; an error goes through the failure responder like a bad code.
- **Auth calls it, not the providers.** Every verify route already returns through `Auth`, so no provider package changes and a stale provider cannot skip it. Passkey routes are actions and skip it; `redirectFor` still covers them.
- **`AuthSuccess` gains optional `mode` and `isNewUser`**, set by `authenticateWithIdentifier` and `completeLinkVerification`. A custom provider that leaves them out is treated as a sign-in by an existing user.
- **`Waitlist.onInitiate` always allows**, including for BLOCKED users: answering them differently at initiate would tell anyone which addresses are blocked. They get a code and are turned away at verify.
- **A verified, non-approved user gets no session.** Previously they never got a code; a session would let apps that skip the per-request `redirectFor` check admit them.
- **`WaitlistConfig.identityStore` and `userStore` are deprecated and optional.** The verify step creates the user now, so the waitlist no longer needs them.

## Compatibility

No export is removed and no type narrows, so existing configurations compile. Behavior changes: unknown addresses now receive a sign-in message, and `autoApprove` and `notify` run at verify rather than at initiate. `AutoApproveInput.request` is the verify request.
