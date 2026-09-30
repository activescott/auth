# Waitlist: summary

Issue #103. Adds `createWaitlist`, an `InitiateGate` for apps that approve new users by hand, and `waitlistNotificationEmail`, the admin notice. Two production apps each carried their own copy of this flow; this is the part they share.

## The shared flow

Both apps keep `approvalStatus: PENDING | APPROVED | BLOCKED` on the user row. On a sign-in initiate, an approved user proceeds, a blocked user is turned away, and an identifier with no account gets a PENDING user, an email to admins, and a redirect to the waitlist page. An allowlist of addresses skips the waitlist. Admins approve or block from their users page. One app also approves someone automatically when an approved user has already shared a file with them; that rule is app policy, so it goes in the `autoApprove` hook rather than the library.

## Decisions

- **The status stays in the app's database**, behind `ApprovalStore` (`getApprovalStatus`, `setApprovalStatus`). Its values match the enum both apps already have, so no mapping. A missing status counts as not approved.
- **Unknown identifiers get their user and identity at initiate**, with the same `userStore.create` and `identityStore.create` calls the verify step makes, so the admin page lists them before any code is sent and verify finds that identity instead of creating a second user.
- **Link initiates pass.** They come from a signed-in user; running the identifier rules would create a ghost user for the new identifier.
- **Blocked users go to `blockedUrl`**, which defaults to the waitlist page so a block is not announced. No new `AuthErrorCode`: adding one would break exhaustive switches in consumers.
- **`autoApprove` never sees BLOCKED users**, so no app rule can undo a block.
- **`notify` fires once per user joining** (`reason: "waitlisted"`) and on every auto-approval (`"auto-approved"`); the app filters on `reason`. A throw is logged and swallowed, since the notice is about something that already happened.
- **The gate does not see passkey sign-ins or a block that lands after sign-in**, so `redirectFor(userId)` exists for a per-request check (the React Router adapter's `onSessionVerified`).
- **The email is rendered, not sent.** The core has no mail dependency, and `EmailTransport` only knows how to send sign-in messages; widening that interface would break custom transports. `waitlistNotificationEmail` returns `{ from, subject, text, html }`, which nodemailer's `sendMail` takes once `to` is added.
- **No adapter change.** Approve and block buttons are app markup in `rowActions`; the server half is `waitlist.handleAdminAction(formData)` (fields `userId`, `intent`).

## Approval email to the user

Added after the first release, for a third consumer that needs it. Both apps send one from their approve action, so it moves behind an `onApproved` hook that `approve` and `handleAdminAction` call when the status changes to APPROVED from anything else. An already-approved user is skipped so a second click sends nothing. `autoApprove` does not call it, since that user is mid-sign-in. The hook gets the user's identities rather than an address because the library does not know which one the app writes to. `waitlistApprovalEmail` renders the message the same way `waitlistNotificationEmail` does.

## Compatibility

Additive only: new exports from `@activescott/auth` and a new optional `WaitlistConfig.onApproved`. `WaitlistNotice.reason` is unchanged; widening it would break exhaustive switches. No existing export is replaced, so nothing is deprecated. The admin subpath is untouched.
