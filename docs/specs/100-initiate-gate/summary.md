# Initiate gate — summary

Issue #100. Adds `AuthConfig.gate.onInitiate({ provider, identifier, mode, request })`, returning `"allow" | { redirect } | { error }`, so an app's rule about who may be sent a sign-in message (allowlist, invite-only beta) runs inside `Auth.handleRequest` instead of in a request-clone-and-parse preamble in the app's auth route.

## Why inside the provider flow

The motivating bug: an app's own pre-library gate parsed the raw form field and acted on it (creating users) before the provider had validated it, so malformed addresses got through. The gate therefore runs only after the provider has parsed, normalized and validated the identifier, and before any challenge is created or message sent. Only the provider knows how to parse its identifier, so the provider calls the gate through `AuthContext.gate.check`, the same pattern as `AuthContext.abuse.checkIdentifier`.

Order inside the email and SMS `initiate`: parse → normalize → validate → link-mode session check → per-recipient abuse check → gate → create challenge and send.

## Decisions

- **`{ redirect }`** answers every caller with a 302 to the given URL. The URL is app configuration, so it is not restricted to the request's origin.
- **`{ error }`** takes an `AuthError` and answers exactly like a provider's own initiate failure: browser form posts go back to the Referer with `?error=<code>`, fetch callers get `{ success: false, error }` with the code's usual status.
- **A throwing gate** fails the initiate (the provider's catch turns it into `PROVIDER_ERROR`); nothing is sent.
- **`request`** is a clone taken before the provider reads the body, so the gate can still read it.
- **Stale providers fail closed.** Provider packages declare `@activescott/auth` as a `^5` peer, so an app can pair a new core with a provider that predates the gate. With `gate` set, the `Auth` constructor throws if any provider serving an `initiate` route lacks `consultsInitiateGate: true`. Apps that do not set `gate` are unaffected.

## Compatibility

Additive only: new optional `AuthConfig.gate`, `AuthContext.gate`, and `AuthProvider.consultsInitiateGate`. No existing export is replaced, so nothing is deprecated.
