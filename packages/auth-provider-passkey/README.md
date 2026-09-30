# @activescott/auth-provider-passkey

[![npm version](https://img.shields.io/npm/v/@activescott/auth-provider-passkey.svg)](https://www.npmjs.com/package/@activescott/auth-provider-passkey)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Passkey (WebAuthn) provider for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth). Users add a passkey while signed in (via email or SMS first), then sign in usernameless with Touch ID, Face ID, Windows Hello, Android, 1Password, iCloud Keychain, or a security key.

Server-side WebAuthn verification uses [`@simplewebauthn/server`](https://simplewebauthn.dev/) (WebCrypto-based). A zero-dependency browser client ships as the `@activescott/auth-provider-passkey/browser` subpath export.

## Usage

Server wiring — **no new storage interface**; passkeys reuse the `IdentityStore` you already have:

```ts
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import { PasskeyProvider } from "@activescott/auth-provider-passkey"

const auth = new Auth({
  session: { secret: process.env.JWT_SECRET! /* ... */ },
  userStore,
  identityStore,
  challengeStore: new InMemoryChallengeStore(), // DB-backed in production
  providers: [
    // other providers such as email and/or SMS go here too — users add
    // a passkey while signed in, so another provider handles first sign-in
    new PasskeyProvider({
      rpName: "MyApp",
      // Bind passkeys to your canonical domain in production; leave unset in
      // dev so rpID and origin derive from each request (e.g. localhost).
      appUrl:
        process.env.NODE_ENV === "production" ? process.env.APP_URL : undefined,
      challengeSecret: process.env.JWT_SECRET!,
    }),
  ],
})
```

Browser (all four endpoints are fetch/JSON — WebAuthn ceremonies run in page JavaScript, not form navigations). `createPasskeyClient` fetches the options, runs the ceremony, and posts the result:

```ts
import { createPasskeyClient } from "@activescott/auth-provider-passkey/browser"

const passkeys = createPasskeyClient() // basePath defaults to "/auth"

// Add a passkey (user must be signed in):
await passkeys.registerPasskey()

// Sign in with a passkey:
await passkeys.signInWithPasskey()
location.assign("/dashboard") // session cookie is set
```

Both throw when the user cancels or the server rejects the request. A server rejection's `Error.message` is the most specific text the response carries — the error's `details.reason` (e.g. `"Unknown credential"`, a passkey saved in a password manager whose identity the server no longer has), else its `message` — so it is fit to show the user.

For conditional UI (passkey autofill on the login form), add `autocomplete="username webauthn"` to your username/email input and start a conditional request on page load:

```ts
import {
  createPasskeyClient,
  isConditionalUIAvailable,
} from "@activescott/auth-provider-passkey/browser"

if (await isConditionalUIAvailable()) {
  // Resolves once the user picks a passkey from the autofill suggestions and
  // the server has set the session cookie. A later signInWithPasskey() call
  // (e.g. from a button) aborts this pending request.
  await createPasskeyClient().signInWithPasskey({ conditional: true })
  location.assign("/dashboard")
}
```

`startRegistration` and `startAuthentication` are still exported for code that runs the HTTP round trips itself, but are deprecated in favor of the client.

## Endpoints

| Endpoint                                  | Auth required | Purpose                                                                         |
| ----------------------------------------- | ------------- | ------------------------------------------------------------------------------- |
| `POST /auth/passkey/register-options`     | session       | Registration options for adding a passkey to the signed-in user                 |
| `POST /auth/passkey/register-verify`      | session       | Verify the attestation, store the credential, link a passkey identity           |
| `POST /auth/passkey/authenticate-options` | none          | Authentication options (empty `allowCredentials` → any discoverable credential) |
| `POST /auth/passkey/authenticate-verify`  | none          | Verify the assertion and set the session cookie                                 |

Registration model: **add-passkey-while-signed-in**. Users sign in with another provider (email, SMS) first, then add a passkey from a settings/dashboard page; afterwards they can sign in usernameless. Passkey-first signup is not supported.

## Configuration

| Option                | Default                                  | Description                                                           |
| --------------------- | ---------------------------------------- | --------------------------------------------------------------------- |
| `rpName`              | (required)                               | Relying party name shown in authenticator prompts                     |
| `appUrl`              | (unset)                                  | Canonical app URL (e.g. `"https://myapp.example"`); set in production |
| `rpID`                | `appUrl` hostname, else request hostname | Relying party ID; overrides `appUrl` (e.g. a parent domain)           |
| `expectedOrigin`      | `appUrl` origin, else request origin     | Expected WebAuthn origin; overrides `appUrl`                          |
| `challengeSecret`     | (required)                               | Signs the short-lived challenge cookie                                |
| `challengeExpiry`     | `"5m"`                                   | Challenge lifetime                                                    |
| `challengeCookieName` | `"auth_passkey_challenge"`               | Challenge cookie name                                                 |

## Storage: passkeys are identities

Each passkey is an ordinary identity row — `{provider: "passkey", identifier: <base64url credential ID>}` — so your existing `IdentityStore` is the only storage involved. The credential's verification state (public key, signature counter, transports, device type, ...) lives in the row's provider-owned `Identity.metadata`. Your store treats that metadata as an opaque JSON blob: persist it unmodified and return it exactly as stored — the provider validates it with a [zod](https://zod.dev) schema on every read and writes it back wholesale via `IdentityStore.update` after each sign-in (counter + last-used). A typical identities table:

```sql
CREATE TABLE identities (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users (id),
  provider    TEXT NOT NULL,       -- 'email' | 'sms' | 'passkey' | ...
  identifier  TEXT NOT NULL,       -- email, E.164 phone, or WebAuthn credential ID
  metadata    JSONB NOT NULL DEFAULT '{}', -- provider-owned; opaque to the app
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  verified_at TIMESTAMPTZ,
  UNIQUE (provider, identifier)
);
CREATE INDEX identities_user_id ON identities (user_id);
```

Metadata may contain sensitive material — treat it like credential data (encryption at rest is a reasonable default). Integrity matters more than secrecy here: anyone who can write this column can register their own key, so guard writes accordingly.

To list a user's passkeys for a settings page, `listPasskeys` filters their identities to passkeys, validates each row's provider state (skipping invalid rows), and returns plain JSON you can hand straight to the page:

```ts
import { listPasskeys } from "@activescott/auth-provider-passkey"

const passkeys = await listPasskeys(identityStore, user.id)
// [{ credentialId, nickname: string | null, synced: boolean,
//    createdAt: ISO string, lastUsedAt: ISO string | null }, ...]
```

The markup is yours; `synced` is true for passkeys synced to a cloud keychain or password manager.

## Challenges

The options endpoints set an HttpOnly, SameSite=Lax cookie containing a signed JWT (`challengeSecret`, 5-minute expiry) that binds the ceremony to the browser, and record the challenge in the core `challengeStore`. The verify endpoints require both and consume the stored challenge on the first redemption attempt — success or not — so every challenge is strictly single-use.

## Cross-platform notes

- **Synced passkeys** (iCloud Keychain, Google Password Manager, 1Password) report `deviceType: "multiDevice"` and usually a signature counter of 0. A counter regression is logged as a warning but does **not** fail authentication — synced passkeys regress counters legitimately, so blocking would lock out real users.
- **rpID scoping**: a passkey is bound to its relying party ID. `localhost` works for development; production passkeys must be created on the production domain. Subdomains of the rpID can use the credential; a different registrable domain cannot.
- **Authenticator choice is the user's**: options are generated with `residentKey: "preferred"`, `userVerification: "preferred"`, and no `authenticatorAttachment`, so platform authenticators, password managers, and roaming security keys all work.
- **Algorithms**: ES256 and RS256 are accepted, covering Apple, Google, Microsoft, and common security keys.
