# @activescott/auth-provider-passkey

[![npm version](https://img.shields.io/npm/v/@activescott/auth-provider-passkey.svg)](https://www.npmjs.com/package/@activescott/auth-provider-passkey)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Passkey (WebAuthn) provider for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth). Users add a passkey while signed in (via email or SMS first), then sign in usernameless with Touch ID, Face ID, Windows Hello, Android, 1Password, iCloud Keychain, or a security key.

Server-side WebAuthn verification uses [`@simplewebauthn/server`](https://simplewebauthn.dev/) (WebCrypto-based). A zero-dependency browser client ships as the `@activescott/auth-provider-passkey/browser` subpath export.

## Usage

Server wiring:

```ts
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import {
  PasskeyProvider,
  InMemoryCredentialStore,
} from "@activescott/auth-provider-passkey"

const auth = new Auth({
  session: { secret: process.env.JWT_SECRET! /* ... */ },
  userStore,
  identityStore,
  challengeStore: new InMemoryChallengeStore(), // DB-backed in production
  providers: [
    new PasskeyProvider({
      rpName: "MyApp",
      credentialStore: new InMemoryCredentialStore(), // DB-backed in production
      challengeSecret: process.env.JWT_SECRET!,
    }),
  ],
})
```

Browser (all four endpoints are fetch/JSON — WebAuthn ceremonies run in page JavaScript, not form navigations):

```ts
import {
  startRegistration,
  startAuthentication,
} from "@activescott/auth-provider-passkey/browser"

// Add a passkey (user must be signed in):
const regOptions = await fetch("/auth/passkey/register-options", {
  method: "POST",
}).then((r) => r.json())
const registration = await startRegistration(regOptions)
await fetch("/auth/passkey/register-verify", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(registration),
})

// Sign in with a passkey:
const authOptions = await fetch("/auth/passkey/authenticate-options", {
  method: "POST",
}).then((r) => r.json())
const assertion = await startAuthentication(authOptions)
const result = await fetch("/auth/passkey/authenticate-verify", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(assertion),
})
if (result.ok) location.assign("/dashboard") // session cookie is set
```

For conditional UI (passkey autofill on the login form), add `autocomplete="username webauthn"` to your username/email input and start a conditional request on page load:

```ts
import {
  startAuthentication,
  isConditionalUIAvailable,
} from "@activescott/auth-provider-passkey/browser"

if (await isConditionalUIAvailable()) {
  const options = await fetch("/auth/passkey/authenticate-options", {
    method: "POST",
  }).then((r) => r.json())
  // Resolves when the user picks a passkey from the autofill suggestions
  const assertion = await startAuthentication(options, { conditional: true })
  // POST to /auth/passkey/authenticate-verify as above
}
```

## Endpoints

| Endpoint                                  | Auth required | Purpose                                                                         |
| ----------------------------------------- | ------------- | ------------------------------------------------------------------------------- |
| `POST /auth/passkey/register-options`     | session       | Registration options for adding a passkey to the signed-in user                 |
| `POST /auth/passkey/register-verify`      | session       | Verify the attestation, store the credential, link a passkey identity           |
| `POST /auth/passkey/authenticate-options` | none          | Authentication options (empty `allowCredentials` → any discoverable credential) |
| `POST /auth/passkey/authenticate-verify`  | none          | Verify the assertion and set the session cookie                                 |

Registration model: **add-passkey-while-signed-in**. Users sign in with another provider (email, SMS) first, then add a passkey from a settings/dashboard page; afterwards they can sign in usernameless. Passkey-first signup is not supported.

## Configuration

| Option                | Default                    | Description                                                             |
| --------------------- | -------------------------- | ----------------------------------------------------------------------- |
| `rpName`              | (required)                 | Relying party name shown in authenticator prompts                       |
| `rpID`                | request hostname           | Relying party ID; set explicitly in production (e.g. `"myapp.example"`) |
| `expectedOrigin`      | request origin             | Expected WebAuthn origin (e.g. `"https://myapp.example"`)               |
| `credentialStore`     | (required)                 | Storage for registered credentials (see below)                          |
| `challengeSecret`     | (required)                 | Signs the short-lived challenge cookie                                  |
| `challengeExpiry`     | `"5m"`                     | Challenge lifetime                                                      |
| `challengeCookieName` | `"auth_passkey_challenge"` | Challenge cookie name                                                   |
| `challengeStore`      | (off)                      | Opt into strict single-use challenges (see below)                       |

## CredentialStore

The only interface an app implements. Use the shipped `InMemoryCredentialStore` for development; back it with your database for production:

```sql
CREATE TABLE passkey_credentials (
  credential_id TEXT PRIMARY KEY, -- base64url WebAuthn credential ID
  public_key    TEXT NOT NULL,    -- base64url COSE public key
  counter       BIGINT NOT NULL,
  transports    TEXT,             -- JSON array, e.g. '["internal","hybrid"]'
  user_id       TEXT NOT NULL REFERENCES users (id),
  device_type   TEXT NOT NULL,    -- 'singleDevice' | 'multiDevice'
  backed_up     BOOLEAN NOT NULL,
  nickname      TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at  TIMESTAMPTZ
);
CREATE INDEX passkey_credentials_user_id ON passkey_credentials (user_id);
```

```ts
interface CredentialStore {
  findById(credentialId: string): Promise<StoredCredential | null>
  findByUserId(userId: string): Promise<StoredCredential[]>
  create(data): Promise<StoredCredential>
  updateCounterAndLastUsed(credentialId: string, counter: number): Promise<void>
  delete?(credentialId: string): Promise<void>
}
```

## Challenges

Challenges are stateless by default: the options endpoints set an HttpOnly, SameSite=Lax cookie containing a signed JWT (`challengeSecret`, 5-minute expiry) and the verify endpoints require it. That means no storage, but a challenge could in principle be redeemed more than once within its 5-minute window. Pass a `challengeStore` to make challenges strictly single-use — each is recorded on issue and consumed on the first redemption attempt.

## Cross-platform notes

- **Synced passkeys** (iCloud Keychain, Google Password Manager, 1Password) report `deviceType: "multiDevice"` and usually a signature counter of 0. A counter regression is logged as a warning but does **not** fail authentication — synced passkeys regress counters legitimately, so blocking would lock out real users.
- **rpID scoping**: a passkey is bound to its relying party ID. `localhost` works for development; production passkeys must be created on the production domain. Subdomains of the rpID can use the credential; a different registrable domain cannot.
- **Authenticator choice is the user's**: options are generated with `residentKey: "preferred"`, `userVerification: "preferred"`, and no `authenticatorAttachment`, so platform authenticators, password managers, and roaming security keys all work.
- **Algorithms**: ES256 and RS256 are accepted, covering Apple, Google, Microsoft, and common security keys.
