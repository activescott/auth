# @activescott/auth-provider-oidc

[![npm version](https://img.shields.io/npm/v/@activescott/auth-provider-oidc.svg)](https://www.npmjs.com/package/@activescott/auth-provider-oidc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

OpenID Connect provider for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth): the authorization code flow with PKCE, and ID token validation per [OIDC Core 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation). Provider-specific adapters are configurations of one `OidcProvider`; Sign in with Slack ships as `createSlackProvider`.

The only runtime dependency is [`jose`](https://github.com/panva/jose), which the core already uses.

## Usage

```ts
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import { createSlackProvider } from "@activescott/auth-provider-oidc"

const auth = new Auth({
  // session, userStore, identityStore ...
  challengeStore: new InMemoryChallengeStore(), // DB-backed in production
  providers: [
    createSlackProvider({
      clientId: process.env.SLACK_CLIENT_ID!,
      clientSecret: process.env.SLACK_CLIENT_SECRET!,
    }),
  ],
})
```

Register `https://your.app/auth/slack/callback` as a redirect URL in the Slack app. For any other OpenID Provider, construct `OidcProvider` with its `issuer`, `clientId`, `clientSecret`, an `id` for the routes, and optionally `scopes` and `identify`.

## Endpoints

| Endpoint                    | Purpose                                                                                                     |
| --------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `GET/POST /auth/{id}/start` | Redirect to the provider. `mode=link` attaches the identity to the signed-in user; `redirectTo` for a link. |
| `GET /auth/{id}/callback`   | The redirect URI. Checks state, redeems the code, validates the ID token, then signs in or links.           |

A sign-in button can be a plain link to `/auth/slack/start`. State, nonce and the PKCE verifier are stored as a single-use challenge in your `ChallengeStore`, bound to the browser by an HttpOnly cookie, so a callback is accepted once and only in the browser that started it.

## Linking without a new session

`/auth/slack/start?mode=link&redirectTo=/settings` requires a session. When the callback succeeds it attaches the identity to that user and answers with a 302 to `redirectTo` (or `linkRedirect`, default `/`) itself, with no session cookie, so a framework adapter's `onSuccess` never runs and the user's current session is left alone. The same identity on another user answers `IDENTITY_CONFLICT` with a merge ticket, as the email and SMS providers do.

Because it answers with a Response, a link skips `gate.onVerified`. `UserStore.onIdentityLinked` still runs, but before the provider state is written, so read the identifier there or read the identity again afterwards.

## Identities

`OidcProvider` keys identities on issuer plus subject (`{iss}|{sub}`) and stores both as provider state. The Slack adapter keys on `{teamId}:{userId}` instead, because Slack user IDs are unique only within a workspace, and stores both IDs:

```ts
import { slackIdentityState } from "@activescott/auth-provider-oidc"

const slack = identities.find((identity) => identity.provider === "slack")
const { teamId, userId } = slackIdentityState(slack) ?? {}
```

Email claims are never used to find or merge accounts. The access token is dropped once the ID token is validated.

## The initiate gate

`AuthConfig.gate` cannot run at start, since the identifier is unknown until the provider answers. Its `onInitiate` runs in the callback instead, after the ID token is validated and before any user or identity is created.

## What the callback checks

The ID token must be signed by a key in the provider's JWKS with an algorithm the discovery document lists (RS256 if it lists none), and have `iss` equal to the configured issuer, `aud` naming only this client, `azp` equal to this client when present, `exp` in the future, `iat` neither in the future nor more than `maxIdTokenAgeSeconds` old, and the `nonce` this client sent. The discovery document's `issuer` must match the configured issuer, and its endpoints must be https. Encrypted ID tokens are not supported.

Failures come back as `INVALID_TOKEN` (an unacceptable ID token or state) or `INVALID_CREDENTIALS` (a refused code, including a PKCE verifier mismatch, or an error from the provider), with `details.check` naming the check that failed.
