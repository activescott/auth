# @activescott/auth-provider-oauth

OAuth 2.0 / OIDC social login providers for [`@activescott/auth`](../auth).

## Providers

| Provider | Protocol | PKCE |
| --- | --- | --- |
| `GoogleProvider` | OIDC | yes |
| `GitHubProvider` | OAuth 2.0 | no (coming soon) |

## Installation

```bash
npm install @activescott/auth-provider-oauth
```

## GoogleProvider

### Google Cloud Console setup

1. Open [APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials).
2. Create an **OAuth 2.0 Client ID** (Web application).
3. Add `<your-base-url>/auth/google/callback` to **Authorized redirect URIs**.
4. Copy the **Client ID** and **Client Secret**.

### Usage

```typescript
import { Auth } from '@activescott/auth';
import { GoogleProvider } from '@activescott/auth-provider-oauth';

const auth = new Auth({
  session: { /* ... */ },
  identityStore,
  userStore,
  providers: [
    new GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      oauthStateSecret: process.env.OAUTH_STATE_SECRET!, // random 32+ char secret
    }),
  ],
});
```

### Routes registered

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/auth/google/initiate` | Redirect to Google sign-in |
| `GET` | `/auth/google/callback` | Exchange code, create session |

### Optional config

```typescript
new GoogleProvider({
  // ...required fields above...
  scopes: ['openid', 'email', 'profile'],  // default
  linkByVerifiedEmail: true,               // link to existing email identity if emails match
})
```

`linkByVerifiedEmail: true` links the Google identity to an existing account that shares the
same verified email address (e.g., a user who previously signed in with a magic link).
Only verified emails (`email_verified: true` in the id\_token) are used for linking.

## Building

```bash
npm run build --workspace=packages/auth-provider-oauth
npm run test --workspace=packages/auth-provider-oauth
```
