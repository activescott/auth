# @activescott/auth-oauth-server

An OAuth 2.1 authorization server for apps built on
[`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth), so an
MCP client (or any OAuth client) can act for a signed-in user against one
protected resource. It follows the MCP authorization spec (2026-07-28):

- protected resource metadata (RFC 9728) and authorization server metadata
  (RFC 8414)
- clients by Client ID Metadata Document, Dynamic Client Registration (RFC
  7591), or rows the app inserts itself
- authorization code with S256 PKCE only, `resource` bound to the token
  (RFC 8707), `iss` on every authorization response (RFC 9207)
- a consent page the app renders, answered by a CSRF-bound POST, never
  framed
- opaque 256-bit tokens stored as SHA-256, rotating refresh tokens with reuse
  detection, revocation (RFC 7009)

No OpenID Connect yet: no `id_token`, JWKS, or userinfo.

Everything speaks Fetch `Request`/`Response`. Storage is an interface the app
implements (`OAuthStore`), like `IdentityStore` in the core.

## Install

```bash
npm install @activescott/auth-oauth-server @activescott/auth
```

## Usage

```typescript
import { OAuthServer } from "@activescott/auth-oauth-server"
import { createClientMetadataFetcher } from "@activescott/auth-oauth-server/node"

export const oauth = new OAuthServer({
  issuer: "https://example.com",
  store: oauthStore, // your OAuthStore
  resource: {
    uri: "https://example.com/mcp",
    scopes: ["files:read", "files:write"],
    defaultScopes: ["files:read"],
    optionalScopes: ["files:write"], // unticked on the consent page
  },
  fetchClientMetadata: createClientMetadataFetcher(),
  reservedClientNames: ["Claude", "ChatGPT", "Gemini", "Example"],
  tokenPrefixes: { access: "exat_", refresh: "exrt_" },
  isUserActive: async (userId) => (await users.find(userId))?.approved ?? false,
  renderConsent: (prompt) => html(renderConsentPage(prompt)),
  renderError: (error) => html(renderErrorPage(error), 400),
})
```

Mount each handler on a route:

| Route                                           | Handler                                                   |
| ----------------------------------------------- | --------------------------------------------------------- |
| `oauth.protectedResourceMetadataUrl` (GET)      | `oauth.handleProtectedResourceMetadata()`                 |
| `/.well-known/oauth-authorization-server` (GET) | `oauth.handleAuthorizationServerMetadata()`               |
| `/oauth/register` (POST)                        | `oauth.handleRegistration(request, { clientIp })`         |
| `/oauth/authorize` (GET and POST)               | `oauth.handleAuthorization(request, { userId })`          |
| `/oauth/token` (POST)                           | `oauth.handleToken(request)`                              |
| `/oauth/revoke` (POST)                          | `oauth.handleRevocation(request)`                         |
| the protected resource                          | `oauth.verifyAccessToken(request, { scopes })`, see below |

The app owns sign-in: send a signed-out user from `/oauth/authorize` to sign
in and back to the same URL, then call `handleAuthorization` with their id.
`clientIp` is the address your own proxy observed, never a client-supplied
`X-Forwarded-For`.

### The consent page

`renderConsent` gets a `ConsentPrompt` and returns a `Response`. The form must
POST to `prompt.action` with `prompt.fields` as hidden inputs, a `decision` of
`approve` or `deny`, and a `scope` checkbox for each optional scope. Nothing
else from the form is trusted: the server re-reads the stored request. Show
the client the way the prompt describes it:

- a CIMD client: its name and `client.clientIdHost`
- a dynamic client (`warnings.unregisteredClient`): `client.redirectHost`
  first, the self-asserted name second
- `warnings.loopbackRedirects` and `warnings.redirectHostDiffers` as warnings

Those hosts are never the app's own. A CIMD `client_id` or a redirect URI on
the issuer host, a host in `ownHosts`, or a subdomain of either is refused, so
a client cannot borrow the app's host by putting a file or a callback on it.
Loopback redirects are exempt.

The server adds `Content-Security-Policy: frame-ancestors 'none'`,
`X-Frame-Options: DENY`, `Cache-Control: no-store` and
`Referrer-Policy: no-referrer` to whatever `renderConsent` and `renderError`
return. Unknown clients and unregistered redirect URIs get `renderError` and
never a redirect.

### The protected resource

```typescript
const auth = await oauth.verifyAccessToken(request, { scopes: ["files:write"] })
if (!auth.ok) return auth.response // 401 or 403 with WWW-Authenticate
// auth.userId, auth.clientId, auth.grantId, auth.scopes
```

A request without a valid token gets a 401 whose challenge names the
resource metadata URL and the default scopes; a token without the scope gets
403 `insufficient_scope`, which clients use to step up.

### Connected apps

`listConnectedApps(userId)` lists the user's grants with each client's name
and host. `revokeGrant(userId, grantId)` disconnects one, revoking every
token under it. Run `pruneDynamicClients()` on a schedule to delete dynamic
registrations that never got a grant within 24 hours.

## Storage

`OAuthStore` covers five records: `OAuthClient`, `OAuthAuthorizationRequest`
(pending consent, single use, 10 minutes), `OAuthCode`, `OAuthGrant` (one per
user and client), and `OAuthToken` (an access token and its refresh token).
Every secret is stored as a SHA-256 hex hash.

Three methods must be one conditional update each, since they are what stops
concurrent requests from redeeming the same code or refresh token twice:
`markCodeUsed`, `markTokenRotated`, and `revokeUnrotatedToken` (in SQL,
`UPDATE ... WHERE used_at IS NULL` and check the row count).
`consumeAuthorizationRequest` must return a request at most once.
`InMemoryOAuthStore` implements all of it for tests.

## Defaults

| Setting                              | Default                                        |
| ------------------------------------ | ---------------------------------------------- |
| Access token lifetime                | 1 hour                                         |
| Refresh token lifetime               | 30 days from consent, not extended             |
| Authorization code, pending consent  | 10 minutes                                     |
| Refresh reuse grace after a rotation | 60 seconds                                     |
| CIMD cache                           | response headers, clamped to 5 min - 24 h      |
| Dynamic registrations per IP         | 5 per minute, 20 per hour                      |
| CIMD fetches per user / across all   | 10 per minute and 50 per hour / 100 per minute |
| Authorization requests per user      | 20 per minute, 200 per hour                    |

Rate limits use the core's `RateLimitStore`; pass `rateLimitStore` to share
counters across instances. The token endpoint is not rate-limited here.

## License

MIT
