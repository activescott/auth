# 83: OAuth authorization server

Issue: [#83](https://github.com/activescott/auth/issues/83). Design:
activescott/fernfiles `docs/specs/046-mcp-server/plan.md` (the Auth section,
"Tokens and storage", decision 1, phases 0 and 1). This package is what that
plan's phase 1 needs; OIDC (`id_token`, JWKS, userinfo) is its phase 4 and is
not here.

## Shape

A new package, `@activescott/auth-oauth-server`, rather than part of the core:
the CIMD fetch needs Node's `https`, `dns` and an IP-range library, and the
core stays dependency-free and runtime-neutral. The endpoints themselves use
only Fetch and WebCrypto; the Node fetcher is at the `./node` subpath.

One `OAuthServer` per protected resource. The app owns sign-in, the consent
page's markup, and storage (`OAuthStore`); the server owns validation, the
consent request's lifecycle, codes, tokens, and the headers on the consent
response.

## Where it differs from Tinkerbell's server

Tinkerbell's OAuth server (activescott/tinkerbell `packages/web-app/app/routes/oauth.*`)
was the starting point. What changed:

| Tinkerbell                                                                             | Here                                                                                                                                             |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Code's client never checked; used-check and mark-used are separate steps               | Code bound to its client; one conditional update marks it used, and a second redemption revokes every token from the code                        |
| Denied consent redirects to the form's `redirect_uri`                                  | Every redirect goes to the stored, re-matched redirect URI; unknown clients and redirects get an error page                                      |
| Consent POST trusts hidden fields                                                      | POST carries a request id and CSRF token bound to a stored, single-use, per-user request; only `decision` and optional scopes come from the form |
| PKCE optional, `plain` accepted                                                        | S256 required                                                                                                                                    |
| `resource` ignored, no audience                                                        | `resource` required at authorize, checked at token and refresh, and on every bearer check                                                        |
| Refresh tokens never expire, not bound to the client, rotation without reuse detection | 30 days absolute, bound to the client, reuse revokes the grant, with a 60-second lost-response exception                                         |
| Secret required even from `none` clients                                               | Public clients authenticate with `client_id` alone                                                                                               |
| No revocation endpoint                                                                 | RFC 7009                                                                                                                                         |
| Exact-match redirects only, `[::1]` not loopback                                       | Loopback redirects match on scheme, host, path and query, any port; `127.0.0.1`, `[::1]`, `localhost`                                            |
| DCR only                                                                               | CIMD with an SSRF-guarded fetch, and DCR with `application_type` rules, reserved names, and a per-IP limit                                       |
| One all-or-nothing scope                                                               | Requested scopes, with optional ones unticked on consent                                                                                         |
| No user status check                                                                   | `isUserActive` on authorize, consent, redemption, refresh, and every bearer check                                                                |
| Hex tokens, no prefix                                                                  | 256-bit base64url tokens behind a configurable prefix for secret scanners                                                                        |
| `openid-configuration` serving OAuth metadata                                          | No OIDC discovery until OIDC exists                                                                                                              |

Kept from Tinkerbell: opaque tokens stored as SHA-256, the `dyn_` style
generated client id, consent behind the app's own sign-in, and the
spec-compliance style of tests.

## Choices the plan left open

- Grants are created when a code is redeemed, not at consent, so a consent
  that never finishes leaves no Connected apps entry.
- The new token pair is stored before the code or refresh token is marked
  used. A concurrent request that loses the conditional update therefore
  always finds, and revokes, what the winner issued.
- Revoking a refresh token revokes every token descended from the same code.
  Revoking an access token revokes it and its paired refresh token. Neither
  counts as reuse later.
- The 401 challenge's `scope` is the resource's `defaultScopes`; the 403's is
  the token's scopes plus the ones required, so a client that replaces its
  scopes on step-up keeps what it had.
- The fetcher pins the connection with a guarded `lookup` on `node:https`
  rather than a custom undici `connect`. Same effect (the socket connects to
  the checked address, TLS still verifies the host name) without a
  dependency.
- A redirect URI or CIMD `client_id` on the issuer host, an `ownHosts`
  entry, or a subdomain of either is refused, for DCR and CIMD alike. The
  consent page leads with those hosts, and an attacker's page on the app's
  own host would read as the app asking. Loopback redirects are exempt.
- Reserved client names match as whole words, case-insensitively, after
  stripping control and format characters. `Claude Code` is refused when
  `Claude` is reserved.
