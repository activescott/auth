import type {
  AuthContext,
  AuthError,
  AuthInitResult,
  AuthProvider,
  AuthResult,
  Challenge,
  ProviderDescription,
  ProviderRoute,
} from "@activescott/auth"
import {
  AuthErrors,
  authenticateWithIdentifier,
  buildChallengeClearingCookie,
  buildChallengeCookie,
  buildReturnUrl,
  completeLinkVerification,
  linkUserIdFromChallenge,
  parseDuration,
  parseRequestBody,
  readCookie,
  resolveRedirectTarget,
} from "@activescott/auth"
import type {
  IdTokenClaims,
  OidcIdentity,
  OidcProviderConfig,
} from "./types.js"
import { OidcClient } from "./oidc-client.js"
import { OidcError } from "./oidc-error.js"
import { codeChallengeFor, randomToken } from "./pkce.js"

const MS_PER_SECOND = 1000

const CHALLENGE_TYPE = "oidc"
const DEFAULT_EXPIRY = "10m"
const DEFAULT_LINK_REDIRECT = "/"

/** ID token checks whose failure means the token itself is not acceptable */
const ID_TOKEN_REASONS = new Set([
  "signature",
  "issuer",
  "audience",
  "azp",
  "expired",
  "iat",
  "nonce",
  "malformed",
  "claims",
])

/**
 * Default identity mapping: key on issuer plus subject, the pair OIDC
 * guarantees is unique and stable.
 */
export function identifyByIssuerAndSubject(
  claims: IdTokenClaims,
): OidcIdentity {
  return {
    identifier: `${claims.iss}|${claims.sub}`,
    providerState: { iss: claims.iss, sub: claims.sub },
  }
}

/**
 * Sign-in and identity linking through an OpenID Connect provider, using the
 * authorization code flow with PKCE. Adapters for a specific provider (see
 * `createSlackProvider`) are configurations of this class.
 *
 * Routes:
 * - `GET|POST /auth/{id}/start` sends the browser to the provider. Pass
 *   `mode=link` (query or form field) to attach the provider identity to the
 *   signed-in user, and `redirectTo` for where a finished link lands. State,
 *   nonce and the PKCE verifier are kept in the challenge store; an HttpOnly
 *   cookie binds them to this browser.
 * - `GET /auth/{id}/callback` is the redirect URI. It checks state against
 *   the cookie's challenge, redeems the code, and validates the ID token.
 *
 * A sign-in resolves a user from the identity like any other provider, and
 * the caller's `onSuccess` responder creates the session. A link finishes
 * with a redirect of its own and no session cookie: the user already has a
 * session, and a framework adapter's `onSuccess` would replace it. Because
 * it answers with a Response, a link skips `gate.onVerified`; the app can
 * inspect the identity in `UserStore.onIdentityLinked` or on the page it
 * lands on.
 *
 * The application's gate (`AuthConfig.gate`) cannot run at start, since the
 * identifier is unknown until the provider answers. Its `onInitiate` is
 * consulted in the callback instead, once the ID token is validated and
 * before any user or identity is created.
 */
export class OidcProvider implements AuthProvider {
  public readonly id: string
  public readonly name: string
  public readonly client: OidcClient
  private readonly identify: (claims: IdTokenClaims) => OidcIdentity

  public constructor(private readonly config: OidcProviderConfig) {
    this.id = config.id
    this.name = config.name
    this.client = new OidcClient(config)
    this.identify = config.identify ?? identifyByIssuerAndSubject
  }

  /**
   * Not routed: OIDC sign-in starts at `/auth/{id}/start`, which sends
   * nothing to a user-controlled address and so needs no initiate route.
   */
  public async initiate(): Promise<AuthInitResult> {
    return {
      success: false,
      error: AuthErrors.configurationError(
        `Start ${this.name} sign-in at /auth/${this.id}/start`,
      ),
    }
  }

  /**
   * Serves the `start` action: record state, nonce and PKCE verifier as a
   * challenge and redirect to the provider's authorization endpoint.
   */
  public async handleAction(
    action: string,
    request: Request,
    context: AuthContext,
  ): Promise<Response> {
    if (action !== "start") {
      return new Response("Not Found", { status: 404 })
    }

    try {
      const url = new URL(request.url)
      const body =
        request.method === "POST" ? await parseRequestBody(request) : {}
      const param = (name: string): string | undefined => {
        const value = body[name] ?? url.searchParams.get(name)
        return typeof value === "string" && value ? value : undefined
      }

      let linkUserId: string | undefined
      if (param("mode") === "link") {
        const session = await context.getSession?.(request)
        if (!session) {
          return this.startFailure(
            request,
            context,
            AuthErrors.sessionInvalid({
              reason: `Sign in before linking ${this.name}`,
            }),
          )
        }
        linkUserId = session.user.id
      }

      const redirectTo = resolveRedirectTarget(
        param("redirectTo"),
        request.url,
        "",
        { logger: context.logger, source: "redirectTo" },
      )

      const challengeId = crypto.randomUUID()
      const state = randomToken()
      const nonce = randomToken()
      const codeVerifier = randomToken()
      const expirySeconds = parseDuration(this.config.expiry ?? DEFAULT_EXPIRY)

      const location = await this.client.authorizationUrl({
        redirectUri: this.redirectUri(context),
        state,
        nonce,
        codeChallenge: await codeChallengeFor(codeVerifier),
      })

      await context.challengeStore.create({
        id: challengeId,
        type: CHALLENGE_TYPE,
        identifier: this.id,
        data: {
          state,
          nonce,
          codeVerifier,
          ...(linkUserId ? { linkUserId } : {}),
          ...(redirectTo ? { redirectTo } : {}),
        },
        maxAttempts: 1,
        expiresAt: new Date(Date.now() + expirySeconds * MS_PER_SECOND),
      })

      const headers = new Headers({ Location: location })
      headers.append(
        "Set-Cookie",
        buildChallengeCookie(
          this.cookieName(),
          challengeId,
          expirySeconds,
          context.baseUrl,
        ),
      )
      return new Response(null, { status: 302, headers })
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error(`Error in ${this.id} provider start:`, error)
      return this.startFailure(
        request,
        context,
        AuthErrors.providerError(
          error instanceof Error ? error.message : "Unknown error",
        ),
      )
    }
  }

  /**
   * The callback. Consumes the challenge whatever the outcome, so a callback
   * URL can be used once.
   */
  public async verify(
    request: Request,
    context: AuthContext,
  ): Promise<AuthResult | Response> {
    const clearingCookie = buildChallengeClearingCookie(
      this.cookieName(),
      context.baseUrl,
    )
    const fail = (error: AuthError, setCookies: string[] = []): AuthResult => ({
      success: false,
      error,
      setCookies: [...setCookies, clearingCookie],
    })

    try {
      const challenge = await this.consumeChallenge(request, context)
      if ("error" in challenge) return fail(challenge.error)

      const params = new URL(request.url).searchParams
      const state = params.get("state")
      if (!state || state !== challenge.data?.state) {
        return fail(AuthErrors.invalidToken({ reason: "State mismatch" }))
      }

      const providerError = params.get("error")
      if (providerError) {
        return fail(
          AuthErrors.invalidCredentials({
            reason: `${this.name} returned ${providerError}`,
          }),
        )
      }

      const code = params.get("code")
      const nonce = challenge.data?.nonce
      const codeVerifier = challenge.data?.codeVerifier
      if (
        !code ||
        typeof nonce !== "string" ||
        typeof codeVerifier !== "string"
      ) {
        return fail(
          AuthErrors.invalidCredentials({
            reason: "Missing authorization code",
          }),
        )
      }

      let identity: OidcIdentity
      try {
        const claims = await this.client.redeemCode({
          code,
          redirectUri: this.redirectUri(context),
          codeVerifier,
          nonce,
        })
        identity = this.identify(claims)
      } catch (error) {
        if (!(error instanceof OidcError) || error.reason === "discovery") {
          throw error
        }
        const details = { reason: error.message, check: error.reason }
        return fail(
          ID_TOKEN_REASONS.has(error.reason)
            ? AuthErrors.invalidToken(details)
            : AuthErrors.invalidCredentials(details),
        )
      }

      const linkUserId = linkUserIdFromChallenge(challenge)
      const gated = await context.gate?.check({
        provider: this.id,
        identifier: identity.identifier,
        mode: linkUserId ? "link" : "signin",
      })
      if (gated instanceof Response) {
        gated.headers.append("Set-Cookie", clearingCookie)
        return gated
      }
      if (gated && !gated.success) return fail(gated.error)

      const result = linkUserId
        ? await completeLinkVerification(
            this.id,
            identity.identifier,
            linkUserId,
            request,
            context,
          )
        : await authenticateWithIdentifier(
            this.id,
            identity.identifier,
            context,
          )
      if (!result.success) return fail(result.error, result.setCookies)

      const stored = await context.identityStore.update(result.identity.id, {
        providerState: identity.providerState,
      })

      if (!linkUserId) {
        return {
          ...result,
          identity: stored,
          setCookies: [...(result.setCookies ?? []), clearingCookie],
        }
      }

      const redirectTo = challenge.data?.redirectTo
      const headers = new Headers({
        Location:
          typeof redirectTo === "string" && redirectTo
            ? redirectTo
            : (this.config.linkRedirect ?? DEFAULT_LINK_REDIRECT),
      })
      headers.append("Set-Cookie", clearingCookie)
      return new Response(null, { status: 302, headers })
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error(`Error in ${this.id} provider callback:`, error)
      return fail(
        AuthErrors.providerError(
          error instanceof Error ? error.message : "Unknown error",
        ),
      )
    }
  }

  public getRoutes(): ProviderRoute[] {
    return [
      { method: "GET", path: `/${this.id}/start`, handler: "action" },
      { method: "POST", path: `/${this.id}/start`, handler: "action" },
      { method: "GET", path: `/${this.id}/callback`, handler: "verify" },
    ]
  }

  /**
   * Non-secret settings for the admin dashboard. The client secret is never
   * included; the client ID is public (it appears in every authorization URL).
   */
  public describe(): ProviderDescription {
    return {
      settings: {
        issuer: this.config.issuer,
        clientId: this.config.clientId,
        scopes: this.client.scopes.join(" "),
        discoveryUrl: this.config.discoveryUrl ?? null,
        redirectUri: this.config.redirectUri ?? null,
        expiry: this.config.expiry ?? DEFAULT_EXPIRY,
        cookieName: this.cookieName(),
        linkRedirect: this.config.linkRedirect ?? DEFAULT_LINK_REDIRECT,
      },
    }
  }

  /**
   * Find the challenge named by this browser's cookie and use it up: one
   * attempt, then deleted, so a replayed callback finds nothing.
   */
  private async consumeChallenge(
    request: Request,
    context: AuthContext,
  ): Promise<Challenge | { error: AuthError }> {
    const challengeId = readCookie(request, this.cookieName())
    if (!challengeId) {
      return {
        error: AuthErrors.invalidCredentials({
          reason: `No ${this.name} sign-in in progress in this browser`,
        }),
      }
    }

    const challenge = await context.challengeStore.findById(challengeId)
    if (
      !challenge ||
      challenge.type !== CHALLENGE_TYPE ||
      challenge.identifier !== this.id
    ) {
      return {
        error: AuthErrors.invalidCredentials({
          reason: `${this.name} sign-in not found. Start again.`,
        }),
      }
    }

    const attempts = await context.challengeStore.incrementAttempts(
      challenge.id,
    )
    await context.challengeStore.delete(challenge.id)
    if (attempts > challenge.maxAttempts) {
      return {
        error: AuthErrors.invalidToken({
          reason: "This sign-in was already used",
        }),
      }
    }
    if (challenge.expiresAt.getTime() < Date.now()) {
      return {
        error: AuthErrors.expiredToken({ reason: "Sign-in took too long" }),
      }
    }
    return challenge
  }

  /** Send the browser back to the page that started the flow, with ?error=<code> */
  private startFailure(
    request: Request,
    context: AuthContext,
    error: AuthError,
  ): Response {
    return new Response(null, {
      status: 302,
      headers: {
        Location: buildReturnUrl(
          request,
          { error: error.code },
          context.logger,
        ),
      },
    })
  }

  private redirectUri(context: AuthContext): string {
    return (
      this.config.redirectUri ?? `${context.baseUrl}/auth/${this.id}/callback`
    )
  }

  private cookieName(): string {
    return this.config.cookieName ?? `auth_${this.id}_oidc`
  }
}
