import type {
  AuthContext,
  AuthError,
  AuthInitResult,
  AuthProvider,
  AuthResult,
  Identity,
  ProviderRoute,
} from "@activescott/auth"
import {
  AuthErrors,
  buildChallengeClearingCookie,
  buildChallengeCookie,
  parseDuration,
  parseRequestBody,
  readCookie,
} from "@activescott/auth"
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server"
import {
  isAuthenticationResponse,
  isRegistrationResponse,
} from "./webauthn-response.js"
import type { ChallengeTokenPayload } from "./challenge-token.js"
import { signChallengeToken, verifyChallengeToken } from "./challenge-token.js"
import { base64urlToUint8Array, uint8ArrayToBase64url } from "./base64url.js"
import type { PasskeyCredentialMetadata } from "./credential-metadata.js"
import { parsePasskeyCredentialMetadata } from "./credential-metadata.js"
import type { PasskeyProviderConfig, WebAuthnServer } from "./types.js"

const MS_PER_SECOND = 1000

const CHALLENGE_TYPE = "webauthn"
const DEFAULT_CHALLENGE_EXPIRY = "5m"
const DEFAULT_CHALLENGE_COOKIE_NAME = "auth_passkey_challenge"

const HTTP_OK = 200
const HTTP_UNAUTHORIZED = 401
const HTTP_NOT_FOUND = 404
const HTTP_METHOD_NOT_ALLOWED = 405
const HTTP_SERVER_ERROR = 500

/** ES256 and RS256; covers Apple, Google, Microsoft, and security keys */
const SUPPORTED_ALGORITHM_IDS = [-7, -257]

const defaultWebAuthn: WebAuthnServer = {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
}

/**
 * Passkey (WebAuthn) authentication provider. Serves four actions under
 * /auth/passkey/:
 *
 * - register-options / register-verify: add a passkey to the signed-in
 *   user (registration requires an existing session).
 * - authenticate-options / authenticate-verify: usernameless sign-in
 *   with a discoverable credential.
 *
 * All four are fetch/JSON endpoints (WebAuthn ceremonies run in page
 * JavaScript, not form navigations). Challenges are bound to the browser
 * with a short-lived signed-JWT HttpOnly cookie and recorded in the
 * core challengeStore, so each is strictly single-use.
 */
export class PasskeyProvider implements AuthProvider {
  public readonly id = "passkey"
  public readonly name = "Passkey"

  public constructor(
    private readonly config: PasskeyProviderConfig,
    private readonly webauthn: WebAuthnServer = defaultWebAuthn,
  ) {}

  /**
   * Alias for the authenticate-options action so the provider satisfies
   * the standard initiate/verify interface
   */
  public async initiate(
    request: Request,
    context: AuthContext,
  ): Promise<AuthInitResult | Response> {
    return this.handleAction("authenticate-options", request, context)
  }

  /**
   * Alias for the authenticate-verify action so the provider satisfies
   * the standard initiate/verify interface
   */
  public async verify(
    request: Request,
    context: AuthContext,
  ): Promise<AuthResult | Response> {
    return this.handleAction("authenticate-verify", request, context)
  }

  /**
   * Dispatch the passkey actions. Auth.handleRequest routes unmatched
   * /auth/passkey/<action> requests here.
   */
  public async handleAction(
    action: string,
    request: Request,
    context: AuthContext,
  ): Promise<Response> {
    try {
      if (request.method !== "POST") {
        return jsonResponse(HTTP_METHOD_NOT_ALLOWED, {
          success: false,
          error: AuthErrors.providerError("Passkey actions require POST"),
        })
      }

      switch (action) {
        case "register-options": {
          return await this.registerOptions(request, context)
        }
        case "register-verify": {
          return await this.registerVerify(request, context)
        }
        case "authenticate-options": {
          return await this.authenticateOptions(request, context)
        }
        case "authenticate-verify": {
          return await this.authenticateVerify(request, context)
        }
        default: {
          return new Response("Unknown action", { status: HTTP_NOT_FOUND })
        }
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error(`Error in passkey provider ${action}:`, error)
      return jsonResponse(HTTP_SERVER_ERROR, {
        success: false,
        error: AuthErrors.providerError(
          error instanceof Error ? error.message : "Unknown error",
        ),
      })
    }
  }

  public canHandle(request: Request): boolean {
    const url = new URL(request.url)
    return url.pathname.startsWith("/auth/passkey")
  }

  public getRoutes(): ProviderRoute[] {
    return [
      {
        method: "POST",
        path: "/passkey/authenticate-options",
        handler: "initiate",
      },
      {
        method: "POST",
        path: "/passkey/authenticate-verify",
        handler: "verify",
      },
    ]
  }

  /**
   * Issue registration options for adding a passkey to the signed-in
   * user. 401 without a session.
   */
  private async registerOptions(
    request: Request,
    context: AuthContext,
  ): Promise<Response> {
    const session = await this.requireSession(request, context)
    if (session instanceof Response) return session

    const existing = await this.findPasskeyIdentities(context, session.user.id)

    const options = await this.webauthn.generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.rpID(context),
      userID: new TextEncoder().encode(session.user.id),
      userName: session.identity.identifier,
      userDisplayName: session.identity.identifier,
      attestationType: "none",
      excludeCredentials: existing.map(({ identity, credential }) => ({
        id: identity.identifier,
        transports: credential.transports,
      })),
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
    })

    return this.optionsResponse(options, {
      challenge: options.challenge,
      purpose: "registration",
      userId: session.user.id,
      identifier: session.identity.identifier,
      context,
    })
  }

  /**
   * Verify the browser's registration response, persist the credential,
   * and link a passkey identity to the signed-in user
   */
  private async registerVerify(
    request: Request,
    context: AuthContext,
  ): Promise<Response> {
    const session = await this.requireSession(request, context)
    if (session instanceof Response) return session

    const token = await this.consumeChallengeToken(request, context)
    if (!token || token.purpose !== "registration") {
      return this.invalidChallengeResponse()
    }
    if (token.userId !== session.user.id) {
      return jsonResponse(HTTP_UNAUTHORIZED, {
        success: false,
        error: AuthErrors.invalidToken({
          reason: "Challenge was issued for a different user",
        }),
      })
    }

    const body = await parseRequestBody(request)
    if (!isRegistrationResponse(body)) {
      return jsonResponse(HTTP_UNAUTHORIZED, {
        success: false,
        error: AuthErrors.invalidCredentials({
          reason: "Malformed registration response",
        }),
      })
    }

    const verification = await this.webauthn.verifyRegistrationResponse({
      response: body,
      expectedChallenge: token.challenge,
      expectedOrigin: this.expectedOrigin(context),
      expectedRPID: this.rpID(context),
      requireUserVerification: false,
    })

    if (!verification.verified || !verification.registrationInfo) {
      return jsonResponse(HTTP_UNAUTHORIZED, {
        success: false,
        error: AuthErrors.invalidCredentials({
          reason: "Registration could not be verified",
        }),
      })
    }

    const { credential, credentialDeviceType, credentialBackedUp } =
      verification.registrationInfo

    // The identity row IS the credential record: identifier is the
    // WebAuthn credential ID, and the provider-owned metadata holds the
    // verification state (see passkeyCredentialMetadataSchema).
    const metadata: PasskeyCredentialMetadata = {
      publicKey: uint8ArrayToBase64url(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports,
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
      nickname: typeof body.nickname === "string" ? body.nickname : undefined,
    }
    await context.identityStore.create({
      userId: session.user.id,
      provider: this.id,
      identifier: credential.id,
      metadata,
    })

    return jsonResponse(
      HTTP_OK,
      { success: true, verified: true, credentialId: credential.id },
      [this.clearingCookie(context)],
    )
  }

  /**
   * Issue authentication options for usernameless sign-in. Empty
   * allowCredentials so the browser offers any discoverable credential
   * for this relying party.
   */
  private async authenticateOptions(
    request: Request,
    context: AuthContext,
  ): Promise<Response> {
    const options = await this.webauthn.generateAuthenticationOptions({
      rpID: this.rpID(context),
      allowCredentials: [],
      userVerification: "preferred",
    })

    return this.optionsResponse(options, {
      challenge: options.challenge,
      purpose: "authentication",
      identifier: "authentication",
      context,
    })
  }

  /**
   * Verify the browser's authentication assertion and create a session.
   * Returns JSON with the session Set-Cookie header (the caller is a
   * fetch, not a form navigation).
   */
  private async authenticateVerify(
    request: Request,
    context: AuthContext,
  ): Promise<Response> {
    const token = await this.consumeChallengeToken(request, context)
    if (!token || token.purpose !== "authentication") {
      return this.invalidChallengeResponse()
    }

    const body = await parseRequestBody(request)
    if (!isAuthenticationResponse(body)) {
      return jsonResponse(HTTP_UNAUTHORIZED, {
        success: false,
        error: AuthErrors.invalidCredentials({
          reason: "Malformed authentication response",
        }),
      })
    }

    const identity = await context.identityStore.findByProviderAndIdentifier(
      this.id,
      body.id,
    )
    if (!identity) {
      return jsonResponse(HTTP_UNAUTHORIZED, {
        success: false,
        error: AuthErrors.invalidCredentials({
          reason: "Unknown credential",
        }),
      })
    }

    const stored = parsePasskeyCredentialMetadata(identity.metadata)
    if (!stored) {
      return jsonResponse(HTTP_SERVER_ERROR, {
        success: false,
        error: AuthErrors.providerError(
          "Stored passkey credential is invalid — the identity store must persist Identity.metadata unmodified",
        ),
      })
    }

    const verification = await this.webauthn.verifyAuthenticationResponse({
      response: body,
      expectedChallenge: token.challenge,
      expectedOrigin: this.expectedOrigin(context),
      expectedRPID: this.rpID(context),
      credential: {
        id: identity.identifier,
        publicKey: base64urlToUint8Array(stored.publicKey),
        // The regression check is ours below (warn, not fail): synced
        // passkeys legitimately report 0 or regressed counters.
        counter: 0,
        transports: stored.transports,
      },
      requireUserVerification: false,
    })

    if (!verification.verified) {
      return jsonResponse(HTTP_UNAUTHORIZED, {
        success: false,
        error: AuthErrors.invalidCredentials({
          reason: "Authentication could not be verified",
        }),
      })
    }

    const newCounter = verification.authenticationInfo.newCounter
    if (stored.counter > 0 && newCounter <= stored.counter) {
      // eslint-disable-next-line no-console
      console.warn(
        `Passkey counter regression for credential ${identity.identifier}: stored ${stored.counter}, received ${newCounter}. Possible cloned authenticator; not blocking because synced passkeys regress legitimately.`,
      )
    }

    const user = await context.userStore.findById(identity.userId)
    if (!user) {
      return jsonResponse(HTTP_UNAUTHORIZED, {
        success: false,
        error: AuthErrors.userNotFound(),
      })
    }

    await context.identityStore.update(identity.id, {
      metadata: {
        ...stored,
        counter: newCounter,
        lastUsedAt: new Date().toISOString(),
      },
      verifiedAt: new Date(),
    })

    const sessionCookie = await context.createSession(user, identity)

    return jsonResponse(
      HTTP_OK,
      { success: true, verified: true, user: { id: user.id } },
      [sessionCookie, this.clearingCookie(context)],
    )
  }

  /**
   * A user's passkey identities with their validated credential state;
   * identities whose metadata fails validation are skipped
   */
  private async findPasskeyIdentities(
    context: AuthContext,
    userId: string,
  ): Promise<{ identity: Identity; credential: PasskeyCredentialMetadata }[]> {
    const identities = await context.identityStore.findByUserId(userId)
    const result: {
      identity: Identity
      credential: PasskeyCredentialMetadata
    }[] = []
    for (const identity of identities) {
      if (identity.provider !== this.id) continue
      const credential = parsePasskeyCredentialMetadata(identity.metadata)
      if (credential) result.push({ identity, credential })
    }
    return result
  }

  /**
   * Resolve the session or produce the 401/configuration error response
   */
  private async requireSession(
    request: Request,
    context: AuthContext,
  ): Promise<
    | { user: { id: string }; identity: { id: string; identifier: string } }
    | Response
  > {
    if (!context.getSession) {
      return jsonResponse(HTTP_SERVER_ERROR, {
        success: false,
        error: AuthErrors.configurationError(
          "Passkey registration requires AuthContext.getSession (upgrade @activescott/auth)",
        ),
      })
    }
    const session = await context.getSession(request)
    if (!session) {
      return jsonResponse(HTTP_UNAUTHORIZED, {
        success: false,
        error: AuthErrors.sessionInvalid({
          reason: "Sign in before registering a passkey",
        }),
      })
    }
    return session
  }

  /**
   * Build the options JSON response carrying the challenge cookie; also
   * records the challenge when a challengeStore is configured
   */
  private async optionsResponse(
    options: object,
    args: {
      challenge: string
      purpose: ChallengeTokenPayload["purpose"]
      userId?: string
      identifier: string
      context: AuthContext
    },
  ): Promise<Response> {
    const expirySeconds = parseDuration(
      this.config.challengeExpiry ?? DEFAULT_CHALLENGE_EXPIRY,
    )
    const jti = crypto.randomUUID()

    // Record the challenge so redemption is strictly single-use; the
    // core config always provides a challengeStore.
    await args.context.challengeStore.create({
      id: jti,
      type: CHALLENGE_TYPE,
      identifier: args.identifier,
      maxAttempts: 1,
      expiresAt: new Date(Date.now() + expirySeconds * MS_PER_SECOND),
    })

    const token = await signChallengeToken(
      this.config.challengeSecret,
      {
        challenge: args.challenge,
        purpose: args.purpose,
        userId: args.userId,
        jti,
      },
      expirySeconds,
    )

    return jsonResponse(HTTP_OK, options, [
      buildChallengeCookie(
        this.cookieName(),
        token,
        expirySeconds,
        args.context.baseUrl,
      ),
    ])
  }

  /**
   * Read and validate the challenge cookie, consuming the challenge
   * row — one redemption attempt per challenge, success or not.
   */
  private async consumeChallengeToken(
    request: Request,
    context: AuthContext,
  ): Promise<ChallengeTokenPayload | null> {
    const cookieValue = readCookie(request, this.cookieName())
    if (!cookieValue) return null

    const token = await verifyChallengeToken(
      this.config.challengeSecret,
      cookieValue,
    )
    if (!token) return null

    const row = await context.challengeStore.findById(token.jti)
    if (!row || row.expiresAt.getTime() < Date.now()) return null
    await context.challengeStore.delete(token.jti)

    return token
  }

  private invalidChallengeResponse(): Response {
    return jsonResponse(HTTP_UNAUTHORIZED, {
      success: false,
      error: AuthErrors.invalidToken({
        reason: "Missing, expired, or already-used challenge. Start over.",
      }),
    })
  }

  private rpID(context: AuthContext): string {
    return this.config.rpID ?? new URL(context.baseUrl).hostname
  }

  private expectedOrigin(context: AuthContext): string {
    return this.config.expectedOrigin ?? new URL(context.baseUrl).origin
  }

  private clearingCookie(context: AuthContext): string {
    return buildChallengeClearingCookie(this.cookieName(), context.baseUrl)
  }

  private cookieName(): string {
    return this.config.challengeCookieName ?? DEFAULT_CHALLENGE_COOKIE_NAME
  }
}

/**
 * Build a JSON Response with optional Set-Cookie headers
 */
function jsonResponse(
  status: number,
  body: object | { success: false; error: AuthError },
  setCookies: string[] = [],
): Response {
  const headers = new Headers({ "Content-Type": "application/json" })
  for (const cookie of setCookies) {
    headers.append("Set-Cookie", cookie)
  }
  return new Response(JSON.stringify(body), { status, headers })
}
