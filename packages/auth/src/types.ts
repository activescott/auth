/**
 * Core types for @activescott/auth
 */
import type { AbuseConfig, AbuseContext } from "./abuse/abuse-guard.js"

/**
 * Minimal user representation for authentication.
 * Applications extend this with their own user model.
 */
export interface AuthUser {
  /** Unique identifier for the user */
  id: string
  /** Additional metadata from the identity/provider */
  metadata?: Record<string, unknown>
}

/**
 * Identity record linking a provider+identifier to a user.
 * One user can have multiple identities (email, phone, passkey).
 */
export interface Identity {
  /** Unique identifier for this identity */
  id: string
  /** Foreign key to the user */
  userId: string
  /** Provider that authenticated this identity (e.g., "email", "sms", "passkey") */
  provider: string
  /** The identifier within that provider (email address, phone number, passkey credential ID) */
  identifier: string
  /**
   * Provider-owned state for this identity — e.g., the passkey provider
   * stores the credential public key and signature counter here;
   * providers with no per-identity state store an empty object.
   * Opaque to the application: stores must persist and return it
   * unmodified (a JSON/JSONB column works). May contain sensitive
   * material; protect it accordingly (encryption at rest is a
   * reasonable default).
   */
  metadata: Record<string, unknown>
  /** When this identity was created */
  createdAt: Date
  /** When this identity was last verified */
  verifiedAt?: Date
}

/**
 * Session data stored in JWT/cookie
 */
export interface Session {
  /** User ID from the database */
  userId: string
  /** Primary identifier used for this session */
  identifier: string
  /** Provider used for this session */
  provider: string
  /** Session creation timestamp (Unix seconds) */
  issuedAt: number
  /** Session expiration timestamp (Unix seconds) */
  expiresAt: number
}

/**
 * Result of a successful authentication
 */
export interface AuthSuccess {
  success: true
  user: AuthUser
  identity: Identity
  /**
   * Set-Cookie header values the caller must include in the HTTP response
   * (e.g., clearing a challenge cookie after OTP verification).
   */
  setCookies?: string[]
}

/**
 * Result of a failed authentication
 */
export interface AuthFailure {
  success: false
  error: AuthError
}

/**
 * Result of an authentication attempt
 */
export type AuthResult = AuthSuccess | AuthFailure

/**
 * Result of initiating authentication (e.g., sending magic link)
 */
export type AuthInitResult =
  | { success: true; message: string; setCookies?: string[] }
  | { success: false; error: AuthError }

/**
 * Structured error for authentication failures
 */
export interface AuthError {
  code: AuthErrorCode
  message: string
  details?: Record<string, unknown>
}

export type AuthErrorCode =
  | "INVALID_CREDENTIALS"
  | "EXPIRED_TOKEN"
  | "INVALID_TOKEN"
  | "MISSING_TOKEN"
  | "USER_NOT_FOUND"
  | "IDENTITY_NOT_FOUND"
  | "PROVIDER_ERROR"
  | "CONFIGURATION_ERROR"
  | "RATE_LIMITED"
  | "SESSION_EXPIRED"
  | "SESSION_INVALID"

/**
 * Identity storage adapter interface.
 * Applications implement this to connect to their database.
 */
export interface IdentityStore {
  /**
   * Find an identity by provider and identifier
   */
  findByProviderAndIdentifier(
    provider: string,
    identifier: string,
  ): Promise<Identity | null>

  /**
   * Find all identities for a user
   */
  findByUserId(userId: string): Promise<Identity[]>

  /**
   * Create a new identity
   */
  create(data: {
    userId: string
    provider: string
    identifier: string
    metadata: Record<string, unknown>
  }): Promise<Identity>

  /**
   * Update an identity's provider-owned metadata and/or verifiedAt.
   * A provided metadata value replaces the stored one wholesale.
   * Required: providers depend on it — e.g., the passkey provider
   * writes the signature counter here on every sign-in.
   */
  update(
    id: string,
    data: Partial<Pick<Identity, "metadata" | "verifiedAt">>,
  ): Promise<Identity>

  /**
   * Delete an identity
   */
  delete?(id: string): Promise<void>
}

/**
 * User storage adapter interface.
 * Applications implement this to manage their user records.
 */
export interface UserStore {
  /**
   * Find a user by their internal ID
   */
  findById(id: string): Promise<AuthUser | null>

  /**
   * Create a new user from identity information
   */
  create(fromIdentity: {
    provider: string
    identifier: string
    metadata?: Record<string, unknown>
  }): Promise<AuthUser>

  /**
   * Optionally update user on login
   */
  onLogin?(user: AuthUser): Promise<void>
}

/**
 * A short-lived verification challenge (e.g., an OTP code sent by email or
 * SMS, or a WebAuthn challenge). Stores only a hash of any secret code.
 */
export interface Challenge {
  /** Unguessable identifier (e.g., crypto.randomUUID()); referenced by the client via cookie */
  id: string
  /** Challenge kind (e.g., "email-otp", "sms-otp", "webauthn") */
  type: string
  /** Identifier being verified (email address, E.164 phone number, user ID) */
  identifier: string
  /** SHA-256 hex hash of the code (see hashOtpCode); never the plaintext code */
  hashedCode?: string
  /** Provider-specific data (e.g., WebAuthn challenge bytes) */
  data?: Record<string, unknown>
  /** Number of verification attempts made so far */
  attempts: number
  /** Maximum verification attempts before the challenge is rejected */
  maxAttempts: number
  /** When this challenge was created */
  createdAt: Date
  /** When this challenge expires */
  expiresAt: Date
}

/**
 * Storage adapter for verification challenges.
 * Applications implement this to connect to their database, or use the
 * shipped InMemoryChallengeStore for single-instance deployments.
 */
export interface ChallengeStore {
  /**
   * Persist a new challenge with attempts=0 and createdAt=now
   */
  create(data: Omit<Challenge, "attempts" | "createdAt">): Promise<Challenge>

  /**
   * Find a challenge by ID. Returns expired challenges too; callers check
   * expiresAt so they can distinguish expired from unknown.
   */
  findById(id: string): Promise<Challenge | null>

  /**
   * Atomically increment the attempt counter and return the new count
   * (SQL: UPDATE ... RETURNING; Redis: INCR)
   */
  incrementAttempts(id: string): Promise<number>

  /**
   * Delete a challenge (after successful verification or invalidation)
   */
  delete(id: string): Promise<void>
}

/**
 * Session configuration
 */
export interface SessionConfig {
  /** JWT secret for signing sessions */
  secret: string
  /** Additional secrets for verification (e.g., for E2E testing) */
  additionalSecrets?: string[]
  /** Session duration (e.g., "30d", "7d") */
  maxAge: string
  /** Cookie name */
  cookieName: string
  /** Cookie options */
  cookie: {
    secure: boolean
    sameSite: "strict" | "lax" | "none"
    domain?: string
    path?: string
  }
  /** JWT issuer claim */
  issuer?: string
  /** JWT audience claim */
  audience?: string
}

/**
 * Core auth configuration
 */
export interface AuthConfig {
  /** Session configuration */
  session: SessionConfig
  /** Identity storage adapter */
  identityStore: IdentityStore
  /** User storage adapter */
  userStore: UserStore
  /** Registered authentication providers */
  providers: AuthProvider[]
  /** Challenge storage adapter for short-lived verification state (magic
   * links, OTP codes, WebAuthn challenges). Use InMemoryChallengeStore for
   * single-instance deployments; back it with shared storage when running
   * multiple instances. */
  challengeStore: ChallengeStore
  /** Abuse protection for the initiate endpoints. Protection is on by
   * default with sensible limits and an in-memory counter store, so this is
   * only needed to tune limits, supply shared storage, add a hosted bot check,
   * or turn it off. */
  abuse?: AbuseConfig
  /** Callback URLs configuration */
  callbacks?: {
    /** URL to redirect to after successful authentication */
    onSuccess?: string | ((user: AuthUser, identity: Identity) => string)
    /** URL to redirect to after failed authentication */
    onError?: string | ((error: AuthError) => string)
  }
}

/**
 * Context passed to providers during authentication
 */
export interface AuthContext {
  /** Identity store for database operations */
  identityStore: IdentityStore
  /** User store for database operations */
  userStore: UserStore
  /** Base URL for generating callback URLs */
  baseUrl: string
  /** Create a session for a user */
  createSession: (user: AuthUser, identity: Identity) => Promise<string>
  /** Challenge store for magic links, OTP codes, and similar short-lived
   * verification state */
  challengeStore: ChallengeStore
  /** Return the authenticated user and identity for the request's session
   * cookie, or null when there is no valid session. Lets providers require
   * an existing session (e.g., passkey registration). */
  getSession?: (
    request: Request,
  ) => Promise<{ user: AuthUser; identity: Identity } | null>
  /** Per-recipient abuse checks. Providers call `checkIdentifier` once they
   * have parsed and normalized the recipient (email address, phone number)
   * and before sending anything to it. */
  abuse?: AbuseContext
}

/**
 * Route definition for a provider
 */
export interface ProviderRoute {
  /** HTTP method */
  method: "GET" | "POST"
  /** Path pattern (relative to auth base path) */
  path: string
  /** Handler type */
  handler: "initiate" | "verify"
}

/**
 * Authentication provider interface.
 * Each auth method (email, SMS, passkey) implements this.
 */
export interface AuthProvider {
  /** Unique identifier for this provider (e.g., "email", "sms", "passkey") */
  readonly id: string

  /** Human-readable name */
  readonly name: string

  /**
   * Message returned when an initiate succeeds (e.g. "Magic link sent. Please
   * check your email."). Auth reuses it verbatim when it silently blocks an
   * abusive initiate, so a blocked caller cannot tell the two apart.
   */
  readonly initiateSentMessage?: string

  /**
   * Initialize authentication flow.
   * For email: sends magic link
   * For passkey: returns registration/authentication options
   * For SMS: sends verification code
   */
  initiate(
    request: Request,
    context: AuthContext,
  ): Promise<AuthInitResult | Response>

  /**
   * Handle callback/verification.
   * For email: verifies magic link or OTP code
   * For passkey: verifies the WebAuthn assertion
   * For SMS: verifies OTP code
   *
   * May return a Response instead of an AuthResult when the step is not a
   * final authentication outcome — e.g., the email provider answers a
   * magic-link GET with a confirm page (the state-changing redemption
   * happens on the subsequent POST so email security scanners that
   * prefetch URLs cannot consume the link).
   */
  verify(request: Request, context: AuthContext): Promise<AuthResult | Response>

  /**
   * Handle a provider-specific action beyond initiate/verify — e.g., the
   * passkey provider's register-options, register-verify,
   * authenticate-options, authenticate-verify. `Auth.handleRequest`
   * dispatches actions it does not recognize here before returning 404.
   */
  handleAction?(
    action: string,
    request: Request,
    context: AuthContext,
  ): Promise<Response>

  /**
   * Check if this provider can handle the given request.
   * Used for automatic provider routing.
   */
  canHandle(request: Request): boolean

  /**
   * Get the routes this provider needs registered.
   */
  getRoutes(): ProviderRoute[]
}
