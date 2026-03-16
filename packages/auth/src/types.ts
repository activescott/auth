/**
 * Core types for @activescott/auth
 */

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
 * One user can have multiple identities (email, phone, OAuth).
 */
export interface Identity {
  /** Unique identifier for this identity */
  id: string
  /** Foreign key to the user */
  userId: string
  /** Provider that authenticated this identity (e.g., "email", "sms", "google") */
  provider: string
  /** The identifier within that provider (email address, phone number, OAuth subject) */
  identifier: string
  /** Additional metadata from the provider */
  metadata?: Record<string, unknown>
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
  | { success: true; message: string }
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
    metadata?: Record<string, unknown>
  }): Promise<Identity>

  /**
   * Update an identity (e.g., update verifiedAt)
   */
  update?(
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
 * Each auth method (email, OAuth, SMS) implements this.
 */
export interface AuthProvider {
  /** Unique identifier for this provider (e.g., "email", "google", "sms") */
  readonly id: string

  /** Human-readable name */
  readonly name: string

  /**
   * Initialize authentication flow.
   * For email: sends magic link
   * For OAuth: returns redirect URL
   * For SMS: sends verification code
   */
  initiate(
    request: Request,
    context: AuthContext,
  ): Promise<AuthInitResult | Response>

  /**
   * Handle callback/verification.
   * For email: verifies magic link token
   * For OAuth: exchanges code for tokens
   * For SMS: verifies OTP code
   */
  verify(request: Request, context: AuthContext): Promise<AuthResult>

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
