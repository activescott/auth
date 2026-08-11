/**
 * Core types for @activescott/auth
 */
import type {
  AbuseConfig,
  AbuseContext,
  AbuseDescription,
} from "./abuse/abuse-guard.js"

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
   * reasonable default). Unlike `AuthUser.metadata` (an app-facing
   * grab-bag), this belongs to the provider — never render or edit it.
   */
  providerState: Record<string, unknown>
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
  /**
   * Set-Cookie header values the caller must include in the HTTP response
   * even though authentication failed — e.g., the merge ticket cookie that
   * accompanies an IDENTITY_CONFLICT during identity linking.
   */
  setCookies?: string[]
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
  | "IDENTITY_CONFLICT"

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
    providerState: Record<string, unknown>
  }): Promise<Identity>

  /**
   * Update an identity's provider-owned state and/or verifiedAt.
   * A provided providerState value replaces the stored one wholesale.
   * Required: providers depend on it — e.g., the passkey provider
   * writes the signature counter here on every sign-in.
   */
  update(
    id: string,
    data: Partial<Pick<Identity, "providerState" | "verifiedAt">>,
  ): Promise<Identity>

  /**
   * Delete an identity
   */
  delete(id: string): Promise<void>

  /**
   * Find all identities for several users in one round trip.
   * Optional: the admin dashboard uses it to render a page of users without
   * one query per user. When absent, callers fall back to looping
   * `findByUserId`.
   */
  findByUserIds?(userIds: string[]): Promise<Identity[]>

  /**
   * Reassign every identity of `fromUserId` to `toUserId` — bulk, and atomic
   * where the backing store allows (SQL: one UPDATE ... WHERE user_id = ...).
   * Account merging (`Auth.mergeUsers`) depends on it.
   *
   * This is the first write `Auth.mergeUsers` performs, so throwing here
   * vetoes the merge with nothing changed. Applications whose per-user data
   * must move all-or-nothing with the identities should implement the
   * ENTIRE merge here in one transaction — reassign identities, migrate app
   * data, delete the absorbed user row — and leave `UserStore.onMerge` as a
   * notification. See the account-merge docs in the README.
   */
  reassignByUserId(fromUserId: string, toUserId: string): Promise<void>
}

/**
 * Arguments for {@link UserStore.listUsers}.
 */
export interface ListUsersOptions {
  /** Maximum number of users to return */
  limit: number
  /** Number of users to skip */
  offset: number
  /**
   * Field to sort by. Opaque to this library — the store decides which
   * values it accepts and what an unrecognized value falls back to.
   */
  sortBy?: string
  /** Sort direction; stores should default to "desc" */
  sortOrder?: "asc" | "desc"
  /**
   * Narrowing criteria, opaque to this library in the same way `sortBy` is:
   * the store decides which keys it understands and ignores the rest.
   *
   * This is what makes a filtered view correct rather than cosmetic — the
   * store turns these into a `WHERE`, so `total` counts the filtered set and
   * pagination pages through it. Filtering an already-fetched page in the
   * browser could not do either.
   *
   * @example
   * ```ts
   * // ?filter.approvalStatus=PENDING reaches the store as:
   * { filter: { approvalStatus: "PENDING" } }
   * ```
   */
  filter?: Record<string, string>
}

/**
 * Result of {@link UserStore.listUsers}.
 */
export interface ListUsersResult {
  /** The requested page of users */
  users: AuthUser[]
  /** Total number of users matching the query, ignoring limit/offset */
  total: number
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

  /**
   * Return a page of users, newest or otherwise ordered per `sortBy`.
   * Optional: only the admin dashboard needs it, and enumerating users is a
   * capability many stores would rather not expose. The dashboard reports a
   * clear error when it is missing.
   *
   * Put anything the dashboard should show beyond identities — a display
   * name, a plan, a row count — in each user's `metadata`; the dashboard
   * renders configured metadata keys as columns.
   */
  listUsers?(options: ListUsersOptions): Promise<ListUsersResult>

  /**
   * Called by `Auth.mergeUsers` after every identity of `fromUser` has been
   * reassigned to `intoUser`. Migrate or delete application data keyed by
   * `fromUser.id` here (file roots, preferences, billing rows), and dispose
   * of the absorbed user record — the library never deletes user rows.
   * Deleting `fromUser` also ends its outstanding sessions: session
   * verification re-checks `findById` on each request.
   *
   * Required so every store decides explicitly what happens to the absorbed
   * user; an empty implementation is a valid decision, silent orphaning by
   * omission is not.
   *
   * NOT atomic with the reassignment: a throw here surfaces as a 500 with
   * the identities already moved, so keep this idempotent and safe to
   * re-run. Applications that need the whole merge to be all-or-nothing
   * should perform it inside `IdentityStore.reassignByUserId` (one
   * transaction, which also vetoes cleanly by throwing before any write)
   * and use this hook only for logging/notification.
   */
  onMerge(fromUser: AuthUser, intoUser: AuthUser): Promise<void>

  /**
   * Called when identity linking attaches a newly verified identifier to
   * this user (a `mode: "link"` verify) — not on ordinary sign-in or
   * sign-up, where `create`/`IdentityStore.create` already run. Use it to
   * denormalize identity data onto the user record, e.g. filling a nullable
   * email column when a phone-first user links an email address.
   */
  onIdentityLinked?(user: AuthUser, identity: Identity): Promise<void>
}

/**
 * Optional hooks for {@link Auth.handleRequest} that turn a verify outcome
 * into the caller's HTTP response — e.g., a framework adapter creates the
 * session cookie and redirects. They apply only to routes declared
 * `handler: "verify"` whose provider returned an AuthResult; providers that
 * answer with a Response directly (confirm pages, passkey JSON) bypass them,
 * as do initiate results. When a hook is absent the default JSON response is
 * used.
 */
export interface AuthResponders {
  /** Turn a successful verify into the response (session cookie, redirect) */
  onSuccess?: (result: AuthSuccess, request: Request) => Promise<Response>
  /** Turn a failed verify into the response. Include `failure.setCookies`
   * (e.g. the IDENTITY_CONFLICT merge ticket) in what you return. */
  onFailure?: (failure: AuthFailure, request: Request) => Promise<Response>
}

/**
 * Result of {@link Auth.mergeUsers}.
 */
export interface MergeResult {
  /** The absorbed user, whose identities were moved */
  fromUserId: string
  /** The surviving user */
  intoUserId: string
  /** The identities that were reassigned, as they were before the move */
  movedIdentities: Identity[]
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
 * Placeholder rendered wherever a secret would otherwise appear. The secret
 * itself never leaves `AuthConfig`.
 */
export const REDACTED = "<redacted>"

/**
 * Session settings safe to display. Mirrors {@link SessionConfig} minus the
 * signing material.
 */
export interface SessionConfigDescription {
  cookieName: string
  maxAge: string
  issuer?: string
  audience?: string
  cookie: SessionConfig["cookie"]
  /** Always {@link REDACTED}; present so the page can show the field is set */
  secret: string
  /** How many `additionalSecrets` are configured; their values never appear */
  additionalSecretCount: number
}

/**
 * One registered provider as shown on the config page: its identity, the
 * routes it claims, and whatever its own `describe()` chose to reveal.
 */
export interface ProviderConfigDescription {
  id: string
  name: string
  initiateSentMessage?: string
  routes: ProviderRoute[]
  settings: Record<string, string | number | boolean | null>
}

/**
 * Which store implementations are wired up and which optional methods they
 * provide. Constructor names are best-effort: stores are commonly plain object
 * literals, which report as "(object literal)".
 */
export interface StoresDescription {
  userStore: string
  identityStore: string
  challengeStore: string
  /** Optional store methods the admin dashboard depends on */
  capabilities: {
    /** Without this the dashboard cannot render a users page at all */
    listUsers: boolean
    /** Without this the dashboard falls back to one query per user */
    findByUserIds: boolean
  }
}

/**
 * A redacted, serializable snapshot of how `Auth` is configured, for the admin
 * dashboard's config page. Safe to send to any client that is already allowed
 * to see the dashboard: it contains no secrets, and each provider redacts its
 * own settings.
 */
export interface AuthConfigDescription {
  session: SessionConfigDescription
  providers: ProviderConfigDescription[]
  abuse: AbuseDescription
  stores: StoresDescription
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
 * Route definition for a provider. `Auth.handleRequest` dispatches strictly
 * from this table: a request whose method+path matches no declared route is
 * a 404 (405 when only the method differs).
 */
export interface ProviderRoute {
  /** HTTP method */
  method: "GET" | "POST"
  /** Path pattern (relative to auth base path) */
  path: string
  /**
   * Which provider entry point serves the route. "initiate" runs the abuse
   * guard first and calls `initiate`; "verify" calls `verify`; "action"
   * calls `handleAction` with the path's action segment (no abuse guard —
   * declare "initiate" for anything that sends a message to a
   * user-controlled address).
   */
  handler: "initiate" | "verify" | "action"
}

/**
 * A provider's own account of how it is configured, for display on the admin
 * dashboard. The provider decides what to include — it is the only code that
 * knows which of its settings are secret.
 */
export interface ProviderDescription {
  /**
   * Non-secret settings to display, in whatever order the object is built.
   * Never include API keys, passwords, tokens, or signing secrets: a value
   * here is rendered verbatim to anyone who can reach the dashboard.
   */
  settings: Record<string, string | number | boolean | null>
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
   * authenticate-options, authenticate-verify. `Auth.handleRequest` calls
   * this for routes declared with `handler: "action"`.
   */
  handleAction?(
    action: string,
    request: Request,
    context: AuthContext,
  ): Promise<Response>

  /**
   * The routes this provider serves. `Auth.handleRequest` dispatches from
   * this table alone, so a path/method not declared here is unreachable.
   */
  getRoutes(): ProviderRoute[]

  /**
   * Report this provider's non-secret configuration for the admin dashboard.
   * Return `{ settings: {} }` if there is nothing worth showing.
   *
   * Only the provider knows which of its settings are secret, so redaction is
   * its responsibility: omit API keys, passwords, tokens, and signing secrets
   * rather than masking them.
   */
  describe(): ProviderDescription
}
