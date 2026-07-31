import {
  Auth,
  InMemoryChallengeStore,
  type AuthUser,
  type Identity,
  type IdentityStore,
  type UserStore,
} from "@activescott/auth"
import {
  EmailProvider,
  NodemailerTransport,
} from "@activescott/auth-provider-email"
import { CaptureTransport } from "./capture-transport.server"
import { createAuthHandlers } from "@activescott/auth-adapter-react-router"

/**
 * In-memory stores — fine for an example, but data evaporates on restart.
 * In a real app, back `UserStore` and `IdentityStore` with persistent storage
 * (Prisma, Drizzle, Kysely, raw SQL, Redis, DynamoDB, etc.). The auth library
 * only cares that the two interfaces are implemented.
 */
const users = new Map<string, AuthUser>()
const identities = new Map<string, Identity>()

// Real app: `prisma.user.findUnique({ where: { id } })`, etc.
const userStore: UserStore = {
  async findById(id) {
    return users.get(id) ?? null
  },
  async create({ identifier }) {
    const user: AuthUser = {
      id: crypto.randomUUID(),
      metadata: { email: identifier },
    }
    users.set(user.id, user)
    return user
  },
}

// Real app: `prisma.identity.findFirst({ where: { provider, identifier } })`, etc.
const identityStore: IdentityStore = {
  async findByProviderAndIdentifier(provider, identifier) {
    for (const identity of identities.values()) {
      if (
        identity.provider === provider &&
        identity.identifier === identifier
      ) {
        return identity
      }
    }
    return null
  },
  async findByUserId(userId) {
    return [...identities.values()].filter((index) => index.userId === userId)
  },
  async create(data) {
    const identity: Identity = {
      id: crypto.randomUUID(),
      userId: data.userId,
      provider: data.provider,
      identifier: data.identifier,
      metadata: data.metadata,
      createdAt: new Date(),
    }
    identities.set(identity.id, identity)
    return identity
  },
  async update(id, data) {
    const existing = identities.get(id)
    if (!existing) throw new Error(`Identity ${id} not found`)
    const updated = { ...existing, ...data }
    identities.set(id, updated)
    return updated
  },
}

/**
 * Hardcoded dev default so the example runs with zero setup. In a real app
 * load this from env (`process.env.JWT_SECRET`) and never commit
 * production secrets. The name below makes it obvious if it ever leaks.
 */
const SESSION_SECRET =
  process.env.JWT_SECRET ?? "dev-only-session-secret-do-not-use-in-production"

/**
 * SMTP is considered configured when SMTP_HOST is set (see .env.example).
 * Configured → real emails are sent. Not configured → dev mode: emails are
 * logged to the server console instead.
 */
const smtpConfigured = Boolean(process.env.SMTP_HOST)

export const auth = new Auth({
  session: {
    secret: SESSION_SECRET,
    maxAge: "30d",
    cookieName: "example_session",
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    },
  },
  identityStore,
  userStore,
  // Holds sign-in challenges (the magic link key and one-time code, both
  // hashed) between "send" and "verify". In-memory works for one server
  // process; use a DB/Redis-backed implementation for multiple instances.
  challengeStore: new InMemoryChallengeStore(),
  providers: [
    new EmailProvider(
      {
        // SMTP fields are unused in dev mode (the transport buffers instead
        // of sending) but the config still requires them.
        smtp: {
          host: process.env.SMTP_HOST ?? "localhost",
          port: Number(process.env.SMTP_PORT ?? 587),
          user: process.env.SMTP_USER ?? "",
          pass: process.env.SMTP_PASS ?? "",
        },
        from: process.env.EMAIL_FROM ?? "login@example.com",
        template: { appName: "RR Auth Example" },
      },
      // Dev mode (no SMTP configured) → emails are logged to the server
      // console instead of sent. Set SMTP_HOST (see .env.example) to send
      // real email.
      new CaptureTransport(new NodemailerTransport(!smtpConfigured)),
    ),
  ],
})

const handlers = createAuthHandlers(auth, {
  successRedirect: "/dashboard",
  errorRedirect: "/login",
  loginUrl: "/login",
})

export const { handleAuth, getSession, requireAuth, optionalAuth, logout } =
  handlers
