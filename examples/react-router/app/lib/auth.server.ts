import {
  Auth,
  type AuthUser,
  type Identity,
  type IdentityStore,
  type UserStore,
} from "@activescott/auth"
import {
  EmailProvider,
  NodemailerTransport,
} from "@activescott/auth-provider-email"
import {
  createAuthHandlers,
  sendMagicLink as sendMagicLinkBase,
} from "@activescott/auth-adapter-react-router"

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
 * Hardcoded dev defaults so the example runs with zero setup. In a real app
 * load these from env (`process.env.JWT_SECRET`, etc.) and never commit
 * production secrets. The names below make it obvious if they ever leak.
 */
const SESSION_SECRET =
  process.env.JWT_SECRET ?? "dev-only-session-secret-do-not-use-in-production"
const MAGIC_LINK_SECRET =
  process.env.JWT_MAGIC_LINK_SECRET ??
  "dev-only-magic-link-secret-do-not-use-in-production"

/**
 * `additionalSecrets` lets your e2e tests sign their own magic-link tokens
 * without an SMTP server. The verifier accepts tokens signed by either the
 * primary secret or any additional secret. See `tests/helpers/auth.ts`.
 */
const E2E_MAGIC_LINK_SECRET =
  process.env.E2E_MAGIC_LINK_SECRET ?? "e2e_test_magic_link_secret"

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
  providers: [
    new EmailProvider(
      {
        magicLinkSecret: MAGIC_LINK_SECRET,
        additionalSecrets: [E2E_MAGIC_LINK_SECRET],
        magicLinkExpiry: "5m",
        // SMTP fields are unused in dev mode (the transport buffers instead
        // of sending) but the config still requires them.
        smtp: { host: "localhost", port: 25, user: "", pass: "" },
        from: "login@example.com",
        template: { appName: "RR Auth Example" },
      },
      // Force dev mode → magic links are logged to the server console
      // instead of sent via SMTP. Drop the `true` (or omit the transport
      // entirely) and configure real `smtp` to send actual email.
      new NodemailerTransport(true),
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

export function sendMagicLink(email: string, baseUrl: string) {
  return sendMagicLinkBase(auth, email, baseUrl)
}
