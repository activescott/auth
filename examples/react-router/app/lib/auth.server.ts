import {
  Auth,
  type AuthUser,
  type Identity,
  type IdentityStore,
  type UserStore
} from '@activescott/auth';
import { EmailProvider, NodemailerTransport } from '@activescott/auth-provider-email';
import { GoogleProvider, GitHubProvider } from '@activescott/auth-provider-oauth';
import {
  createAuthHandlers,
  sendMagicLink as sendMagicLinkBase
} from '@activescott/auth-adapter-react-router';

/**
 * In-memory stores — fine for an example, but data evaporates on restart.
 * In a real app, back `UserStore` and `IdentityStore` with persistent storage
 * (Prisma, Drizzle, Kysely, raw SQL, Redis, DynamoDB, etc.). The auth library
 * only cares that the two interfaces are implemented.
 */
const users = new Map<string, AuthUser>();
const identities = new Map<string, Identity>();

// Real app: `prisma.user.findUnique({ where: { id } })`, etc.
const userStore: UserStore = {
  async findById(id) {
    return users.get(id) ?? null;
  },
  async create({ identifier, metadata }) {
    const user: AuthUser = {
      id: crypto.randomUUID(),
      metadata: metadata ?? { email: identifier }
    };
    users.set(user.id, user);
    return user;
  }
};

// Real app: `prisma.identity.findFirst({ where: { provider, identifier } })`, etc.
const identityStore: IdentityStore = {
  async findByProviderAndIdentifier(provider, identifier) {
    for (const identity of identities.values()) {
      if (identity.provider === provider && identity.identifier === identifier) {
        return identity;
      }
    }
    return null;
  },
  async findByUserId(userId) {
    return [...identities.values()].filter((index) => index.userId === userId);
  },
  async create(data) {
    const identity: Identity = {
      id: crypto.randomUUID(),
      userId: data.userId,
      provider: data.provider,
      identifier: data.identifier,
      metadata: data.metadata,
      createdAt: new Date()
    };
    identities.set(identity.id, identity);
    return identity;
  },
  async update(id, data) {
    const existing = identities.get(id);
    if (!existing) throw new Error(`Identity ${id} not found`);
    const updated = { ...existing, ...data };
    identities.set(id, updated);
    return updated;
  }
};

/**
 * Hardcoded dev defaults so the example runs with zero setup. In a real app
 * load these from env (`process.env.JWT_SECRET`, etc.) and never commit
 * production secrets. The names below make it obvious if they ever leak.
 */
const SESSION_SECRET = process.env.JWT_SECRET ?? 'dev-only-session-secret-do-not-use-in-production';
const MAGIC_LINK_SECRET =
  process.env.JWT_MAGIC_LINK_SECRET ?? 'dev-only-magic-link-secret-do-not-use-in-production';

/**
 * `additionalSecrets` lets your e2e tests sign their own magic-link tokens
 * without an SMTP server. The verifier accepts tokens signed by either the
 * primary secret or any additional secret. See `tests/helpers/auth.ts`.
 */
const E2E_MAGIC_LINK_SECRET = process.env.E2E_MAGIC_LINK_SECRET ?? 'e2e_test_magic_link_secret';

// OAuth provider credentials — set these in .env to enable social login.
// Omitting them disables the providers at startup.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const OAUTH_STATE_SECRET =
  process.env.OAUTH_STATE_SECRET ?? 'dev-only-oauth-state-secret-at-least-32-chars!!';

const oauthProviders = [];
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  oauthProviders.push(
    new GoogleProvider({
      clientId: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      oauthStateSecret: OAUTH_STATE_SECRET
    })
  );
}
if (GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET) {
  oauthProviders.push(
    new GitHubProvider({
      clientId: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
      oauthStateSecret: OAUTH_STATE_SECRET
    })
  );
}

export const auth = new Auth({
  session: {
    secret: SESSION_SECRET,
    maxAge: '30d',
    cookieName: 'example_session',
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/'
    }
  },
  identityStore,
  userStore,
  providers: [
    new EmailProvider(
      {
        magicLinkSecret: MAGIC_LINK_SECRET,
        additionalSecrets: [E2E_MAGIC_LINK_SECRET],
        magicLinkExpiry: '5m',
        // SMTP fields are unused in dev mode (the transport buffers instead
        // of sending) but the config still requires them.
        smtp: { host: 'localhost', port: 25, user: '', pass: '' },
        from: 'login@example.com',
        template: { appName: 'RR Auth Example' }
      },
      // Force dev mode → magic links are logged to the server console
      // instead of sent via SMTP. Drop the `true` (or omit the transport
      // entirely) and configure real `smtp` to send actual email.
      new NodemailerTransport(true)
    ),
    ...oauthProviders
  ]
});

const handlers = createAuthHandlers(auth, {
  successRedirect: '/dashboard',
  errorRedirect: '/login',
  loginUrl: '/login'
});

export const { handleAuth, getSession, requireAuth, optionalAuth, logout } = handlers;

export function sendMagicLink(email: string, baseUrl: string) {
  return sendMagicLinkBase(auth, email, baseUrl);
}

/**
 * Test-only helper: create a real user + identity in the in-memory stores and
 * return the Set-Cookie header value for a session that represents them.
 *
 * Only available when NODE_ENV !== 'production'.  Used by the Playwright
 * e2e suite to simulate a completed OAuth login without going through a real
 * provider.  See `tests/helpers/auth.ts`.
 */
export async function createTestSession({
  provider,
  identifier,
  email
}: {
  provider: string;
  identifier: string;
  email?: string;
}): Promise<string> {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('createTestSession is not available in production');
  }
  const existing = await identityStore.findByProviderAndIdentifier(provider, identifier);
  let user: AuthUser;
  let identity: Identity;
  if (existing) {
    const found = await userStore.findById(existing.userId);
    if (!found) throw new Error(`User ${existing.userId} not found`);
    user = found;
    identity = existing;
  } else {
    user = await userStore.create({ provider, identifier, metadata: email ? { email } : {} });
    identity = await identityStore.create({ userId: user.id, provider, identifier });
  }
  return auth.createSessionCookie(user, identity);
}
