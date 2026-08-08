import {
  Auth,
  InMemoryChallengeStore,
  buildReturnUrl,
  createFormToken,
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
  SmsProvider,
  ConsoleTransport,
  isVerificationTransport,
  type SmsTransport,
  type VerificationTransport,
} from "@activescott/auth-provider-sms"
import {
  TwilioMessagingTransport,
  TwilioVerifyTransport,
} from "@activescott/auth-sms-twilio"
import {
  PasskeyProvider,
  parsePasskeyCredentialMetadata,
} from "@activescott/auth-provider-passkey"
import { CaptureEmailTransport } from "@activescott/auth-provider-email/testing"
import { CaptureSmsTransport } from "@activescott/auth-provider-sms/testing"
import { TurnstileBotCheck } from "@activescott/auth-botcheck-turnstile"
import { createAuthHandlers } from "@activescott/auth-adapter-react-router"
import { createAdminHandlers } from "@activescott/auth-adapter-react-router/admin"

/** Set TURNSTILE_SECRET_KEY (and TURNSTILE_SITE_KEY) to turn Turnstile on */
const turnstileSecretKey = process.env.TURNSTILE_SECRET_KEY

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
  async create({ provider, identifier }) {
    // identifier is an email or a phone number depending on which
    // provider signed the user up
    const user: AuthUser = {
      id: crypto.randomUUID(),
      // Anything the admin users page should show as a column goes in
      // metadata — that is the extension point, so the store interface does
      // not need to know about application-specific fields.
      metadata: {
        identifier,
        signedUpWith: provider,
        signedUpAt: new Date().toISOString(),
      },
    }
    users.set(user.id, user)
    return user
  },
  /**
   * Optional, and only the admin dashboard uses it. A real app pushes the
   * sorting and paging into the database; here the whole map is small enough
   * to sort in memory.
   */
  async listUsers({ limit, offset, sortBy, sortOrder, filter }) {
    let all = [...users.values()]

    // Filtering belongs here, not in the page: `total` has to count the
    // filtered set for the pager to be right. A real app turns this into a
    // WHERE clause. Keys this store does not recognize are ignored, the same
    // way an unknown `sortBy` is.
    const wantedProvider = filter?.signedUpWith
    if (wantedProvider) {
      all = all.filter((user) => user.metadata?.signedUpWith === wantedProvider)
    }

    const direction = sortOrder === "asc" ? 1 : -1
    if (sortBy) {
      all.sort((left, right) => {
        const a = String(left.metadata?.[sortBy] ?? "")
        const b = String(right.metadata?.[sortBy] ?? "")
        return a.localeCompare(b) * direction
      })
    }
    return { users: all.slice(offset, offset + limit), total: all.length }
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
  /**
   * Optional. Without it the admin users page still works, but issues one
   * query per row; a real app implements this as a single `WHERE user_id IN
   * (...)`.
   */
  async findByUserIds(userIds) {
    const wanted = new Set(userIds)
    return [...identities.values()].filter((index) => wanted.has(index.userId))
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
 * The signed-in user's passkeys for the dashboard list. Passkeys are
 * ordinary identity rows ({provider: "passkey"}) whose provider-owned
 * metadata holds the credential state; a restart wipes the in-memory
 * store, orphaning any passkeys saved in the browser/password manager
 * for localhost (delete those there when it happens).
 */
export async function listPasskeys(userId: string): Promise<
  {
    credentialId: string
    nickname: string | null
    synced: boolean
    createdAt: string
    lastUsedAt: string | null
  }[]
> {
  const all = await identityStore.findByUserId(userId)
  const passkeys = []
  for (const identity of all) {
    if (identity.provider !== "passkey") continue
    const credential = parsePasskeyCredentialMetadata(identity.metadata)
    if (!credential) continue
    passkeys.push({
      credentialId: identity.identifier,
      nickname: credential.nickname ?? null,
      // "multiDevice" = synced to a cloud keychain / password manager
      synced: credential.deviceType === "multiDevice",
      createdAt: identity.createdAt.toISOString(),
      lastUsedAt: credential.lastUsedAt ?? null,
    })
  }
  return passkeys
}

/**
 * SMTP is considered configured when SMTP_HOST is set (see .env.example).
 * Configured → real emails are sent. Not configured → dev mode: emails are
 * logged to the server console instead.
 */
const smtpConfigured = Boolean(process.env.SMTP_HOST)

/**
 * Twilio is considered configured when its env vars are all set (see
 * .env.example): account SID, auth token, and either a Verify service or a
 * sender. Fully configured → real texts. Anything less → console transport
 * (codes printed to the server console), with a log line naming exactly
 * what's missing — so a subtle misconfiguration (one env var absent in
 * prod) is diagnosable instead of silent.
 *
 * TWILIO_VERIFY_SERVICE_SID picks Twilio Verify, where Twilio generates,
 * texts, and checks the code from senders it already registered — no US A2P
 * 10DLC registration, no number to own, ~4-6x the per-sign-in cost. The
 * TWILIO_SMS_* sender vars pick raw SMS instead, which is cheaper per
 * message but leaves 10DLC registration to the app.
 */
function createSmsTransport(): SmsTransport | VerificationTransport {
  // E2e must never text real messages, even if Twilio env vars leak in
  // from the shell environment.
  if (process.env.E2E_TEST_MODE === "true") {
    return new ConsoleTransport()
  }

  const accountSid = process.env.TWILIO_ACCOUNT_SID
  const authToken = process.env.TWILIO_AUTH_TOKEN
  const from = process.env.TWILIO_SMS_FROM
  const messagingServiceSid = process.env.TWILIO_SMS_MESSAGING_SERVICE_SID
  const verifyServiceSid = process.env.TWILIO_VERIFY_SERVICE_SID

  if (accountSid && authToken && verifyServiceSid) {
    console.log(
      "SMS via Twilio Verify. Codes are generated and checked by Twilio; " +
        "per-attempt outcomes are in the Verify log: " +
        "https://console.twilio.com/us1/monitor/logs/verify-logs",
    )
    return new TwilioVerifyTransport({
      accountSid,
      authToken,
      serviceSid: verifyServiceSid,
    })
  }

  if (accountSid && authToken && (from || messagingServiceSid)) {
    console.log(
      "SMS via Twilio. If a text never arrives, check the delivery log " +
        "(carriers can filter messages the API accepted, e.g. error 30034 " +
        "for unregistered A2P 10DLC numbers): " +
        "https://console.twilio.com/us1/monitor/logs/sms",
    )
    return new TwilioMessagingTransport({
      accountSid,
      authToken,
      from,
      messagingServiceSid,
    })
  }

  const missing = [
    !accountSid && "TWILIO_ACCOUNT_SID",
    !authToken && "TWILIO_AUTH_TOKEN",
    !from &&
      !messagingServiceSid &&
      "TWILIO_VERIFY_SERVICE_SID, TWILIO_SMS_MESSAGING_SERVICE_SID, or TWILIO_SMS_FROM",
  ].filter((name): name is string => typeof name === "string")

  if (missing.length < 3) {
    // Partially configured — likely a misconfiguration, so be loud
    console.warn(
      `SMS: falling back to the console transport because Twilio is only partially configured — missing ${missing.join(", ")}. Set it to send real texts.`,
    )
  } else {
    console.log(
      "SMS: no Twilio configuration found — sign-in codes will be printed " +
        "to this console. See .env.example to configure real texting.",
    )
  }
  return new ConsoleTransport()
}

/**
 * The capture transports record the last message per recipient so the e2e
 * readback route can hand tests the code without an inbox or a phone. They
 * come from each provider's `/testing` subpath — test support, not part of
 * the package's normal surface. A real app installs them only under a
 * test-mode flag; this example always does because it has no other way to
 * show you the code.
 */
const captureEmailTransport = new CaptureEmailTransport(
  new NodemailerTransport(!smtpConfigured),
)
const smsTransport = createSmsTransport()

/**
 * Capturing only makes sense for a transport that sends a message this
 * process composed. With Twilio Verify the code is generated, sent, and
 * checked by the vendor and never reaches us, so there is nothing to capture
 * — hence null, and the readback route answers 404 for phone lookups. E2e
 * forces the console transport, so its readback is unaffected.
 */
const captureSmsTransport = isVerificationTransport(smsTransport)
  ? null
  : new CaptureSmsTransport(smsTransport)

export { captureEmailTransport, captureSmsTransport }

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
  // Abuse protection is on with no configuration at all: per-IP and
  // per-recipient rate limits backed by an in-memory counter store, plus the
  // form-token check the login form below feeds. Everything
  // here is optional tuning.
  abuse: {
    // Submissions faster than this are treated as bots. The library default
    // is 2 seconds; this example lowers it to 1 so its Playwright suite does
    // not pause two seconds before every sign-in. Keep the default (or
    // higher) in a real app.
    minFormFillSeconds: 1,
    // Where blocked attempts go beyond the library's own warn-level log.
    // A real app forwards these to its logger/metrics so an abuse burst is
    // visible: `logger.warn({ ...event }, "auth abuse blocked")`.
    onBlocked: (event) => {
      // eslint-disable-next-line no-console -- the example has no logger
      console.warn("abuse blocked:", event)
    },
    // Hosted bot checks live in their own packages so you only install the
    // vendor you use. Turnstile stays off unless a secret key is present, so
    // the example runs with no Cloudflare account.
    botChecks: turnstileSecretKey
      ? [new TurnstileBotCheck({ secretKey: turnstileSecretKey })]
      : [],
  },
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
      captureEmailTransport,
    ),
    new SmsProvider(
      {
        appName: "RR Auth Example",
        // Uncomment with your app's domain to enable WebOTP one-tap
        // autofill on Android/Chrome (appends "@domain #code" to the SMS):
        // webOtpDomain: "example.com",
      },
      // The capture wrapper records the last code per phone number for
      // the e2e readback route; it delegates to the real transport. Twilio
      // Verify never hands us the code, so there is nothing to wrap and the
      // transport is used directly.
      captureSmsTransport ?? smsTransport,
    ),
    new PasskeyProvider({
      rpName: "RR Auth Example",
      // rpID and expectedOrigin default to the request's hostname/origin,
      // which suits dev and e2e on localhost. Set both explicitly in
      // production (passkeys are bound to the domain they were created on).
      challengeSecret: SESSION_SECRET,
    }),
  ],
})

const handlers = createAuthHandlers(auth, {
  successRedirect: "/dashboard",
  // Back to the page the form was posted from, with ?error= added, instead of
  // a bare "/login". The login page keeps the chosen provider in the query
  // (?via=sms), so a plain path would answer a failed phone code on the email
  // tab. buildReturnUrl reads the Referer and preserves everything already
  // there.
  errorRedirect: (error, request) =>
    buildReturnUrl(request, { error: error.code }),
  loginUrl: "/login",
})

export const { handleAuth, getSession, requireAuth, optionalAuth, logout } =
  handlers

/**
 * The read-only admin dashboard at /admin. Who gets in is an allowlist of
 * identifiers (email addresses and/or E.164 phone numbers) in
 * AUTH_ADMIN_IDENTIFIERS — see .env.example. The list is empty by default, and
 * an empty list admits nobody, so the pages stay shut until you opt in.
 *
 * A signed-in visitor who is not on the list gets a 404 rather than a 403, so
 * the admin area does not announce itself.
 */
export const { requireAdmin, adminUsersLoader, adminConfigLoader } =
  createAdminHandlers(auth, {
    requireAuth,
    admins: process.env.AUTH_ADMIN_IDENTIFIERS,
    // Newest sign-ups first, which is what you usually want when you open the
    // page. The key is a metadata key, handled by `userStore.listUsers` above.
    defaultSort: { sortBy: "signedUpAt", sortOrder: "desc" },
  })

/**
 * Anti-bot form fields for the login page, minted per render: a signed
 * timestamp the form-token check reads to reject submissions faster than a
 * human could type, plus the Turnstile site key when Turnstile is configured.
 */
export async function createLoginFormFields(): Promise<{
  formToken: string
  turnstileSiteKey: string | null
}> {
  return {
    formToken: await createFormToken(SESSION_SECRET),
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY ?? null,
  }
}
