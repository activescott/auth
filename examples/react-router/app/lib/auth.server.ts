import {
  Auth,
  InMemoryChallengeStore,
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
  TwilioTransport,
  TwilioVerifyTransport,
} from "@activescott/auth-sms-twilio"
import {
  PasskeyProvider,
  parsePasskeyCredentialMetadata,
} from "@activescott/auth-provider-passkey"
import { CaptureEmailTransport } from "./capture-email-transport.server"
import { CaptureSmsTransport } from "./capture-sms-transport.server"
import { TurnstileBotCheck } from "@activescott/auth-botcheck-turnstile"
import { createAuthHandlers } from "@activescott/auth-adapter-react-router"

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
  async create({ identifier }) {
    // identifier is an email or a phone number depending on which
    // provider signed the user up
    const user: AuthUser = {
      id: crypto.randomUUID(),
      metadata: { identifier },
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
 * Wrap a message-sending transport in the e2e capture wrapper, leaving a
 * hosted verification transport alone — with Twilio Verify the code lives at
 * the vendor, so no code passes through this process to capture.
 */
function wrapForE2eReadback(
  transport: SmsTransport | VerificationTransport,
): SmsTransport | VerificationTransport {
  return isVerificationTransport(transport)
    ? transport
    : new CaptureSmsTransport(transport)
}

/**
 * SMTP is considered configured when SMTP_HOST is set (see .env.example).
 * Configured → real emails are sent. Not configured → dev mode: emails are
 * logged to the server console instead.
 */
const smtpConfigured = Boolean(process.env.SMTP_HOST)

/**
 * Twilio is considered configured when its env vars are all set (see
 * .env.example): account SID, auth token, and a sender (from number or
 * Messaging Service SID). Fully configured → real texts. Anything less →
 * console transport (codes printed to the server console), with a log
 * line naming exactly what's missing — so a subtle misconfiguration
 * (one env var absent in prod) is diagnosable instead of silent.
 *
 * Setting TWILIO_VERIFY_SERVICE_SID instead of a sender picks Twilio Verify,
 * where Twilio generates, texts, and checks the code from senders it already
 * registered — no US A2P 10DLC registration, no number to own, ~4-6x the
 * per-sign-in cost.
 */
function createSmsTransport(): SmsTransport | VerificationTransport {
  // E2e must never text real messages, even if Twilio env vars leak in
  // from the shell environment.
  if (process.env.E2E_TEST_MODE === "true") {
    return new ConsoleTransport()
  }

  const accountSid = process.env.TWILIO_ACCOUNT_SID
  const authToken = process.env.TWILIO_AUTH_TOKEN
  const from = process.env.TWILIO_FROM
  const messagingServiceSid = process.env.TWILIO_MESSAGING_SERVICE_SID
  const verifyServiceSid = process.env.TWILIO_VERIFY_SERVICE_SID

  if (accountSid && authToken && verifyServiceSid) {
    console.log(
      "SMS via Twilio Verify. Codes are generated and checked by Twilio; " +
        "per-attempt outcomes are in the Verify log: " +
        "https://console.twilio.com/us1/monitor/logs/verify",
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
    return new TwilioTransport({
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
      "TWILIO_FROM, TWILIO_MESSAGING_SERVICE_SID, or TWILIO_VERIFY_SERVICE_SID",
  ].filter((name): name is string => typeof name === "string")

  if (missing.length < 3) {
    // Partially configured — likely a misconfiguration, so be loud
    console.warn(
      `SMS: falling back to the console transport because Twilio is only partially configured — missing ${missing.join(", ")}. Set it to send real texts.`,
    )
  } else {
    console.log(
      "SMS: no Twilio configuration found — sign-in codes will be printed " +
        "to this console. Run ./infra/twilio/setup-twilio.mts to configure " +
        "real texting.",
    )
  }
  return new ConsoleTransport()
}

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
      new CaptureEmailTransport(new NodemailerTransport(!smtpConfigured)),
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
      // Verify never hands us the code, so there is nothing to capture and
      // that transport is passed straight through.
      wrapForE2eReadback(createSmsTransport()),
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
  errorRedirect: "/login",
  loginUrl: "/login",
})

export const { handleAuth, getSession, requireAuth, optionalAuth, logout } =
  handlers

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
