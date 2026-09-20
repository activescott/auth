import {
  AUTH_ERROR_MESSAGES,
  createFormToken,
  getAuthErrorMessage,
  resolveRedirectTarget,
} from "@activescott/auth"
import type { Auth, AuthErrorCode, IdentityStore } from "@activescott/auth"

const IDENTITY_CONFLICT: AuthErrorCode = "IDENTITY_CONFLICT"

/** Identity.provider of passkeys, which the profile page lists separately */
const PASSKEY_PROVIDER_ID = "passkey"

/** App messages by error code; they win over the library's own */
export type AuthErrorMessages = Readonly<Record<string, string>>

/**
 * Options for {@link createAuthPageLoaders}
 * @typeParam TPasskey - What `listPasskeys` returns per passkey
 */
export interface AuthPageLoadersOptions<TPasskey = never> {
  /**
   * The public half of the Turnstile key pair, handed to the page so
   * `useTurnstile` can render the widget. Leave it unset (or empty) where
   * Turnstile is off, dev and e2e usually, and the forms render without it.
   */
  turnstileSiteKey?: string | null
  /**
   * Fills `passkeys` on the profile page. Pass `listPasskeys` from
   * `@activescott/auth-provider-passkey` as is; without it `passkeys` is
   * empty. Taken as an option so apps without passkeys never install the
   * WebAuthn library.
   */
  listPasskeys?: (
    identityStore: IdentityStore,
    userId: string,
  ) => Promise<TPasskey[]>
  /**
   * Messages for error codes the library does not know (an initiate gate's
   * `?error=blocked`) or words differently. Applied by both loaders.
   */
  errorMessages?: AuthErrorMessages
}

/** Per-call options for the page loaders */
export interface PageLoaderCallOptions {
  /** Merged over the factory's `errorMessages` for this page only */
  errorMessages?: AuthErrorMessages
}

/**
 * What a sign-in page needs to render, parsed from the URL the providers
 * redirect back to. Plain JSON, so it can be returned from a loader as is.
 */
export interface SignInLoaderData {
  /**
   * Which provider's form to show, from `?via=`: the id of a provider with an
   * initiate route, defaulting to the first one registered. The providers
   * redirect back to the page the form was posted from, so `?via=sms`
   * survives the round trip. Null only when no provider has an initiate
   * route.
   */
  via: string | null
  /** `?sent=1`: the message went out, so show the code form */
  sent: boolean
  /** The message for `?error=`, or null */
  error: string | null
  /** The raw `?error=` code, for pages that branch on it */
  errorCode: string | null
  /**
   * `?redirectTo=` when it names a page on this app, else null. Post it with
   * the initiate form and add it to the verify URL so the user lands where
   * they were headed.
   */
  redirectTo: string | null
  /** Signed render timestamp for the form-token bot check; post it as `FORM_TOKEN_FIELD` */
  formToken: string
  /** Turnstile site key, or null when Turnstile is off */
  turnstileSiteKey: string | null
}

/** An email address or phone number that signs in to the account */
export interface SignInMethod {
  id: string
  provider: string
  identifier: string
  /** ISO timestamp */
  createdAt: string
  /** ISO timestamp, or null if never recorded */
  verifiedAt: string | null
}

/**
 * State of the add-a-sign-in-method flow on a profile page. The flow posts to
 * the providers' own initiate and verify endpoints with `mode=link`, and they
 * redirect back here, so its progress travels in the query string.
 */
export interface LinkFlow {
  /**
   * The provider whose add form is open, from `?add=`. Null once the flow has
   * finished (`linked` or `merged`), so a finished flow does not leave its form
   * open.
   */
  add: string | null
  /** `?sent=1`: the confirmation went out, so show the code form */
  sent: boolean
  /** `?linked=1` with no error: the identifier was added */
  linked: boolean
  /** `?merged=1`: another account was merged into this one */
  merged: boolean
  /**
   * Set when the verify answered IDENTITY_CONFLICT: the identifier belongs to
   * another account and a merge ticket cookie is waiting. Offer the merge by
   * posting to `/auth/{provider}/link-merge`; the ticket only redeems at the
   * provider that minted it, which comes from `?provider=` or else `?add=`.
   * When neither names one, this is null and `error` carries the conflict
   * message instead.
   */
  conflict: { provider: string } | null
  /** The message for `?error=`, or null (also null for a conflict it can offer to merge) */
  error: string | null
  /** The raw `?error=` code */
  errorCode: string | null
  /** Link initiates go through the same abuse checks as sign-in */
  formToken: string
  turnstileSiteKey: string | null
}

/**
 * What a profile page needs for its sign-in methods section
 * @typeParam TPasskey - What `listPasskeys` returns per passkey
 */
export interface ProfileAuthLoaderData<TPasskey = never> {
  /** Every sign-in method except passkeys */
  identities: SignInMethod[]
  /** From the `listPasskeys` option; empty without it */
  passkeys: TPasskey[]
  linkFlow: LinkFlow
}

/**
 * Loaders returned by {@link createAuthPageLoaders}
 * @typeParam TPasskey - What `listPasskeys` returns per passkey
 */
export interface AuthPageLoaders<TPasskey = never> {
  /**
   * Everything a sign-in page renders from. Deciding whether a signed-in
   * visitor skips the page stays with the app, which knows who counts as
   * signed in.
   */
  signInLoader(
    request: Request,
    options?: PageLoaderCallOptions,
  ): Promise<SignInLoaderData>
  /**
   * The signed-in user's sign-in methods, passkeys, and add-method flow
   * state. Call it after your own `requireAuth`.
   */
  profileAuthLoader(
    userId: string,
    request: Request,
    options?: PageLoaderCallOptions,
  ): Promise<ProfileAuthLoaderData<TPasskey>>
  /** The user's sign-in methods, passkeys excluded */
  listSignInMethods(userId: string): Promise<SignInMethod[]>
}

/**
 * Server-side loaders for sign-in and profile pages. They parse the query
 * parameters the providers redirect back with, mint the form token, and
 * resolve error codes to messages; the page keeps its own markup.
 *
 * @typeParam TPasskey - Inferred from `listPasskeys`
 *
 * @example
 * ```ts
 * import { listPasskeys } from "@activescott/auth-provider-passkey"
 *
 * export const { signInLoader, profileAuthLoader } = createAuthPageLoaders(
 *   auth,
 *   { turnstileSiteKey: process.env.TURNSTILE_SITE_KEY, listPasskeys },
 * )
 * ```
 */
export function createAuthPageLoaders<TPasskey = never>(
  auth: Auth,
  options: AuthPageLoadersOptions<TPasskey> = {},
): AuthPageLoaders<TPasskey> {
  const turnstileSiteKey = options.turnstileSiteKey || null

  // Providers are fixed once Auth is constructed
  let initiateProviders: string[] | undefined
  function providersWithInitiate(): string[] {
    initiateProviders ??= auth
      .getProviders()
      .filter((provider) =>
        provider.getRoutes().some((route) => route.handler === "initiate"),
      )
      .map((provider) => provider.id)
    return initiateProviders
  }

  function pickProvider(candidate: string | null): string | null {
    return candidate && providersWithInitiate().includes(candidate)
      ? candidate
      : null
  }

  function messageFor(
    code: string,
    callOptions: PageLoaderCallOptions | undefined,
  ): string {
    const overrides = {
      ...options.errorMessages,
      ...callOptions?.errorMessages,
    }
    // Own keys only: the code comes from the URL, and ?error=toString must
    // not find Object.prototype.toString
    if (Object.hasOwn(overrides, code)) return overrides[code] as string
    if (Object.hasOwn(AUTH_ERROR_MESSAGES, code)) {
      return AUTH_ERROR_MESSAGES[code as AuthErrorCode]
    }
    // No code is "", so this is the library's default message
    return getAuthErrorMessage("")
  }

  function mintFormToken(): Promise<string> {
    // The abuse guard verifies form tokens with the session secret
    return createFormToken(auth.getSessionConfig().secret)
  }

  async function listSignInMethods(userId: string): Promise<SignInMethod[]> {
    const { identityStore } = auth.getStores()
    const identities = await identityStore.findByUserId(userId)
    return identities
      .filter((identity) => identity.provider !== PASSKEY_PROVIDER_ID)
      .map((identity) => ({
        id: identity.id,
        provider: identity.provider,
        identifier: identity.identifier,
        createdAt: identity.createdAt.toISOString(),
        verifiedAt: identity.verifiedAt?.toISOString() ?? null,
      }))
  }

  return {
    async signInLoader(request, callOptions) {
      const params = new URL(request.url).searchParams
      const errorCode = params.get("error")
      const redirectTo = resolveRedirectTarget(
        params.get("redirectTo"),
        request.url,
        "",
        { logger: auth.getLogger(), source: "redirectTo" },
      )
      return {
        via:
          pickProvider(params.get("via")) ?? providersWithInitiate()[0] ?? null,
        sent: params.get("sent") === "1",
        error: errorCode ? messageFor(errorCode, callOptions) : null,
        errorCode,
        redirectTo: redirectTo || null,
        formToken: await mintFormToken(),
        turnstileSiteKey,
      }
    },

    async profileAuthLoader(userId, request, callOptions) {
      const params = new URL(request.url).searchParams
      const errorCode = params.get("error")
      const merged = params.get("merged") === "1"
      const linked = params.get("linked") === "1" && !errorCode && !merged
      const add = pickProvider(params.get("add"))
      const conflictProvider =
        errorCode === IDENTITY_CONFLICT
          ? (pickProvider(params.get("provider")) ?? add)
          : null

      const [identities, passkeys, formToken] = await Promise.all([
        listSignInMethods(userId),
        options.listPasskeys
          ? options.listPasskeys(auth.getStores().identityStore, userId)
          : Promise.resolve([]),
        mintFormToken(),
      ])

      return {
        identities,
        passkeys,
        linkFlow: {
          add: linked || merged ? null : add,
          sent: params.get("sent") === "1" && !merged,
          linked,
          merged,
          conflict: conflictProvider ? { provider: conflictProvider } : null,
          error:
            errorCode && !conflictProvider
              ? messageFor(errorCode, callOptions)
              : null,
          errorCode,
          formToken,
          turnstileSiteKey,
        },
      }
    },

    listSignInMethods,
  }
}
