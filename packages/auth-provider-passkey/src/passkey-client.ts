import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/server"
import {
  runAuthenticationCeremony,
  runRegistrationCeremony,
} from "./webauthn-ceremony.js"

const DEFAULT_BASE_PATH = "/auth"

/** Options for createPasskeyClient */
export interface PasskeyClientOptions {
  /**
   * Path the auth routes are served under (default "/auth"); the client
   * posts to `${basePath}/passkey/<action>`. Requests are same-origin
   * fetches, so the browser sends the session and challenge cookies.
   */
  basePath?: string
}

/** Options for PasskeyClient.signInWithPasskey */
export interface SignInWithPasskeyOptions {
  /**
   * Use conditional UI (passkey autofill on a field with
   * autocomplete="username webauthn"). The promise then stays pending until
   * the user picks a passkey from the autofill suggestions, and is rejected
   * with an AbortError if another ceremony starts first. Check
   * isConditionalUIAvailable() before passing true.
   */
  conditional?: boolean
}

/** Browser client for the passkey provider's four endpoints */
export interface PasskeyClient {
  /**
   * Add a passkey to the signed-in user: fetch registration options, run
   * the WebAuthn ceremony, and post the result back for verification.
   * Throws when the user cancels or the server rejects the registration.
   */
  registerPasskey(): Promise<void>
  /**
   * Sign in with a passkey. On success the session cookie is set and the
   * caller navigates. Throws when the user cancels or the server rejects the
   * assertion.
   */
  signInWithPasskey(options?: SignInWithPasskeyOptions): Promise<void>
}

/**
 * Create a browser client that runs the passkey ceremonies against the
 * provider's endpoints. When the server rejects a request, the thrown
 * Error's message is the most specific one the response carries: the
 * error's details.reason (e.g. "Unknown credential" — a passkey saved in a
 * password manager whose identity row the server no longer has), else its
 * message, else the HTTP status.
 */
export function createPasskeyClient(
  options: PasskeyClientOptions = {},
): PasskeyClient {
  const basePath = (options.basePath ?? DEFAULT_BASE_PATH).replace(/\/+$/, "")
  const actionUrl = (action: string): string => `${basePath}/passkey/${action}`

  return {
    async registerPasskey() {
      const optionsJSON =
        await postJson<PublicKeyCredentialCreationOptionsJSON>(
          actionUrl("register-options"),
        )
      const registration = await runRegistrationCeremony(optionsJSON)
      await postJson(actionUrl("register-verify"), registration)
    },

    async signInWithPasskey({ conditional = false } = {}) {
      const optionsJSON = await postJson<PublicKeyCredentialRequestOptionsJSON>(
        actionUrl("authenticate-options"),
      )
      const assertion = await runAuthenticationCeremony(optionsJSON, {
        conditional,
      })
      await postJson(actionUrl("authenticate-verify"), assertion)
    },
  }
}

/**
 * POST (optionally with a JSON body) and return the parsed JSON response,
 * throwing an Error that carries the server's most specific reason on a
 * non-2xx status
 */
async function postJson<T>(url: string, body?: object): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    ...(body && {
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  })
  const json: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    throw new Error(
      errorMessage(json) ?? `Request to ${url} failed (${response.status})`,
    )
  }
  return json as T
}

/**
 * The error text from a `{ success: false, error: AuthError }` body:
 * details.reason when present, else message
 */
function errorMessage(json: unknown): string | undefined {
  if (!isRecord(json) || !isRecord(json.error)) return undefined
  const { details, message } = json.error
  if (isRecord(details) && typeof details.reason === "string") {
    return details.reason
  }
  return typeof message === "string" ? message : undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}
