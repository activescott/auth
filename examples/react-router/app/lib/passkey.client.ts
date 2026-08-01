import {
  startRegistration,
  startAuthentication,
  isConditionalUIAvailable,
} from "@activescott/auth-provider-passkey/browser"

export { isConditionalUIAvailable }

/**
 * Add a passkey to the signed-in user: fetch registration options, run
 * the WebAuthn ceremony, and post the result back for verification.
 * Throws when the user cancels or the server rejects the registration.
 */
export async function registerPasskey(): Promise<void> {
  const options = await postJson<Parameters<typeof startRegistration>[0]>(
    "/auth/passkey/register-options",
  )
  const registration = await startRegistration(options)
  await postJson("/auth/passkey/register-verify", registration)
}

/**
 * Sign in with a passkey. Pass conditional=true for the autofill flow
 * (the promise stays pending until the user picks a passkey from the
 * autofill suggestions). On success the session cookie is set; the
 * caller navigates.
 */
export async function signInWithPasskey(conditional = false): Promise<void> {
  const options = await postJson<Parameters<typeof startAuthentication>[0]>(
    "/auth/passkey/authenticate-options",
  )
  const assertion = await startAuthentication(options, { conditional })
  await postJson("/auth/passkey/authenticate-verify", assertion)
}

async function postJson<T>(url: string, body?: object): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    ...(body && {
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  })
  const json = await response.json().catch(() => null)
  if (!response.ok) {
    const message =
      json && typeof json.error?.message === "string"
        ? json.error.message
        : `Request to ${url} failed (${response.status})`
    throw new Error(message)
  }
  return json
}
