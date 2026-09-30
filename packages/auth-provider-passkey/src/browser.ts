import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server"
import {
  runAuthenticationCeremony,
  runRegistrationCeremony,
} from "./webauthn-ceremony.js"

export { createPasskeyClient } from "./passkey-client.js"
export type {
  PasskeyClient,
  PasskeyClientOptions,
  SignInWithPasskeyOptions,
} from "./passkey-client.js"
export { isConditionalUIAvailable } from "./webauthn-ceremony.js"

/**
 * Run the WebAuthn registration ceremony in the browser: converts the
 * options JSON from the register-options action, calls
 * navigator.credentials.create, and returns the JSON body to POST to
 * register-verify. Throws when the user cancels or no authenticator is
 * available.
 *
 * @deprecated You probably don't need this anymore. Use
 * `createPasskeyClient().registerPasskey()` instead, which also fetches the
 * options and posts the result. If that doesn't work for you, open a PR that
 * amends this comment, explains why, and recommends keeping the deprecation
 * or adding a feature you need.
 */
export async function startRegistration(
  optionsJSON: PublicKeyCredentialCreationOptionsJSON,
): Promise<RegistrationResponseJSON> {
  return runRegistrationCeremony(optionsJSON)
}

/**
 * Run the WebAuthn authentication ceremony in the browser: converts the
 * options JSON from the authenticate-options action, calls
 * navigator.credentials.get, and returns the JSON body to POST to
 * authenticate-verify.
 *
 * Pass conditional: true for conditional UI (passkey autofill on a form
 * field with autocomplete="... webauthn"); the returned promise then
 * stays pending until the user picks a passkey from the autofill.
 *
 * @deprecated You probably don't need this anymore. Use
 * `createPasskeyClient().signInWithPasskey({ conditional })` instead, which
 * also fetches the options and posts the assertion. If that doesn't work for
 * you, open a PR that amends this comment, explains why, and recommends
 * keeping the deprecation or adding a feature you need.
 */
export async function startAuthentication(
  optionsJSON: PublicKeyCredentialRequestOptionsJSON,
  options: { conditional?: boolean } = {},
): Promise<AuthenticationResponseJSON> {
  return runAuthenticationCeremony(optionsJSON, options)
}
