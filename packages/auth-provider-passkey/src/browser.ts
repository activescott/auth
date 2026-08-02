import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server"
import { base64urlToUint8Array, uint8ArrayToBase64url } from "./base64url.js"

/**
 * Run the WebAuthn registration ceremony in the browser: converts the
 * options JSON from the register-options action, calls
 * navigator.credentials.create, and returns the JSON body to POST to
 * register-verify. Throws when the user cancels or no authenticator is
 * available.
 */
export async function startRegistration(
  optionsJSON: PublicKeyCredentialCreationOptionsJSON,
): Promise<RegistrationResponseJSON> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...optionsJSON,
    challenge: toBuffer(optionsJSON.challenge),
    user: {
      ...optionsJSON.user,
      id: toBuffer(optionsJSON.user.id),
    },
    excludeCredentials: optionsJSON.excludeCredentials?.map((credential) => ({
      ...credential,
      id: toBuffer(credential.id),
      transports: toDomTransports(credential.transports),
    })),
  }

  const credential = await navigator.credentials.create({
    publicKey,
    signal: newCeremonySignal(),
  })
  if (!(credential instanceof PublicKeyCredential)) {
    throw new TypeError("Registration was not completed")
  }
  const response = credential.response
  if (!(response instanceof AuthenticatorAttestationResponse)) {
    throw new TypeError("Unexpected authenticator response type")
  }

  return {
    id: credential.id,
    rawId: fromBuffer(credential.rawId),
    response: {
      clientDataJSON: fromBuffer(response.clientDataJSON),
      attestationObject: fromBuffer(response.attestationObject),
      transports: castTransports(response.getTransports?.()),
    },
    type: "public-key",
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: castAttachment(credential.authenticatorAttachment),
  }
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
 */
export async function startAuthentication(
  optionsJSON: PublicKeyCredentialRequestOptionsJSON,
  options: { conditional?: boolean } = {},
): Promise<AuthenticationResponseJSON> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...optionsJSON,
    challenge: toBuffer(optionsJSON.challenge),
    allowCredentials: optionsJSON.allowCredentials?.map((credential) => ({
      ...credential,
      id: toBuffer(credential.id),
      transports: toDomTransports(credential.transports),
    })),
  }

  const credential = await navigator.credentials.get({
    publicKey,
    mediation: options.conditional ? "conditional" : undefined,
    signal: newCeremonySignal(),
  })
  if (!(credential instanceof PublicKeyCredential)) {
    throw new TypeError("Authentication was not completed")
  }
  const response = credential.response
  if (!(response instanceof AuthenticatorAssertionResponse)) {
    throw new TypeError("Unexpected authenticator response type")
  }

  return {
    id: credential.id,
    rawId: fromBuffer(credential.rawId),
    response: {
      clientDataJSON: fromBuffer(response.clientDataJSON),
      authenticatorData: fromBuffer(response.authenticatorData),
      signature: fromBuffer(response.signature),
      userHandle: response.userHandle
        ? fromBuffer(response.userHandle)
        : undefined,
    },
    type: "public-key",
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: castAttachment(credential.authenticatorAttachment),
  }
}

/**
 * True when the browser supports WebAuthn conditional UI (passkey
 * autofill)
 */
export async function isConditionalUIAvailable(): Promise<boolean> {
  return (
    typeof PublicKeyCredential !== "undefined" &&
    typeof PublicKeyCredential.isConditionalMediationAvailable === "function" &&
    (await PublicKeyCredential.isConditionalMediationAvailable())
  )
}

let pendingCeremony: AbortController | undefined

/**
 * The browser allows one WebAuthn ceremony at a time, so starting a new
 * one aborts any pending request — e.g. a conditional-UI request left
 * pending on the login page when the user clicks the passkey button.
 */
function newCeremonySignal(): AbortSignal {
  pendingCeremony?.abort(
    new DOMException("Superseded by a new WebAuthn ceremony", "AbortError"),
  )
  pendingCeremony = new AbortController()
  return pendingCeremony.signal
}

function toBuffer(value: string): ArrayBuffer {
  return base64urlToUint8Array(value).buffer
}

function fromBuffer(buffer: ArrayBuffer): string {
  return uint8ArrayToBase64url(new Uint8Array(buffer))
}

/**
 * Keep only the transports the DOM WebAuthn types accept; authenticators
 * may report values (e.g. "smart-card") that lib.dom does not know yet.
 */
function toDomTransports(
  transports: readonly string[] | undefined,
): AuthenticatorTransport[] | undefined {
  const filtered = transports?.filter(isDomTransport)
  return filtered && filtered.length > 0 ? filtered : undefined
}

function isDomTransport(
  transport: string,
): transport is AuthenticatorTransport {
  return ["ble", "hybrid", "internal", "nfc", "usb"].includes(transport)
}

/**
 * Filter authenticator-reported transports to the values
 * @simplewebauthn/server understands
 */
function castTransports(
  transports: readonly string[] | undefined,
): RegistrationResponseJSON["response"]["transports"] {
  const filtered = transports?.filter(isKnownTransport)
  return filtered && filtered.length > 0 ? filtered : undefined
}

function isKnownTransport(
  transport: string,
): transport is NonNullable<
  RegistrationResponseJSON["response"]["transports"]
>[number] {
  return [
    "ble",
    "cable",
    "hybrid",
    "internal",
    "nfc",
    "smart-card",
    "usb",
  ].includes(transport)
}

function castAttachment(
  attachment: string | null | undefined,
): RegistrationResponseJSON["authenticatorAttachment"] {
  return attachment === "platform" || attachment === "cross-platform"
    ? attachment
    : undefined
}
