import { z } from "zod"
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server"

/**
 * Envelope schemas for the WebAuthn response JSON the browser posts to
 * the verify actions. Deliberately loose: they check the fields this
 * provider touches before handing the body to @simplewebauthn/server,
 * whose verification owns field-level validation.
 */
const registrationResponseSchema = z.looseObject({
  id: z.string().min(1),
  rawId: z.string().min(1),
  type: z.literal("public-key"),
  response: z.looseObject({
    clientDataJSON: z.string().min(1),
    attestationObject: z.string().min(1),
  }),
})

const authenticationResponseSchema = z.looseObject({
  id: z.string().min(1),
  rawId: z.string().min(1),
  type: z.literal("public-key"),
  response: z.looseObject({
    clientDataJSON: z.string().min(1),
    authenticatorData: z.string().min(1),
    signature: z.string().min(1),
  }),
})

/**
 * Narrow a parsed body to a WebAuthn registration response
 */
export function isRegistrationResponse(
  body: Record<string, unknown>,
): body is RegistrationResponseJSON & Record<string, unknown> {
  return registrationResponseSchema.safeParse(body).success
}

/**
 * Narrow a parsed body to a WebAuthn authentication response
 */
export function isAuthenticationResponse(
  body: Record<string, unknown>,
): body is AuthenticationResponseJSON & Record<string, unknown> {
  return authenticationResponseSchema.safeParse(body).success
}
