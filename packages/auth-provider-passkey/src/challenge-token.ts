import { SignJWT, jwtVerify } from "jose"

export interface ChallengeTokenPayload {
  /** The WebAuthn challenge (base64url) issued in the options */
  challenge: string
  /** Which ceremony this challenge was issued for */
  purpose: "registration" | "authentication"
  /** The signed-in user a registration challenge is bound to */
  userId?: string
  /** Unique token id; keys the optional single-use challenge store row */
  jti: string
}

/**
 * Sign a challenge as a compact JWT for the HttpOnly challenge cookie
 */
export async function signChallengeToken(
  secret: string,
  payload: ChallengeTokenPayload,
  expirySeconds: number,
): Promise<string> {
  return new SignJWT({
    challenge: payload.challenge,
    purpose: payload.purpose,
    userId: payload.userId,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setJti(payload.jti)
    .setIssuedAt()
    .setExpirationTime(`${expirySeconds}s`)
    .sign(new TextEncoder().encode(secret))
}

/**
 * Verify a challenge cookie JWT. Returns null for a missing, tampered,
 * expired, or malformed token.
 */
export async function verifyChallengeToken(
  secret: string,
  token: string,
): Promise<ChallengeTokenPayload | null> {
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(secret))
    const { challenge, purpose, userId, jti } = payload
    if (typeof challenge !== "string" || typeof jti !== "string") return null
    if (purpose !== "registration" && purpose !== "authentication") return null
    return {
      challenge,
      purpose,
      userId: typeof userId === "string" ? userId : undefined,
      jti,
    }
  } catch {
    return null
  }
}
