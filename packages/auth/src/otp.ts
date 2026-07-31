import type { Challenge } from "./types.js"

const DEFAULT_OTP_LENGTH = 6
const DECIMAL_DIGITS = 10
/** Largest byte value usable without modulo bias for base-10 digits (250 = 25 * 10) */
const UNBIASED_BYTE_LIMIT = 250

/**
 * Generate a numeric one-time code using a CSPRNG.
 * Uses rejection sampling so every digit is uniformly distributed.
 */
export function generateOtpCode(length: number = DEFAULT_OTP_LENGTH): string {
  if (!Number.isInteger(length) || length < 1) {
    throw new Error(`OTP length must be a positive integer, got ${length}`)
  }

  const digits: string[] = []
  while (digits.length < length) {
    const bytes = new Uint8Array(length)
    crypto.getRandomValues(bytes)
    for (const byte of bytes) {
      if (digits.length === length) break
      if (byte < UNBIASED_BYTE_LIMIT) {
        digits.push(String(byte % DECIMAL_DIGITS))
      }
    }
  }
  return digits.join("")
}

/**
 * Hash an OTP code for at-rest storage in a Challenge.
 * The challenge ID acts as the salt, so identical codes for different
 * challenges produce different hashes.
 */
export async function hashOtpCode(
  challengeId: string,
  code: string,
): Promise<string> {
  const data = new TextEncoder().encode(`${challengeId}:${code}`)
  const digest = await crypto.subtle.digest("SHA-256", data)
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
}

/**
 * Compare a submitted code against a challenge's stored hash in constant
 * time. Does NOT check expiry or attempt limits; callers enforce those
 * before comparing.
 */
export async function verifyOtpCode(
  challenge: Pick<Challenge, "id" | "hashedCode">,
  code: string,
): Promise<boolean> {
  if (!challenge.hashedCode) return false
  const submitted = await hashOtpCode(challenge.id, code)
  return constantTimeEqual(submitted, challenge.hashedCode)
}

/**
 * Constant-time string comparison to prevent timing attacks. Both inputs
 * are hex digests of equal length in normal operation; a length mismatch
 * returns false without leaking where the strings differ.
 */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let index = 0; index < a.length; index++) {
    diff |= a.charCodeAt(index) ^ b.charCodeAt(index)
  }
  return diff === 0
}
