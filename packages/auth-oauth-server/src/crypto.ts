/** 256 bits, the entropy of every token, code, and secret this server issues. */
const TOKEN_BYTES = 32
const HEX_RADIX = 16
const HEX_BYTE_WIDTH = 2

/**
 * A 256-bit random value from the platform CSPRNG, base64url without
 * padding, behind an optional prefix.
 */
export function randomToken(prefix = ""): string {
  const bytes = crypto.getRandomValues(new Uint8Array(TOKEN_BYTES))
  return prefix + base64url(bytes)
}

/** SHA-256 of a UTF-8 string as lowercase hex: how every secret is stored. */
export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  )
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(HEX_RADIX).padStart(HEX_BYTE_WIDTH, "0"),
  ).join("")
}

/** The RFC 7636 S256 challenge for a verifier: BASE64URL(SHA256(ASCII(verifier))). */
export async function s256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  )
  return base64url(new Uint8Array(digest))
}

function base64url(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}
