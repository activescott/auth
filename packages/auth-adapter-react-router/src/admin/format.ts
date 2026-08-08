/** Characters kept at each end when eliding a long opaque identifier */
const IDENTIFIER_HEAD = 10
const IDENTIFIER_TAIL = 6
const IDENTIFIER_MAX = IDENTIFIER_HEAD + IDENTIFIER_TAIL + 3

/**
 * Words that read wrong in title case. Matched against whole words only, so
 * "identifier" is not caught by "id".
 */
const ACRONYMS = new Set(["id", "ip", "otp", "rp", "sms", "smtp", "url", "jwt"])

/**
 * Render a timestamp as `YYYY-MM-DD HH:MM UTC`.
 *
 * Deliberately not `toLocaleString`: these pages are server-rendered and then
 * hydrated, and a locale- or timezone-dependent format produces different text
 * on the server than in the browser, which React reports as a hydration
 * mismatch. A fixed UTC format renders identically everywhere.
 */
export function formatTimestamp(value: string | undefined): string | null {
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  const iso = date.toISOString()
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`
}

/**
 * Shorten an identifier that is too long to read in a table cell — passkey
 * identifiers are base64url credential ids of 40+ characters.
 *
 * Email addresses and E.164 numbers are never shortened however long they are:
 * they are the thing an operator scans the table for, and half an address is
 * no use. Only opaque identifiers get elided.
 */
export function elideIdentifier(identifier: string): string {
  const isHumanReadable = identifier.includes("@") || identifier.startsWith("+")
  if (isHumanReadable || identifier.length <= IDENTIFIER_MAX) return identifier
  return `${identifier.slice(0, IDENTIFIER_HEAD)}…${identifier.slice(-IDENTIFIER_TAIL)}`
}

/**
 * Turn a settings or metadata key into a heading: `maxNoteCount` becomes
 * "Max Note Count", `otp.maxAttempts` becomes "OTP Max Attempts".
 */
export function humanizeKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[\s._-]+/)
    .filter((word) => word.length > 0)
    .map((word) =>
      ACRONYMS.has(word.toLowerCase())
        ? word.toUpperCase()
        : word.charAt(0).toUpperCase() + word.slice(1),
    )
    .join(" ")
}

/**
 * Best-effort text for an arbitrary metadata value. Objects and arrays are
 * JSON-encoded rather than rendered as "[object Object]"; nullish values
 * return null so the caller can show a placeholder instead.
 */
export function formatValue(value: unknown): string | null {
  if (value === null || value === undefined) return null
  if (typeof value === "string") return value
  if (typeof value === "number" || typeof value === "bigint") {
    return String(value)
  }
  if (typeof value === "boolean") return value ? "Yes" : "No"
  if (value instanceof Date) return formatTimestamp(value.toISOString())
  return JSON.stringify(value)
}
