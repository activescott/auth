/** Longest client name kept, in code points. */
export const MAX_CLIENT_NAME_LENGTH = 64

/**
 * Make a self-asserted `client_name` safe to show on the consent page: drop
 * control and format characters (which include the bidi overrides and
 * zero-width characters used to disguise a name), collapse whitespace, and
 * cap the length. Returns null when nothing is left.
 */
export function sanitizeClientName(name: unknown): string | null {
  if (typeof name !== "string") return null
  const cleaned = name
    .normalize("NFKC")
    .replace(/[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/gu, "")
    .replace(/\s+/gu, " ")
    .trim()
  const capped = Array.from(cleaned).slice(0, MAX_CLIENT_NAME_LENGTH).join("")
  return capped.length > 0 ? capped : null
}

/**
 * Whether a sanitized name contains one of the reserved names as a whole
 * word, ignoring case: with `["Claude"]`, both `claude` and `Claude Desktop`
 * match, `Claudette` does not.
 */
export function isReservedClientName(
  name: string,
  reservedNames: readonly string[],
): boolean {
  const words = ` ${toWords(name)} `
  return reservedNames.some((reserved) => {
    const reservedWords = toWords(reserved)
    return reservedWords.length > 0 && words.includes(` ${reservedWords} `)
  })
}

function toWords(value: string): string {
  return value
    .normalize("NFKC")
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean)
    .join(" ")
}
