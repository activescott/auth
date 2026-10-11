import { CONFUSABLES } from "./confusables-data.js"

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
 * word, ignoring case and lookalike characters: with `["Claude"]`, `claude`,
 * `Claude Desktop`, `C1aude` and `ᴄʟᴀᴜᴅᴇ` match, `Claudette` does not.
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
  return skeleton(value)
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean)
    .join(" ")
}

/**
 * The UTS #39 skeleton, made case insensitive: map each character through
 * confusables.txt, drop accents, lowercase, and repeat until nothing
 * changes, since lowercasing can produce a letter with its own mapping.
 * `i` and `w` are then folded to `l` and `vv`, which confusables.txt keeps
 * apart.
 */
function skeleton(value: string): string {
  let current = value
  for (let pass = 0; pass < 4; pass++) {
    const next = Array.from(
      current.normalize("NFKD"),
      (char) => CONFUSABLE_MAP.get(char) ?? char,
    )
      .join("")
      .normalize("NFKD")
      .replace(/\p{M}/gu, "")
      .toLowerCase()
    if (next === current) break
    current = next
  }
  return current.replace(/i/g, "l").replace(/w/g, "vv")
}

const CONFUSABLE_MAP: ReadonlyMap<string, string> = new Map(
  CONFUSABLES.flatMap((line) => line.split(" ")).map((entry) => {
    const [from, to] = entry.split(">") as [string, string]
    return [
      String.fromCodePoint(parseInt(from, 16)),
      String.fromCodePoint(...to.split("+").map((hex) => parseInt(hex, 16))),
    ]
  }),
)

/**
 * Scripts a word may combine with Latin, following the UTS #39 "highly
 * restrictive" profile: Japanese, Chinese and Korean writing mix with Latin
 * routinely, while Latin with Cyrillic or Greek is how a lookalike is built.
 */
const ALLOWED_SCRIPT_SETS: ReadonlyArray<ReadonlySet<string>> = [
  new Set(["Latin", "Han", "Hiragana", "Katakana"]),
  new Set(["Latin", "Han", "Bopomofo"]),
  new Set(["Latin", "Han", "Hangul"]),
]

const SCRIPTS: ReadonlyArray<readonly [string, RegExp]> = [
  ["Latin", /\p{Script=Latin}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Armenian", /\p{Script=Armenian}/u],
  ["Georgian", /\p{Script=Georgian}/u],
  ["Cherokee", /\p{Script=Cherokee}/u],
  ["Lisu", /\p{Script=Lisu}/u],
  ["Hebrew", /\p{Script=Hebrew}/u],
  ["Arabic", /\p{Script=Arabic}/u],
  ["Han", /\p{Script=Han}/u],
  ["Hiragana", /\p{Script=Hiragana}/u],
  ["Katakana", /\p{Script=Katakana}/u],
  ["Hangul", /\p{Script=Hangul}/u],
  ["Bopomofo", /\p{Script=Bopomofo}/u],
]

function scriptOf(char: string): string | null {
  if (
    !/\p{L}/u.test(char) ||
    /[\p{Script=Common}\p{Script=Inherited}]/u.test(char)
  ) {
    return null
  }
  return SCRIPTS.find(([, pattern]) => pattern.test(char))?.[0] ?? "Other"
}

/**
 * Whether a word of the name borrows a lookalike letter from another script
 * in that word, such as `Сlaude` with a Cyrillic `С`. Words are checked one
 * at a time, so `Google Диск` passes, and a word mixing scripts passes when
 * none of its letters imitates another script in it, as in `μTorrent`.
 * Digits, punctuation and combining marks belong to every script.
 */
export function isMixedScriptName(name: string): boolean {
  return name.split(/\s+/u).some((word) => {
    const letters = Array.from(word).flatMap((char) => {
      const script = scriptOf(char)
      return script ? [{ char, script }] : []
    })
    const scripts = new Set(letters.map(({ script }) => script))
    if (scripts.size <= 1) return false
    if (
      ALLOWED_SCRIPT_SETS.some((allowed) =>
        [...scripts].every((script) => allowed.has(script)),
      )
    ) {
      return false
    }
    return letters.some(({ char, script }) =>
      Array.from(CONFUSABLE_MAP.get(char) ?? "").some((target) => {
        const targetScript = scriptOf(target)
        return (
          targetScript !== null &&
          targetScript !== script &&
          scripts.has(targetScript)
        )
      }),
    )
  })
}
