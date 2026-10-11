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
 * `Claude Desktop` and `C1aude` match, `Claudette` does not. Lookalikes are
 * folded to a skeleton in the spirit of UTS #39: accents are dropped, Greek
 * and Cyrillic letters that look Latin become Latin, and `1`, `i`, `|`, `0`,
 * `rn` and `vv` become `l`, `l`, `l`, `o`, `m` and `w`.
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

function skeleton(value: string): string {
  const folded = Array.from(
    value.normalize("NFKD").replace(/\p{M}/gu, ""),
    (char) => LATIN_LOOKALIKES.get(char) ?? char,
  ).join("")
  return folded
    .toLowerCase()
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/[1i|]/g, "l")
    .replace(/0/g, "o")
}

/**
 * Greek and Cyrillic letters, and a few Latin ones, that render like a
 * Latin letter. Mapped before lowercasing, since `Η` looks like `H` while
 * its lowercase `η` looks like `n`.
 */
const LATIN_LOOKALIKES: ReadonlyMap<string, string> = new Map(
  [
    // Cyrillic
    ["АВСЕНІЈКМОРЅТХУҮԌԚԜӀ", "ABCEHIJKMOPSTXYYGQWl"],
    ["асекорхуѕіјԁһӏԛԝү", "acekopxysijdhlqwy"],
    // Greek
    ["ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ", "ABEZHIKMNOPTYX"],
    ["αικνορυχγ", "aikvopuxy"],
    // Latin
    ["ıɑɡ", "iag"],
  ].flatMap(([from, to]) =>
    Array.from(from!, (char, index): [string, string] => [char, to![index]!]),
  ),
)

/**
 * Scripts a name may combine with Latin, following the UTS #39 "highly
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
  ["Hebrew", /\p{Script=Hebrew}/u],
  ["Arabic", /\p{Script=Arabic}/u],
  ["Han", /\p{Script=Han}/u],
  ["Hiragana", /\p{Script=Hiragana}/u],
  ["Katakana", /\p{Script=Katakana}/u],
  ["Hangul", /\p{Script=Hangul}/u],
  ["Bopomofo", /\p{Script=Bopomofo}/u],
]

/**
 * Whether a name's letters come from scripts that do not belong together,
 * such as `Сlaude` with a Cyrillic `С`. Digits, punctuation and combining
 * marks belong to every script and are ignored.
 */
export function isMixedScriptName(name: string): boolean {
  const scripts = new Set<string>()
  for (const char of name) {
    if (
      !/\p{L}/u.test(char) ||
      /[\p{Script=Common}\p{Script=Inherited}]/u.test(char)
    ) {
      continue
    }
    scripts.add(
      SCRIPTS.find(([, pattern]) => pattern.test(char))?.[0] ?? "Other",
    )
  }
  if (scripts.size <= 1) return false
  return !ALLOWED_SCRIPT_SETS.some((allowed) =>
    [...scripts].every((script) => allowed.has(script)),
  )
}
