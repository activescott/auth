/**
 * Check PasskeyProviderConfig.expectedOrigin against the relying party ID
 * at construction, so a typo fails at boot instead of rejecting every
 * ceremony. Each http(s) entry must be a bare origin (no path or trailing
 * slash, which would never equal a browser's origin) whose hostname is the
 * RP ID or a subdomain of it, since browsers only run a ceremony for an RP
 * ID on those hosts. Other entries, such as an Android app's
 * "android:apk-key-hash:...", pass through unchecked.
 *
 * A list needs a fixed RP ID (rpID or appUrl): otherwise the RP ID is each
 * request's hostname, and one RP ID shared by several origins is the point
 * of the list.
 */
export function checkExpectedOrigin(
  expectedOrigin: string | string[],
  rpID: string | undefined,
): void {
  const origins =
    typeof expectedOrigin === "string" ? [expectedOrigin] : expectedOrigin
  if (Array.isArray(expectedOrigin)) {
    if (origins.length === 0) {
      throw new TypeError("PasskeyProvider expectedOrigin list is empty")
    }
    if (rpID === undefined) {
      throw new TypeError(
        "PasskeyProvider expectedOrigin is a list, so set rpID or appUrl too",
      )
    }
  }
  for (const origin of origins) checkOrigin(origin, rpID)
}

function checkOrigin(origin: string, rpID: string | undefined): void {
  let url: URL
  try {
    url = new URL(origin)
  } catch {
    throw new TypeError(
      `PasskeyProvider expectedOrigin is not a valid origin: ${JSON.stringify(origin)}`,
    )
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return
  if (url.origin !== origin) {
    throw new TypeError(
      `PasskeyProvider expectedOrigin must be an origin like ${JSON.stringify(url.origin)}, not ${JSON.stringify(origin)}`,
    )
  }
  if (rpID === undefined) return
  const rp = rpID.toLowerCase()
  if (url.hostname !== rp && !url.hostname.endsWith(`.${rp}`)) {
    throw new TypeError(
      `PasskeyProvider expectedOrigin ${JSON.stringify(origin)} is not on rpID ${JSON.stringify(rpID)} or a subdomain of it`,
    )
  }
}
