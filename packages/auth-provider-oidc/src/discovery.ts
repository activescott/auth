import type { OidcDiscoveryDocument } from "./types.js"
import { OidcError } from "./oidc-error.js"

/** Hosts allowed to serve discovery and endpoints over plain http (local IdPs in development) */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"])

/**
 * The discovery URL for an issuer: `{issuer}/.well-known/openid-configuration`
 * (OpenID Connect Discovery 1.0, section 4).
 */
export function discoveryUrlFor(issuer: string): string {
  return `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`
}

/**
 * Fetch and check an OpenID Provider's discovery document. The document's
 * `issuer` must equal the configured issuer exactly (Discovery 4.3), and the
 * endpoints this package calls must be https, so a tampered or misconfigured
 * document cannot point token exchange somewhere else.
 *
 * @throws OidcError with reason "discovery"
 */
export async function fetchDiscoveryDocument(
  issuer: string,
  url: string,
  fetchImpl: typeof fetch,
): Promise<OidcDiscoveryDocument> {
  const response = await fetchImpl(url, {
    headers: { Accept: "application/json" },
  })
  if (!response.ok) {
    throw new OidcError(
      "discovery",
      `Discovery document request failed with HTTP ${response.status}`,
    )
  }

  const document = (await response.json()) as Partial<OidcDiscoveryDocument>
  if (document.issuer !== issuer) {
    throw new OidcError(
      "discovery",
      `Discovery document issuer ${String(document.issuer)} does not match ${issuer}`,
    )
  }
  for (const field of [
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
  ] as const) {
    const value = document[field]
    if (typeof value !== "string" || !isSecureUrl(value)) {
      throw new OidcError(
        "discovery",
        `Discovery document ${field} is missing or not https`,
      )
    }
  }
  if (
    document.code_challenge_methods_supported &&
    !document.code_challenge_methods_supported.includes("S256")
  ) {
    throw new OidcError("discovery", "Provider does not support PKCE S256")
  }

  return document as OidcDiscoveryDocument
}

function isSecureUrl(value: string): boolean {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return false
  }
  return (
    url.protocol === "https:" ||
    (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))
  )
}
