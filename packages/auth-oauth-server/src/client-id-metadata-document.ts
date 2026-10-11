import {
  isClientMetadataError,
  validateClientMetadata,
  type ClientMetadataError,
} from "./client-metadata.js"
import { isOwnHost, normalizeHost } from "./own-hosts.js"
import type { OAuthClient } from "./types.js"

const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600
const MS_PER_SECOND = 1000
/** A document is cached for at least this long, so `no-store` cannot force a fetch per authorize. */
export const MIN_METADATA_CACHE_SECONDS = 5 * SECONDS_PER_MINUTE
/** And at most this long, so a huge `max-age` cannot freeze a document's redirect URIs. */
export const MAX_METADATA_CACHE_SECONDS = 24 * SECONDS_PER_HOUR

/** Whether a `client_id` is a URL that names a Client ID Metadata Document. */
export function looksLikeMetadataDocumentUrl(clientId: string): boolean {
  return clientId.startsWith("https://")
}

/**
 * Check a CIMD `client_id` before anything is fetched: the URL rules of the
 * CIMD draft (§3: https, a path, no dot segments, fragment, or userinfo),
 * port 443 only, a DNS name rather than an IP literal, and a host that is
 * not one of the app's own or a subdomain of one. The last rule stops a
 * metadata document hosted on the app itself (say, a user's public file)
 * from borrowing the app's host on the consent page. Returns an error
 * description, or null.
 */
export function metadataDocumentUrlProblem(
  clientId: string,
  ownHosts: ReadonlySet<string>,
): string | null {
  let url: URL
  try {
    url = new URL(clientId)
  } catch {
    return "client_id is not a valid URL"
  }
  if (url.protocol !== "https:") return "client_id must use https"
  if (url.username || url.password) {
    return "client_id must not contain userinfo"
  }
  if (clientId.includes("#")) return "client_id must not contain a fragment"
  if (url.search || clientId.includes("?")) {
    return "client_id must not contain a query"
  }
  if (url.port !== "") return "client_id must use port 443"
  if (url.pathname === "/" || url.pathname === "") {
    return "client_id must contain a path"
  }
  const rawPath = clientId.slice(clientId.indexOf("/", "https://".length))
  if (
    rawPath
      .split("/")
      .some(
        (segment) =>
          segment === "." ||
          segment === ".." ||
          /^(%2e|\.){1,2}$/i.test(segment),
      )
  ) {
    return "client_id must not contain dot path segments"
  }
  const host = normalizeHost(url.hostname)
  if (/^[\d.]+$/.test(host) || host.startsWith("[")) {
    return "client_id must use a DNS name, not an IP address"
  }
  if (isOwnHost(host, ownHosts)) {
    return "client_id must not be hosted on this server"
  }
  if (url.toString() !== clientId) {
    return "client_id must be in normalized form"
  }
  return null
}

/**
 * Validate a fetched metadata document against the URL it came from and turn
 * it into a client row. The document's `client_id` must equal the URL, and
 * it must not carry a secret: a CIMD client is public.
 */
export function clientFromMetadataDocument(
  clientId: string,
  document: unknown,
  maxAgeSeconds: number | null,
  now: Date,
  ownHosts: ReadonlySet<string>,
): OAuthClient | ClientMetadataError {
  if (typeof document !== "object" || document === null) {
    return {
      error: "invalid_client_metadata",
      description: "metadata document must be a JSON object",
    }
  }
  const fields = document as Record<string, unknown>
  if (fields.client_id !== clientId) {
    return {
      error: "invalid_client_metadata",
      description: "metadata document client_id does not match its URL",
    }
  }
  if ("client_secret" in fields || "client_secret_expires_at" in fields) {
    return {
      error: "invalid_client_metadata",
      description: "metadata document must not contain a client secret",
    }
  }
  const metadata = validateClientMetadata(document, "none", ownHosts)
  if (isClientMetadataError(metadata)) return metadata
  if (metadata.tokenEndpointAuthMethod !== "none") {
    return {
      error: "invalid_client_metadata",
      description:
        "metadata document clients must use token_endpoint_auth_method none",
    }
  }
  return {
    clientId,
    kind: "cimd",
    applicationType: metadata.applicationType,
    name: metadata.name,
    redirectUris: metadata.redirectUris,
    tokenEndpointAuthMethod: "none",
    clientSecretHash: null,
    createdAt: now,
    metadataFetchedAt: now,
    metadataExpiresAt: new Date(
      now.getTime() + clampCacheSeconds(maxAgeSeconds) * MS_PER_SECOND,
    ),
  }
}

/** Clamp a document's HTTP cache lifetime to between 5 minutes and 24 hours. */
export function clampCacheSeconds(maxAgeSeconds: number | null): number {
  if (maxAgeSeconds === null || !Number.isFinite(maxAgeSeconds)) {
    return MIN_METADATA_CACHE_SECONDS
  }
  return Math.min(
    MAX_METADATA_CACHE_SECONDS,
    Math.max(MIN_METADATA_CACHE_SECONDS, Math.floor(maxAgeSeconds)),
  )
}
