import {
  MAX_REDIRECT_URIS,
  inferApplicationType,
  redirectUriProblem,
} from "./redirect-uri.js"
import { sanitizeClientName } from "./client-name.js"
import type { OAuthApplicationType, TokenEndpointAuthMethod } from "./types.js"

const SUPPORTED_GRANT_TYPES = new Set(["authorization_code", "refresh_token"])
const SUPPORTED_RESPONSE_TYPES = new Set(["code"])
const AUTH_METHODS = new Set<string>([
  "none",
  "client_secret_basic",
  "client_secret_post",
])

/** Client metadata after validation, common to DCR and CIMD. */
export interface ValidatedClientMetadata {
  name: string | null
  redirectUris: string[]
  applicationType: OAuthApplicationType
  tokenEndpointAuthMethod: TokenEndpointAuthMethod
  grantTypes: string[]
}

/** An RFC 7591 §3.2.2 error code with its description. */
export interface ClientMetadataError {
  error: "invalid_client_metadata" | "invalid_redirect_uri"
  description: string
}

/**
 * Validate client metadata (RFC 7591 §2) from a registration request or a
 * metadata document. `logo_uri` and every other display field but
 * `client_name` are ignored: the consent page never renders them.
 */
export function validateClientMetadata(
  input: unknown,
  defaultAuthMethod: TokenEndpointAuthMethod,
): ValidatedClientMetadata | ClientMetadataError {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return metadataError("client metadata must be a JSON object")
  }
  const metadata = input as Record<string, unknown>

  const redirectUris = metadata.redirect_uris
  if (
    !Array.isArray(redirectUris) ||
    redirectUris.length === 0 ||
    !redirectUris.every((uri): uri is string => typeof uri === "string")
  ) {
    return {
      error: "invalid_redirect_uri",
      description: "redirect_uris must be a non-empty array of strings",
    }
  }
  if (redirectUris.length > MAX_REDIRECT_URIS) {
    return {
      error: "invalid_redirect_uri",
      description: `at most ${MAX_REDIRECT_URIS} redirect_uris are allowed`,
    }
  }

  let applicationType: OAuthApplicationType
  if (metadata.application_type === undefined) {
    const inferred = inferApplicationType(redirectUris)
    if (!inferred) {
      return {
        error: "invalid_redirect_uri",
        description:
          "redirect_uris mix loopback and non-loopback URIs; send application_type",
      }
    }
    applicationType = inferred
  } else if (
    metadata.application_type === "native" ||
    metadata.application_type === "web"
  ) {
    applicationType = metadata.application_type
  } else {
    return metadataError("application_type must be native or web")
  }

  for (const uri of redirectUris) {
    const problem = redirectUriProblem(uri, applicationType)
    if (problem) return { error: "invalid_redirect_uri", description: problem }
  }

  const authMethod = metadata.token_endpoint_auth_method ?? defaultAuthMethod
  if (typeof authMethod !== "string" || !AUTH_METHODS.has(authMethod)) {
    return metadataError(
      "token_endpoint_auth_method must be none, client_secret_basic or client_secret_post",
    )
  }

  const grantTypes = metadata.grant_types ?? ["authorization_code"]
  if (
    !Array.isArray(grantTypes) ||
    !grantTypes.every(
      (type) => typeof type === "string" && SUPPORTED_GRANT_TYPES.has(type),
    )
  ) {
    return metadataError(
      "grant_types may only contain authorization_code and refresh_token",
    )
  }
  const responseTypes = metadata.response_types ?? ["code"]
  if (
    !Array.isArray(responseTypes) ||
    !responseTypes.every(
      (type) => typeof type === "string" && SUPPORTED_RESPONSE_TYPES.has(type),
    )
  ) {
    return metadataError("response_types may only contain code")
  }

  if (
    metadata.client_name !== undefined &&
    typeof metadata.client_name !== "string"
  ) {
    return metadataError("client_name must be a string")
  }

  return {
    name: sanitizeClientName(metadata.client_name),
    redirectUris,
    applicationType,
    tokenEndpointAuthMethod: authMethod as TokenEndpointAuthMethod,
    grantTypes: grantTypes as string[],
  }
}

export function isClientMetadataError(
  value: ValidatedClientMetadata | ClientMetadataError,
): value is ClientMetadataError {
  return "error" in value
}

function metadataError(description: string): ClientMetadataError {
  return { error: "invalid_client_metadata", description }
}
