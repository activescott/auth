import type { AuthError, AuthErrorCode } from "./types.js"

/**
 * Auth error codes as constants for type-safe comparisons.
 * Use these instead of magic strings when checking error codes.
 *
 * @example
 * ```typescript
 * import { AUTH_ERROR_CODES } from "@activescott/auth"
 *
 * if (error.code === AUTH_ERROR_CODES.INVALID_TOKEN) {
 *   // handle invalid token
 * }
 * ```
 */
export const AUTH_ERROR_CODES = {
  INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
  EXPIRED_TOKEN: "EXPIRED_TOKEN",
  INVALID_TOKEN: "INVALID_TOKEN",
  MISSING_TOKEN: "MISSING_TOKEN",
  USER_NOT_FOUND: "USER_NOT_FOUND",
  IDENTITY_NOT_FOUND: "IDENTITY_NOT_FOUND",
  PROVIDER_ERROR: "PROVIDER_ERROR",
  CONFIGURATION_ERROR: "CONFIGURATION_ERROR",
  RATE_LIMITED: "RATE_LIMITED",
  SESSION_EXPIRED: "SESSION_EXPIRED",
  SESSION_INVALID: "SESSION_INVALID",
} as const satisfies Record<AuthErrorCode, AuthErrorCode>

/**
 * Default user-friendly error messages for each auth error code.
 * Applications can use these directly or customize as needed.
 *
 * @example
 * ```typescript
 * import { AUTH_ERROR_CODES, AUTH_ERROR_MESSAGES } from "@activescott/auth"
 *
 * const errorCode = searchParams.get("error")
 * const message = AUTH_ERROR_MESSAGES[errorCode] ?? "An error occurred"
 * ```
 */
export const AUTH_ERROR_MESSAGES: Record<AuthErrorCode, string> = {
  INVALID_CREDENTIALS: "Invalid credentials. Please try again.",
  EXPIRED_TOKEN: "Your link has expired. Please request a new one.",
  INVALID_TOKEN: "Invalid or expired link. Please try again.",
  MISSING_TOKEN: "Missing authentication token. Please try again.",
  USER_NOT_FOUND: "User not found.",
  IDENTITY_NOT_FOUND: "Identity not found.",
  PROVIDER_ERROR: "Authentication provider error. Please try again.",
  CONFIGURATION_ERROR: "Authentication is not configured correctly.",
  RATE_LIMITED: "Too many attempts. Please wait and try again.",
  SESSION_EXPIRED: "Your session has expired. Please sign in again.",
  SESSION_INVALID: "Invalid session. Please sign in again.",
}

const DEFAULT_ERROR_MESSAGE =
  "An authentication error occurred. Please try again."

/**
 * Get a user-friendly error message for an auth error code.
 * Returns a default message if the code is not recognized.
 *
 * @param code - The error code string (may come from URL params, etc.)
 * @param defaultMessage - Optional custom default message for unrecognized codes
 * @returns The user-friendly error message
 *
 * @example
 * ```typescript
 * import { getAuthErrorMessage } from "@activescott/auth"
 *
 * const errorCode = searchParams.get("error")
 * const message = errorCode ? getAuthErrorMessage(errorCode) : null
 * ```
 */
export function getAuthErrorMessage(
  code: string,
  defaultMessage: string = DEFAULT_ERROR_MESSAGE,
): string {
  if (code in AUTH_ERROR_MESSAGES) {
    return AUTH_ERROR_MESSAGES[code as AuthErrorCode]
  }
  return defaultMessage
}

/**
 * Create an AuthError object
 */
export function createAuthError(
  code: AuthErrorCode,
  message: string,
  details?: Record<string, unknown>,
): AuthError {
  return { code, message, details }
}

/**
 * AuthError class for throwing errors
 */
export class AuthenticationError extends Error {
  public readonly code: AuthErrorCode
  public readonly details?: Record<string, unknown>

  public constructor(
    code: AuthErrorCode,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message)
    this.name = "AuthenticationError"
    this.code = code
    this.details = details
  }

  public toAuthError(): AuthError {
    return {
      code: this.code,
      message: this.message,
      details: this.details,
    }
  }
}

/**
 * Pre-defined error factories for common errors
 */
export const AuthErrors = {
  invalidToken: (details?: Record<string, unknown>) =>
    createAuthError("INVALID_TOKEN", "Invalid or malformed token", details),

  expiredToken: (details?: Record<string, unknown>) =>
    createAuthError("EXPIRED_TOKEN", "Token has expired", details),

  missingToken: (details?: Record<string, unknown>) =>
    createAuthError("MISSING_TOKEN", "Token is missing", details),

  invalidCredentials: (details?: Record<string, unknown>) =>
    createAuthError(
      "INVALID_CREDENTIALS",
      "Invalid credentials provided",
      details,
    ),

  userNotFound: (details?: Record<string, unknown>) =>
    createAuthError("USER_NOT_FOUND", "User not found", details),

  identityNotFound: (details?: Record<string, unknown>) =>
    createAuthError("IDENTITY_NOT_FOUND", "Identity not found", details),

  providerError: (message: string, details?: Record<string, unknown>) =>
    createAuthError("PROVIDER_ERROR", message, details),

  configurationError: (message: string, details?: Record<string, unknown>) =>
    createAuthError("CONFIGURATION_ERROR", message, details),

  rateLimited: (details?: Record<string, unknown>) =>
    createAuthError(
      "RATE_LIMITED",
      "Too many requests, please try again later",
      details,
    ),

  sessionExpired: (details?: Record<string, unknown>) =>
    createAuthError("SESSION_EXPIRED", "Session has expired", details),

  sessionInvalid: (details?: Record<string, unknown>) =>
    createAuthError("SESSION_INVALID", "Session is invalid", details),
} as const
