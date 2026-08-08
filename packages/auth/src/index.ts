// Core types
export type {
  AuthUser,
  Identity,
  Session,
  AuthResult,
  AuthSuccess,
  AuthFailure,
  AuthInitResult,
  AuthError,
  AuthErrorCode,
  IdentityStore,
  UserStore,
  ListUsersOptions,
  ListUsersResult,
  SessionConfig,
  AuthConfig,
  AuthContext,
  ProviderRoute,
  AuthProvider,
  ProviderDescription,
  SessionConfigDescription,
  ProviderConfigDescription,
  StoresDescription,
  AuthConfigDescription,
  Challenge,
  ChallengeStore,
} from "./types.js"
export { REDACTED } from "./types.js"

// Auth class
export { Auth } from "./auth.js"

// Session management
export { SessionManager } from "./session/index.js"

// OTP utilities and challenge storage
export {
  generateOtpCode,
  hashOtpCode,
  verifyOtpCode,
  verifyOtpChallenge,
  constantTimeEqual,
} from "./otp.js"
export type { OtpVerifyFailure, OtpChallengeResult } from "./otp.js"
export { InMemoryChallengeStore } from "./stores/in-memory-challenge-store.js"

// Abuse protection
export type {
  AbuseConfig,
  AbuseContext,
  AbuseDecision,
  AbuseDescription,
  AbuseEvent,
  AbuseReason,
} from "./abuse/abuse-guard.js"
export { AbuseGuard } from "./abuse/abuse-guard.js"
export type { RateLimitRule, RateLimitVerdict } from "./abuse/rate-limiter.js"
export { RateLimiter } from "./abuse/rate-limiter.js"
export type { RateLimitHit, RateLimitStore } from "./abuse/rate-limit-store.js"
export { InMemoryRateLimitStore } from "./stores/in-memory-rate-limit-store.js"
export type { ClientIpOptions } from "./abuse/client-ip.js"
export { getClientIp } from "./abuse/client-ip.js"
export type {
  BotCheckInput,
  BotCheckProvider,
  BotCheckResult,
  FormTokenFailure,
  FormTokenResult,
} from "./abuse/bot-check.js"
export {
  createFormToken,
  verifyFormToken,
  FormTokenBotCheck,
  DEFAULT_MIN_FORM_FILL_SECONDS,
  FORM_TOKEN_FIELD,
} from "./abuse/bot-check.js"

// Utilities for provider authors
export {
  parseRequestBody,
  isBrowserFormPost,
  buildReturnUrl,
  buildChallengeCookie,
  buildChallengeClearingCookie,
  readCookie,
  parseDuration,
  authenticateWithIdentifier,
  initiateAccepted,
} from "./provider-util.js"

// Errors
export {
  AUTH_ERROR_CODES,
  AUTH_ERROR_MESSAGES,
  getAuthErrorMessage,
  AuthenticationError,
  AuthErrors,
  createAuthError,
} from "./errors.js"
