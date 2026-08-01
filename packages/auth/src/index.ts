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
  SessionConfig,
  AuthConfig,
  AuthContext,
  ProviderRoute,
  AuthProvider,
  Challenge,
  ChallengeStore,
} from "./types.js"

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
