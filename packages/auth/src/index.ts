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
export { generateOtpCode, hashOtpCode, verifyOtpCode } from "./otp.js"
export { InMemoryChallengeStore } from "./stores/in-memory-challenge-store.js"

// Errors
export {
  AUTH_ERROR_CODES,
  AUTH_ERROR_MESSAGES,
  getAuthErrorMessage,
  AuthenticationError,
  AuthErrors,
  createAuthError,
} from "./errors.js"
