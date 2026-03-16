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
} from "./types.js"

// Auth class
export { Auth } from "./auth.js"

// Session management
export { SessionManager } from "./session/index.js"

// Errors
export {
  AUTH_ERROR_CODES,
  AUTH_ERROR_MESSAGES,
  getAuthErrorMessage,
  AuthenticationError,
  AuthErrors,
  createAuthError,
} from "./errors.js"
