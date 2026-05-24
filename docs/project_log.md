# Project Log

Historical record of work done across sessions. Most recent entries first.

Format per entry:

```text
### yyyy-MM-dd-##

- Agent: [Claude/Gemini/Other]
- Subject: [Brief description of the session's work]
- Current Issue: [GitHub issue number if applicable, or "none"]
- Work Done:
  - [task 1]
  - [task 2]
- Commits: [commit hash(es) from this session]
- Files Modified:
  - [list each modified file]
```

## Log Entries

### 2026-05-24-07

- Agent: Claude
- Subject: MicrosoftProvider (Azure AD / Entra ID OIDC) (issue #25)
- Current Issue: #25
- Work Done:
  - New `MicrosoftProvider` class extending `OAuthProvider`; default tenant is `common`
    (accepts personal MSA + work/school AAD accounts); custom tenant supported via config
  - New `MicrosoftProviderConfig` interface extending `OAuthProviderConfig` with optional `tenant`
  - Both exported from `@activescott/auth-provider-oauth`
  - Overrides `validateIdToken` for multi-tenant (`common`/`organizations`/`consumers`): skips
    jose's exact issuer check (the discovery doc returns `{tenantid}` template) and validates
    `iss` against `^https://login\.microsoftonline\.com/[^/]+/v2\.0$` instead; specific-tenant
    config delegates to base class (strict OIDC issuer check)
  - Defaults `emailVerified=true` when Microsoft omits the `email_verified` claim so
    `linkByVerifiedEmail` works correctly
  - 16 new tests in `microsoft-provider.test.ts`
  - Opened issue #25 and PR #26
- Commits: 465389c
- Files Modified:
  - packages/auth-provider-oauth/src/providers/microsoft.ts (new)
  - packages/auth-provider-oauth/src/__tests__/microsoft-provider.test.ts (new)
  - packages/auth-provider-oauth/src/index.ts

### 2026-05-24-06

- Agent: Claude
- Subject: Provider enabled/disabled flag and isProviderEnabled() helper (issue #20)
- Current Issue: #20
- Work Done:
  - Added optional `enabled?` to `AuthProvider` interface in `@activescott/auth`
  - `Auth.handleRequest` returns 404 for disabled provider paths
  - `Auth.findProvider` skips disabled providers
  - New `Auth.getEnabledProviders(): { id, name }[]` for login UI
  - New `packages/auth/src/config.ts` with `isProviderEnabled(id, defaultValue?)`
    reading `AUTH_<ID>_ENABLED` env var; exported from core
  - Added `enabled?` to `OAuthProviderConfig` and `EmailProviderConfig`; both
    provider base classes set `public readonly enabled` from config
  - Example app uses `isProviderEnabled()` for Google/GitHub; `login.tsx` uses
    `getEnabledProviders()` for button rendering
  - `.env.example` documents `AUTH_*_ENABLED` toggle vars
  - 19 new tests in `packages/auth/src/__tests__/provider-enabled.test.ts`
  - Opened PR #24
- Commits: 45866d2
- Files Modified:
  - packages/auth/src/types.ts
  - packages/auth/src/auth.ts
  - packages/auth/src/config.ts (new)
  - packages/auth/src/index.ts
  - packages/auth/src/__tests__/provider-enabled.test.ts (new)
  - packages/auth-provider-oauth/src/types.ts
  - packages/auth-provider-oauth/src/base/oauth-provider.ts
  - packages/auth-provider-email/src/types.ts
  - packages/auth-provider-email/src/email-provider.ts
  - examples/react-router/app/lib/auth.server.ts
  - examples/react-router/app/routes/login.tsx
  - examples/react-router/.env.example

### 2026-05-24-05

- Agent: Claude
- Subject: Email-based OAuth account linking via IdentityStore.findByEmail (issue #14)
- Current Issue: #14
- Work Done:
  - Added optional `findByEmail?(email: string): Promise<Identity | null>` to `IdentityStore`
    in `packages/auth/src/types.ts`
  - Updated `OAuthProvider.findOrCreateUser` to call `findByEmail` instead of
    `findByProviderAndIdentifier('email', ...)` when `linkByVerifiedEmail: true`
  - `AuthenticationError('CONFIGURATION_ERROR', ...)` thrown when `findByEmail` missing
    and `linkByVerifiedEmail: true`; `verify` catch block updated to preserve
    `AuthenticationError` error codes (not override with `PROVIDER_ERROR`)
  - Added `findByEmail` implementation to example app's in-memory `identityStore`
  - Updated existing linking test; added 3 new tests (linking match, no match, unverified
    email, missing findByEmail → CONFIGURATION_ERROR); 88 tests total
  - Opened PR #23
- Commits: 06dad33
- Files Modified:
  - packages/auth/src/types.ts
  - packages/auth-provider-oauth/src/base/oauth-provider.ts
  - packages/auth-provider-oauth/src/__tests__/oauth-provider.test.ts
  - examples/react-router/app/lib/auth.server.ts

### 2026-05-24-04

- Agent: Claude
- Subject: Wire OAuth providers into the React Router example app (issue #15)
- Current Issue: #15
- Work Done:
  - Added `@activescott/auth-provider-oauth` dependency to `examples/react-router/package.json`
  - Updated `auth.server.ts`: imports `GoogleProvider` + `GitHubProvider`; registers them
    conditionally on env vars (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`,
    `GITHUB_CLIENT_SECRET`, `OAUTH_STATE_SECRET`); updated `userStore.create` to accept and use
    passed `metadata` (fallback to `{ email: identifier }` for email provider backward compat)
  - Added `createTestSession` helper to `auth.server.ts` (disabled in production) for e2e use
  - Updated `login.tsx` to show Google/GitHub sign-in buttons when providers are registered
  - Updated `dashboard.tsx` to use `getSession` (returns user + identity) and display provider name
  - Added test-only route `app/routes/auth.test-login.ts` at `GET /auth/test-login`
  - Added `loginAsOAuth` helper to `tests/helpers/auth.ts`
  - Added 3 new Playwright e2e tests in `oauth` describe block
  - Created `examples/react-router/.env.example`
  - Updated `examples/react-router/README.md` with OAuth setup instructions and test pattern docs
  - Opened PR #22
- Commits: 8f6036b
- Files Modified:
  - examples/react-router/package.json
  - examples/react-router/app/lib/auth.server.ts
  - examples/react-router/app/routes/dashboard.tsx
  - examples/react-router/app/routes/login.tsx
  - examples/react-router/app/routes/auth.test-login.ts (new)
  - examples/react-router/.env.example (new)
  - examples/react-router/tests/auth.spec.ts
  - examples/react-router/tests/helpers/auth.ts
  - examples/react-router/README.md

### 2026-05-24-03

- Agent: Claude
- Subject: Implement abstract OAuthProvider base class with OIDC discovery (issue #11)
- Current Issue: #11
- Work Done:
  - Created `packages/auth-provider-oauth/src/base/oauth-provider.ts` — abstract `OAuthProvider`
    class with full OAuth 2.0/OIDC flow (initiate redirect, verify callback, PKCE, discovery cache)
  - Added `jose` ^5.9.6 dependency for JWKS-based id_token validation
  - `validateIdToken()` helper uses `createRemoteJWKSet` + `jwtVerify` from jose
  - `normalizeOIDCClaims()` maps standard OIDC claims to `OAuthProfile`
  - `findOrCreateUser()` with optional `linkByVerifiedEmail` account linking
  - Fixed `readStateCookie` validation: `!payload.codeVerifier` rejected empty strings, breaking
    non-PKCE providers that store `codeVerifier: ''`; changed to `payload.codeVerifier == null`
  - Updated `src/index.ts` to export `OAuthProvider` and `OIDCDiscoveryDocument`
  - Created `src/__tests__/oauth-provider.test.ts` with 30 tests covering all paths
  - Opened PR #18: `feat(auth-provider-oauth): abstract OAuthProvider base class with OIDC discovery`
- Commits: b7175dd
- Files Modified:
  - packages/auth-provider-oauth/src/base/oauth-provider.ts (new)
  - packages/auth-provider-oauth/src/__tests__/oauth-provider.test.ts (new)
  - packages/auth-provider-oauth/src/base/state-cookie.ts (fix: allow empty codeVerifier)
  - packages/auth-provider-oauth/src/index.ts (export OAuthProvider + OIDCDiscoveryDocument)
  - packages/auth-provider-oauth/package.json (add jose dependency)
  - package-lock.json

### 2026-05-24-01

- Agent: Claude
- Subject: Apply mjs-project-template tooling and standards
- Current Issue: none
- Work Done:
  - Created CLAUDE.md (redirects to AGENTS.md)
  - Created AGENTS.md with project-specific context and agent behavior rules
  - Created CODE_STANDARDS.md, ARCHITECTURE.md, CONTRIBUTING.md, SECURITY.md
  - Added .markdownlint.json, .editorconfig, .nvmrc (Node 22)
  - Replaced .prettierrc with .prettierrc.json (semi: true, singleQuote, 100-char width)
  - Added eslint.config.mjs with TypeScript-checked rules
  - Updated root package.json: added ESLint/markdownlint deps, lint scripts, lint-staged config
  - Added .husky/pre-commit hook (lint-staged)
  - Added .github/PULL_REQUEST_TEMPLATE.md and ISSUE_TEMPLATE/{bug_report,feature_request}.md
  - Added .claude/commands/ (context, check-todos, update-agents, session-commit, semver, sync-template)
  - Added .claude/README.md and .claude/mcp.json
  - Updated .gitignore and .prettierignore
  - Reformatted all source files to match new Prettier config (semi: true)
- Commits: TBD
- Files Modified:
  - CLAUDE.md, AGENTS.md, CODE_STANDARDS.md, ARCHITECTURE.md, CONTRIBUTING.md, SECURITY.md
  - .markdownlint.json, .editorconfig, .nvmrc, .prettierrc.json, .prettierignore, .gitignore
  - eslint.config.mjs, package.json
  - .husky/pre-commit
  - .github/PULL_REQUEST_TEMPLATE.md
  - .github/ISSUE_TEMPLATE/bug_report.md, feature_request.md
  - .claude/README.md, .claude/mcp.json
  - .claude/commands/{context,check-todos,update-agents,session-commit,semver,sync-template}.md
  - packages/auth/src/*.ts, packages/auth/src/session/*.ts
  - packages/auth-provider-email/src/*.ts, packages/auth-provider-email/src/transports/*.ts
  - packages/auth-adapter-react-router/src/*.ts
