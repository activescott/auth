# Security Guidelines

This document outlines security best practices for this project. **Core rule: NEVER put unencrypted secrets in Git** (see [CODE_STANDARDS.md](./CODE_STANDARDS.md#guiding-principles)).

## Table of Contents

- [Secret Management](#secret-management)
- [Dependency Management](#dependency-management)
- [Authentication & Session Security](#authentication--session-security)
- [Code Security](#code-security)
- [Security Incident Response](#security-incident-response)

## Secret Management

### Never Commit Secrets

Never commit passwords, API keys, tokens, or other secrets to version control.

### What Counts as a Secret

- `JWT_SECRET` — session signing key
- `JWT_MAGIC_LINK_SECRET` — magic link signing key
- SMTP credentials (`SMTP_USER`, `SMTP_PASS`)
- OAuth client secrets (future)
- Any private encryption keys

### How to Handle Secrets

#### Local Development

Copy `.env.example` to `.env` and fill in your local values. Never commit `.env`.

#### Production Deployment

Use GitHub repository secrets (Settings → Secrets and variables → Actions). Reference in workflows:

```yaml
env:
  JWT_SECRET: ${{ secrets.JWT_SECRET }}
```

### Secret Rotation

- Rotate secrets regularly (at least quarterly)
- Immediately rotate compromised secrets
- When rotating `JWT_SECRET` or `JWT_MAGIC_LINK_SECRET`, use `additionalSecrets` in `SessionConfig` / `EmailProviderConfig` to accept old tokens during the transition window, then remove the old secret after its TTL expires

## Dependency Management

Keep dependencies minimal, well-maintained, and secure.

- Regularly audit: `npm audit`
- Document why each dependency is needed
- Update promptly when security issues are found
- Prefer packages with small dependency trees for a library that others depend on

## Authentication & Session Security

This library is specifically an authentication library — security is the primary concern.

### JWT Sessions

- Sessions are signed JWTs stored in `HttpOnly`, `SameSite=Lax` cookies
- `Secure` flag must be `true` in production
- `maxAge` should be as short as practical (default: 30 days)
- JWTs are verified on every request; the 2-minute in-memory cache reduces DB load without weakening security

### Magic Link Tokens

- Magic link tokens are short-lived JWTs (default: 5 minutes)
- The `magicLinkSecret` must be different from the session `secret`
- Tokens are single-use by design — once `verifiedAt` is set, re-use doesn't create a new session without a new token
- Never log or expose magic link URLs

### Identity Model

- Identities are `(provider, identifier)` pairs — the email address is the identifier, not a password
- New users are created automatically on first successful magic link verification
- The `verifiedAt` timestamp is updated on each successful verification

### Adding New Providers

Any new `AuthProvider` implementation must:

- Never log sensitive request fields (tokens, emails in some contexts)
- Validate all input at the boundary
- Use short-lived tokens with appropriate secrets
- Handle token verification errors without leaking information (same error message for invalid vs. expired)

## Code Security

- Validate all inputs at system boundaries (request bodies, query params)
- Use `zod` schemas for configuration validation (see `packages/auth-provider-email/src/config.ts`)
- Never expose internal error details to HTTP responses — map to `AuthError` with generic messages
- Avoid timing attacks: use constant-time comparison for secrets where applicable

## Security Incident Response

If you discover a security vulnerability:

1. Do NOT open a public GitHub issue
2. Email the maintainer directly (see package.json `author`)
3. Include: description, reproduction steps, potential impact
4. Allow reasonable time for a fix before public disclosure

If you accidentally commit a secret:

1. Immediately rotate the secret (change the key/password)
2. Remove the secret from Git history (`git filter-repo` or GitHub support)
3. Force-push the cleaned branch
4. Audit access logs for potential misuse
