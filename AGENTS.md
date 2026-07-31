# AGENTS.md

This file provides guidance to LLM coding agents (e.g. Claude Code, claude.ai/code) when working with code in this repository.

## Commands

npm workspaces monorepo. From the repo root:

```bash
npm install
npm run build        # tsc build in every workspace
npm run typecheck    # tsc --noEmit in every workspace
npm test             # vitest run in every workspace
npm run lint         # prettier --check .
```

Scope to one package with `-w`:

```bash
npm test -w packages/auth
npm test -w packages/auth -- src/__tests__/auth.test.ts   # single test file
npm test -w packages/auth -- -t "test name pattern"        # single test by name
```

E2e tests (Playwright, drives the example app; requires the three packages built first):

```bash
npm run build --workspace=@activescott/auth --workspace=@activescott/auth-provider-email --workspace=@activescott/auth-adapter-react-router
npm run install-browsers -w examples/react-router/tests   # once
npm run e2e -w examples/react-router/tests
```

## Architecture

Read [README.md](./README.md) first — it documents the package layout, the app → adapter → core → provider layering (with diagram), the `IdentityStore`/`UserStore` contracts, the `Identity` data model, how to implement a custom `AuthProvider`, and the recommended e2e testing pattern (`additionalSecrets` + minting magic-link JWTs directly).

Source map for what lives where (not in the README):

- `packages/auth/src/auth.ts` — `Auth` class: dispatches standard `Request`s to providers, verifies sessions.
- `packages/auth/src/session/session-manager.ts` — `SessionManager`: issues/verifies JWT cookie sessions.
- `packages/auth/src/types.ts` — the contracts: `AuthProvider`, `IdentityStore`, `UserStore`, `AuthUser`, `Identity`, `Session`.
- `packages/auth/src/errors.ts` — `AuthErrors`.
- `packages/auth-provider-email/src/email-provider.ts` — email magic link provider; `src/transports/` holds the `EmailTransport` implementations (Nodemailer SMTP).
- `packages/auth-adapter-react-router/src/handlers.ts` — `createAuthHandlers` and friends.
- `examples/react-router/` — runnable example app; its Playwright e2e suite is the nested workspace `examples/react-router/tests`.

Everything speaks Fetch-API `Request`/`Response` (no Node-only APIs in the core path) so packages run on Node and edge runtimes — preserve that when changing core or providers.

## Commits and releases

Commit format drives automated per-package releases — full rules, bump table, and rationale are in the README's [Release process](./README.md#release-process) section. The parts an agent must not get wrong:

- Conventional Commits with a **required scope**, restricted to: `auth`, `auth-provider-email`, `auth-adapter-react-router`, or `examples`. Enforced by a husky commitlint hook.
- The scope determines which package gets version-bumped and published. A change spanning multiple packages needs separate commits per scope — preferred workflow is one PR per package. Never squash-merge a multi-package PR.
- No manual release command; merging to `main` releases automatically.
