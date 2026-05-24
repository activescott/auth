# Contributing

Thank you for your interest in contributing to this project! This document provides guidelines for developers and AI agents working on this codebase.

## Contribution Scope

This local fork of `activescott/auth` exists to implement **OAuth providers** (Google, GitHub, etc.) as contributions to the upstream repository. New providers implement the `AuthProvider` interface and live in new packages — no changes to the core `@activescott/auth` package are required.

## Before You Start

- Read [AGENTS.md](./AGENTS.md) for project context and status
- Review [CODE_STANDARDS.md](./CODE_STANDARDS.md) for coding guidelines and guiding principles
- Check [SECURITY.md](./SECURITY.md) for security practices
- See [ARCHITECTURE.md](./ARCHITECTURE.md) for project structure

## Table of Contents

- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Making Changes](#making-changes)
- [Commit Guidelines](#commit-guidelines)
- [Pull Requests](#pull-requests)
- [Code Review Process](#code-review-process)

## Getting Started

```bash
git clone https://github.com/activescott/auth.git
cd auth
npm install
npm run build   # build all packages (required before running e2e tests)
npm run test    # verify everything works
```

## Development Workflow

### Read Project Context First

Before starting work, read `AGENTS.md` to understand:

- Project goals and current status
- Architecture and tech stack
- Known blockers or issues
- Priority tasks

Use the slash command:

```bash
/context
```

### Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
git checkout -b fix/bug-description
```

Branch naming: `type/description` (e.g., `feature/sms-provider`, `fix/session-expiry`)

## Making Changes

### Linting and Formatting

```bash
npm run lint        # Check for issues (ESLint + markdownlint)
npm run lint:fix    # Auto-fix issues
npm run format      # Format with Prettier
```

### Testing

```bash
npm run test              # Run unit tests (all packages)
npm run test --workspace=@activescott/auth  # Single package

# E2e tests — requires packages to be built first
npm run build --workspace=@activescott/auth --workspace=@activescott/auth-provider-email --workspace=@activescott/auth-adapter-react-router
npm run e2e --workspace=@activescott/auth-example-react-router-e2e
```

### Working on an OAuth Provider

Our primary contribution goal is implementing OAuth providers. New providers implement the `AuthProvider` interface from `@activescott/auth` — no changes to core are needed.

Reference implementation: `packages/auth-provider-email/src/email-provider.ts`

Key methods to implement:

- `initiate(request, context)` — redirect to the OAuth authorization URL
- `verify(request, context)` — exchange the code for tokens, look up or create the user/identity
- `canHandle(request)` — return true for `/auth/<provider>/*` paths
- `getRoutes()` — declare the provider's route paths

## Commit Guidelines

All commit messages must follow conventional commits format with the required scopes:

```text
type(scope): description
```

Valid scopes: `auth`, `auth-provider-email`, `auth-adapter-react-router`, `examples`

See [CODE_STANDARDS.md — Git Commit Messages](./CODE_STANDARDS.md#git-commit-messages) for full details and examples.

Pre-commit hooks enforce linting on staged files via lint-staged.

## Pull Requests

### Before Creating a PR

1. Update branch: `git fetch origin && git rebase origin/main`
2. Run checks: `npm run lint && npm run typecheck && npm run test && npm run build`
3. Update [AGENTS.md](./AGENTS.md) if making significant changes

### PR Checklist

- [ ] Code follows [CODE_STANDARDS.md](./CODE_STANDARDS.md)
- [ ] Tests pass (`npm run test`)
- [ ] Linting passes (`npm run lint`)
- [ ] TypeScript compiles (`npm run typecheck`)
- [ ] No hardcoded secrets
- [ ] Commit messages follow conventional format with valid scope
- [ ] [AGENTS.md](./AGENTS.md) updated if applicable

## Code Review Process

- Be respectful and constructive
- Review promptly
- All CI checks must pass before merging (validate + e2e)

## Questions?

- Check [AGENTS.md](./AGENTS.md) for project context
- Read [CODE_STANDARDS.md](./CODE_STANDARDS.md) for guidelines
- Open an issue for questions
