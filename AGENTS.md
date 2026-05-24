---
project_state: "active"
last_updated: "2026-05-24"
agent_priority_level: "medium"
blockers: []
requires_human_review: ["major architectural changes", "security policy modifications", "breaking API changes", "publishing to npm"]
agent_autonomy_level: "high"
---

# Project Context for AI Agents

This file serves as the single source of truth for project context and state. All agents should read this and update it when working on this project.

## Agent Context Protocol

### Machine-Readable Metadata

See YAML frontmatter above for current project state.

### Update Requirements

- Update `last_updated` field whenever making significant changes to this file
- Update `project_state` to reflect current status: "template", "active", "maintenance", "archived"
- Update `blockers` array with any current blockers preventing progress
- Update `agent_priority_level` based on urgency: "low", "medium", "high", "critical"

## CRITICAL

### Core Documentation (Single Source of Truth)

- [README.md](./README.md) - Project overview, install instructions, and quick start
- [CODE_STANDARDS.md](./CODE_STANDARDS.md) - Guiding principles, naming, formatting, linting, testing, commits
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Package structure, data model, request flow, technology stack
- [SECURITY.md](./SECURITY.md) - Secret management, dependency security, authentication, encryption
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Development workflow, branching strategy, pull request process
- [docs/project_log.md](docs/project_log.md) - Historical record of work done, next steps, session tracking

### Auxiliary Documentation

- [.github/workflows/ci.yaml](.github/workflows/ci.yaml) - CI/CD pipelines and release automation

## Context Overview

- Project Name: `@activescott/auth`
- Upstream: <https://github.com/activescott/auth>
- Description: A framework-agnostic TypeScript authentication library with a provider pattern. Supports email magic links (live in production), with OAuth and SMS planned. Used in production by ramblefeed.com and tinkerbellbot.com.

## Contribution Goal

**Our specific contribution to this upstream project is implementing OAuth providers** (Google, GitHub, and others). The `AuthProvider` interface in `@activescott/auth` is the extension point — new providers don't require changes to core. See `packages/auth-provider-email/src/email-provider.ts` as the reference implementation.

OAuth work should land in a new package, e.g. `packages/auth-provider-oauth`, or as individual packages per provider (`packages/auth-provider-google`, etc.). Discuss the packaging approach before starting implementation.

## Key Decisions

- **NodeNext module resolution** — all imports must use `.js` extensions even for `.ts` source files
- **`verbatimModuleSyntax`** — always use `import type` for type-only imports
- **Three-package monorepo** — core (`@activescott/auth`), email provider, and React Router adapter are separate published packages with independent semver
- **Standard `Request`/`Response`** — no framework-specific types in core or providers; only the adapter layer touches framework APIs
- **JWT-in-HttpOnly-cookie sessions** — sessions are self-contained JWTs; no session store needed

## Architecture & Tech Stack

See [ARCHITECTURE.md](./ARCHITECTURE.md) for package structure, data model, request flow, and technology stack.

## Coding Standards

See [CODE_STANDARDS.md](./CODE_STANDARDS.md) for naming conventions, formatting, linting, testing, and commit message format.

## Behavioral Principles

These four principles reduce common LLM coding mistakes. They bias toward caution over speed; for trivial tasks, use judgment.

### 1. Think Before Coding

Don't assume. Don't hide confusion. Surface tradeoffs.

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop, name what's confusing, ask.

This applies to ambiguous scope, not every step — `agent_autonomy_level: high` still holds for clearly-defined work.

### 2. Simplicity First

Minimum code that solves the problem. Nothing speculative.

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ship the smallest coherent slice. Ask before bundling adjacent work into the current change.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

Touch only what you must. Clean up only your own mess.

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that your changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

Define success criteria. Loop until verified.

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan with a verify-step per item.

## Project Constraints

### Technical Constraints

- Node.js v22+ required
- TypeScript strict mode must remain enabled
- NodeNext module resolution — `.js` extensions required on all imports
- `verbatimModuleSyntax` enabled — use `import type` for all type-only imports
- All code must pass linting and tests before commit
- No unencrypted secrets in Git (per CODE_STANDARDS.md)
- Each package must have a clean `dist/` build before publishing

### Process Constraints

- All work must be done in feature branches
- Pull requests required for main branch
- Update `docs/project_log.md` after each session
- Update this file's `last_updated` timestamp when making significant changes
- Breaking changes require a major version bump per semver

### Agent-Specific Guidelines

- Always read this file before starting work
- Check `blockers` array before proceeding
- Respect the priority matrix below
- When uncertain, ask for human guidance
- Document all assumptions and decisions

### Agent Behavior Rules

- **Eagerness** — Do not jump into implementation unless clearly instructed. When intent is ambiguous, default to research and recommendations rather than action.
- **No speculation** — Never speculate about code you have not opened. Read relevant files BEFORE answering questions.
- **Parallel tool calls** — If calling multiple tools with no dependencies between them, make all independent calls in parallel.

## Commands

```bash
# Build
npm run build                       # Build all packages
npm run build --workspace=@activescott/auth  # Build one package

# Testing
npm run test                        # Run all unit tests
npm run test --workspace=@activescott/auth   # Test one package
npx vitest run packages/auth/src/__tests__/auth.test.ts  # Single file

# Code Quality
npm run lint                        # ESLint + markdownlint
npm run lint:fix                    # Auto-fix lint issues
npm run format                      # Format with Prettier
npm run typecheck                   # TypeScript type checking

# E2e (build packages first, then)
npm run e2e --workspace=@activescott/auth-example-react-router-e2e
```

## Key Standards (Quick Reference)

- TypeScript strict mode — no implicit any, strict null checks
- Prettier — single quotes, semicolons, 2-space indent, 100-char width, no trailing commas
- ESLint — prefer const, unused vars prefixed with `_`, no floating promises
- Commits — conventional format: `type(scope): description`
  - Valid scopes: `auth`, `auth-provider-email`, `auth-provider-oauth`, `auth-adapter-react-router`, `examples`
- Branches — format: `type/description` (e.g., `feature/sms-provider`, `fix/session-expiry`)

## Agent Priority Matrix

### Agents CAN Work Autonomously On

- Bug fixes for non-critical issues
- Documentation updates and corrections
- Writing tests for existing functionality
- Adding features explicitly described in project_log.md
- Code quality improvements (linting, formatting, type safety)
- Dependency updates (patch and minor versions)
- OAuth provider implementation work (new `AuthProvider` implementations — they don't touch core)

### Agents MUST Request Human Review For

- Major architectural changes or new patterns
- Security changes (session handling, token verification, secret management)
- Breaking API changes (types exported from packages)
- Publishing packages to npm
- Major dependency updates (major versions)
- Changes to CI/CD pipelines
- New third-party services or integrations

## Session Workflow

- Read this file (AGENTS.md)
- Check `docs/project_log.md` for recent work
- Work on tasks following CODE_STANDARDS.md
- Update `docs/project_log.md` with session log entry
- Update this file's `last_updated` field if making significant changes

## GitHub Workflow

See [CONTRIBUTING.md](./CONTRIBUTING.md) for branching strategy, commit guidelines, pull request process, and testing requirements.

Important: Keep this file synchronized and updated. This is the bridge between different agents working on the same project.
