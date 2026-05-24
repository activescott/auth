# Code Standards

This document outlines the coding standards and best practices for this project.

Related documents:

- [ARCHITECTURE.md](./ARCHITECTURE.md) - Project structure and architectural patterns
- [SECURITY.md](./SECURITY.md) - Security guidelines and dependency management
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Development workflow and contribution process

## Guiding Principles

- DRY (Don't Repeat Yourself) - Every piece of knowledge should have a single, unambiguous, authoritative representation. Refactor repeated logic into reusable components.
- Iterate progressively - Start with core features only. Gather feedback.
- No secrets in Git - NEVER put unencrypted secrets in Git or other CMS systems.
- GitHub CLI - Primary method for interacting with GitHub.
- Think first - Present options before implementing. On larger objectives, present a phased plan.
- Markdown style - Use bullet points, not numbered lists for content (section headers like `## Step 1` are fine). No bold text as a heading or pseudo-heading — see Markdownlint MD036 below.

## Language & Environment

- Language: English (US) for all code and documentation
- Runtime: Node.js v22+ with TypeScript
- Module system: ESM (`"type": "module"`, NodeNext resolution)
- Target: ES2022

## TypeScript Configuration

We use strict TypeScript settings (`strict: true`) with NodeNext module resolution. Key requirements:

- Strict null checks enabled
- No implicit `any` types
- `verbatimModuleSyntax` enabled — always use `import type` for type-only imports
- All imports must use `.js` extensions (even for `.ts` source files)
- No unused variables or parameters

See each package's `tsconfig.json` for the full configuration.

## Code Formatting

### Prettier

Automatic code formatting using Prettier ensures consistency across the codebase.

Key settings (`.prettierrc.json`):

- Single quotes for strings
- Semicolons required
- 2-space indentation
- 100-character line width
- Trailing commas disabled
- Unix line endings (LF)

Run formatting:

```bash
npm run format
```

### EditorConfig

EditorConfig settings (`.editorconfig`) ensure consistent editor behavior across different tools and IDEs.

## Linting

### ESLint

We use ESLint 9 (flat config) with TypeScript support to catch code quality issues.

Configuration: `eslint.config.mjs`

Key rules:

- Prefer `const` over `let` and `var`
- Unused variables must be prefixed with `_`
- `console` calls trigger warnings (use proper logging instead)
- Single quotes required
- Semicolons required
- No floating promises — always `await` async operations
- Proper async/await usage

Run linting:

```bash
npm run lint          # Runs both code and markdown linting
npm run lint:code     # ESLint only
```

Auto-fix fixable issues:

```bash
npm run lint:fix      # Fixes both code and markdown
npm run lint:code:fix # ESLint only
```

### Markdownlint

We use Markdownlint to ensure consistent and well-formatted documentation.

Configuration: `.markdownlint.json`

Key rules:

- Consistent heading style
- 2-space indentation for lists
- Line length limits (900 chars general, 80 for headings)
- Blank lines around lists and code blocks
- No bold text as headings (MD036) — use proper heading syntax (`##`, `###`, etc.) instead of `**Bold:**`

Run markdown linting:

```bash
npm run lint:md       # Check all markdown files
npm run lint:md:fix   # Auto-fix markdown issues (note: MD036 requires manual fix)
```

#### Heading vs Bold Text

```markdown
<!-- Bad - bold text used as heading -->
**Update Requirements:**
- Item 1
- Item 2

<!-- Good - proper heading -->
### Update Requirements

- Item 1
- Item 2
```

## Naming Conventions

- Files: Use kebab-case for file names (e.g., `email-provider.ts`, `session-manager.ts`)
- Classes: Use PascalCase (e.g., `EmailProvider`, `SessionManager`)
- Functions/Variables: Use camelCase (e.g., `verifySession`, `createSessionCookie`)
- Constants: Use UPPER_SNAKE_CASE (e.g., `SECONDS_PER_MINUTE`, `DEFAULT_CACHE_TTL_MINUTES`)
- Private members: Prefix with underscore (e.g., `_internalState`) or use TypeScript `private`

## Code Organization

### Function Length

- Keep functions focused and single-purpose
- Prefer functions under 50 lines
- Extract complex logic into separate functions

### Comments

- Avoid obvious comments
- Explain *why*, not *what* — the code shows what it does
- Use JSDoc for public APIs

## Error Handling

- Always handle promise rejections
- Use typed errors from `AuthErrors` factory when possible
- Provide meaningful error messages
- Log errors via `console.error` at provider boundaries only

## Testing

We use [Vitest](https://vitest.dev/) as the test runner.

- Write tests for all public functions
- Place test files in `src/__tests__/` alongside source: `foo.ts` → `__tests__/foo.test.ts`
- Use `describe()` for groups, `it()` for specs
- Test behavior, not implementation details

```bash
npm run test                         # Run all tests
npm run test --workspace=@activescott/auth  # Run tests in one package
npx vitest run packages/auth/src/__tests__/auth.test.ts  # Single file
```

## Git Commit Messages

Follow conventional commits format with the required scopes for this monorepo:

```text
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

Valid scopes: `auth`, `auth-provider-email`, `auth-provider-oauth`, `auth-adapter-react-router`, `examples`

Example:

```text
feat(auth-provider-email): add DKIM signing support

Adds optional DKIM signing via nodemailer's built-in support.
Configured through the smtp config block.

Closes #42
```

## Pre-commit Hooks

Husky + lint-staged runs linting on **changed files only** before each commit. Commits with linting errors will be rejected.

The pre-commit hook runs via lint-staged:

- ESLint + Prettier on staged `.ts` files
- Markdownlint on staged `.md` files

## Package Standards

Keep dependencies minimal, well-maintained, and secure.

For complete dependency security guidance, see [SECURITY.md](./SECURITY.md#dependency-management).

Quick checklist:

- Regularly audit: `npm audit`
- Document why each dependency is needed
- Use exact versions for critical dependencies
- Update promptly when security issues are found

## Environment Variables

- Store sensitive data in `.env` files (never commit)
- Document required environment variables in `.env.example`
- Use meaningful variable names: `JWT_SECRET`, `FROM_EMAIL`

## Review Checklist

Before submitting code for review:

- [ ] Code passes linting (`npm run lint` — includes both code and markdown)
- [ ] Code is formatted (`npm run format`)
- [ ] Tests pass and coverage is adequate
- [ ] TypeScript compiles without errors (`npm run typecheck`)
- [ ] Markdown files pass linting (included in `npm run lint`)
- [ ] No `console.log` statements in production code
- [ ] Commit message follows [conventions](#git-commit-messages)
- [ ] [AGENTS.md](./AGENTS.md) updated if applicable
- [ ] No hardcoded secrets or credentials
