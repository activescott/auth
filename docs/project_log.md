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
