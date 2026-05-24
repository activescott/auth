# Claude MCP Commands

This directory contains Model Context Protocol (MCP) configuration and custom commands for Claude integration with this project.

## Available Commands

### `/context`

Reads AGENTS.md to get current project state: overview, status, architecture, blockers, and priorities. Use at the start of each session.

### `/check-todos`

Displays actionable work items from AGENTS.md organized by priority level.

### `/update-agents`

Reminds you to update AGENTS.md with your session's progress, decisions, and next steps.

### `/session-commit`

Commits current work, appends a structured entry to `docs/project_log.md`, and optionally comments on related GitHub issues.

### `/semver`

Cuts a new semver release for one of the monorepo packages: bumps version, creates an annotated tag, pushes, and creates a GitHub release.

### `/sync-template`

Syncs config files from `jwilleke/mjs-project-template` into this repo via cherry-pick, merge, or file copy.

## Typical Workflow

- Start session: `/context` to read project state
- Check priorities: `/check-todos` to pick what to work on
- End session: `/session-commit` to commit work and update the log

## See Also

- [AGENTS.md](../AGENTS.md) — single source of truth for project context
- [CODE_STANDARDS.md](../CODE_STANDARDS.md) — coding guidelines
- [CONTRIBUTING.md](../CONTRIBUTING.md) — contribution workflow
