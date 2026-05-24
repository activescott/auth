---
name: project-oauth-focus
description: This repo is a fork of activescott/auth; our specific contribution goal is implementing OAuth providers (Google, GitHub, etc.)
metadata:
  type: project
---

The purpose of this local fork of `activescott/auth` is to implement **OAuth providers** (Google, GitHub, and others) as contributions back to the upstream repository at <https://github.com/activescott/auth>.

**Why:** The upstream README lists "OAuth providers — planned, not yet implemented" and the `AuthProvider` interface was designed as the extension point for exactly this.

**How to apply:** New OAuth work should live in new packages (e.g. `packages/auth-provider-google` or a shared `packages/auth-provider-oauth`). Changes to the core `packages/auth` package should be minimal. When suggesting work, prioritize OAuth provider implementation over other improvements.
