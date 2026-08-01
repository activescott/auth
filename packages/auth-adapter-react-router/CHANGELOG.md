# Changelog

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [1.0.2](https://github.com/activescott/auth/compare/auth-adapter-react-router@1.0.1...auth-adapter-react-router@1.0.2) (2026-08-01)

### Bug Fixes

* allow react-router 8 as a peer ([6d02b81](https://github.com/activescott/auth/commit/6d02b81b05f9919df9ac43e11a0a5087b4f73121)), closes [#43](https://github.com/activescott/auth/issues/43)

## [1.0.1](https://github.com/activescott/auth/compare/auth-adapter-react-router@1.0.0...auth-adapter-react-router@1.0.1) (2026-08-01)

### Bug Fixes

* correct auth peer dependency range ([8df3496](https://github.com/activescott/auth/commit/8df3496371bbcffbe763000e4018873037edfa83))

## [1.0.0](https://github.com/activescott/auth/compare/auth-adapter-react-router@0.1.3...auth-adapter-react-router@1.0.0) (2026-07-31)

### ⚠ BREAKING CHANGES

* sendMagicLink, SendMagicLinkResult, and
SendMagicLinkOptions are removed. Login forms post directly to
/auth/email/initiate; the provider redirects back with ?sent=1/?error=
and sets the challenge cookie itself, so login pages need no action.

### Features

* pass through provider pages, drop sendMagicLink ([d4bad63](https://github.com/activescott/auth/commit/d4bad639aba09a8e238261e1efdd55de6edb4047))
* propagate provider Set-Cookie values ([c92f851](https://github.com/activescott/auth/commit/c92f851d8cc3320a27614af0402f4c5ef2ea14e6))

## [0.1.3](https://github.com/activescott/auth/compare/auth-adapter-react-router@0.1.2...auth-adapter-react-router@0.1.3) (2026-05-09)

### Bug Fixes

* add npm version and license badges to README ([623c5b1](https://github.com/activescott/auth/commit/623c5b1073343908e7d2e3d403704f1641435fcf)), closes [#6](https://github.com/activescott/auth/issues/6)

## [0.1.2](https://github.com/activescott/auth/compare/auth-adapter-react-router@0.1.1...auth-adapter-react-router@0.1.2) (2026-05-09)

### Bug Fixes

* add package README so npm page is no longer blank ([8e218f1](https://github.com/activescott/auth/commit/8e218f129db772eedd4aa80bf16ddfa4016672cf))

## 0.1.1 (2026-03-16)

## 0.1.1 (2026-03-16)

## 0.1.1 (2026-03-16)

## 0.1.1 (2026-03-16)

## [0.1.1](https://github.com/activescott/tinkerbell/compare/auth-adapter-react-router@0.1.0...auth-adapter-react-router@0.1.1) (2026-01-30)

### Bug Fixes

* bump the minor-and-patch group across 1 directory with 23 updates ([d7d7fdb](https://github.com/activescott/tinkerbell/commit/d7d7fdbf1e81e84ad6d7238f6fae603e8843c400))

## [0.1.0](https://github.com/activescott/tinkerbell/compare/auth-adapter-react-router@0.1.0...auth-adapter-react-router@0.1.0) (2026-01-24)

## 0.1.0 (2026-01-06)
