# Changelog

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [2.1.0](https://github.com/activescott/auth/compare/auth@2.0.0...auth@2.1.0) (2026-08-01)

### Features

* add verifyOtpChallenge and shared provider utilities ([8bf3dfe](https://github.com/activescott/auth/commit/8bf3dfe7e38e9609a602c8874313576da36e1783))

## [2.0.0](https://github.com/activescott/auth/compare/auth@1.0.0...auth@2.0.0) (2026-07-31)

### ⚠ BREAKING CHANGES

* SessionManager.verifyToken is now async and returns
Promise<Session | null>. All other public APIs (Auth.verifySession,
SessionManager.getSession, adapter helpers) were already async and are
unchanged.

### Features

* replace jsonwebtoken with jose for wintertc-compatible sessions ([3c4f66d](https://github.com/activescott/auth/commit/3c4f66d7d9045f1dc289c8234fbb6fe92e448133)), closes [#33](https://github.com/activescott/auth/issues/33)

## [1.0.0](https://github.com/activescott/auth/compare/auth@0.1.3...auth@1.0.0) (2026-07-31)

### ⚠ BREAKING CHANGES

* AuthConfig.challengeStore and AuthContext.challengeStore
are now required. Short-lived verification state (magic links, OTP codes,
future WebAuthn challenges) is stored server-side; apps provide a
ChallengeStore (InMemoryChallengeStore for single-instance deployments).
* AuthProvider.verify may now return a Response in
addition to AuthResult. This lets providers answer non-final steps
directly — e.g., rendering a confirm page on magic-link GET so email
security scanners that prefetch URLs cannot consume single-use links;
redemption happens on the subsequent POST.

### Features

* add ChallengeStore, OTP utilities, and provider Set-Cookie support ([ce8c5e2](https://github.com/activescott/auth/commit/ce8c5e2a0b50887a6497a542b9745b36920b6da0))
* require challengeStore and allow verify to return a Response ([1eeffff](https://github.com/activescott/auth/commit/1eeffff12e0dcbf55e2cf9f35fab978b810a2769))

## [0.1.3](https://github.com/activescott/auth/compare/auth@0.1.2...auth@0.1.3) (2026-05-09)

### Bug Fixes

* add npm version and license badges to README ([e0175df](https://github.com/activescott/auth/commit/e0175dfd3face870edf7196b6897240f0bd697a2)), closes [#6](https://github.com/activescott/auth/issues/6)

## [0.1.2](https://github.com/activescott/auth/compare/auth@0.1.1...auth@0.1.2) (2026-05-09)

### Bug Fixes

* add package README so npm page is no longer blank ([ff7c04d](https://github.com/activescott/auth/commit/ff7c04dd74117d4349652c656a8c4f7fc972e5c4))

## 0.1.1 (2026-03-16)

### Features

* add CI release workflow to publish packages to NPM ([82b9850](https://github.com/activescott/auth/commit/82b9850702efb7c418154e776e4679a52b34e593))
* initial extraction from tinkerbell monorepo ([665e5a3](https://github.com/activescott/auth/commit/665e5a3d3cf11cc484a66b083df158f52dc0fd95))

## 0.1.1 (2026-03-16)

### Features

* add CI release workflow to publish packages to NPM ([82b9850](https://github.com/activescott/auth/commit/82b9850702efb7c418154e776e4679a52b34e593))
* initial extraction from tinkerbell monorepo ([665e5a3](https://github.com/activescott/auth/commit/665e5a3d3cf11cc484a66b083df158f52dc0fd95))

## 0.1.1 (2026-03-16)

### Features

* add CI release workflow to publish packages to NPM ([82b9850](https://github.com/activescott/auth/commit/82b9850702efb7c418154e776e4679a52b34e593))
* initial extraction from tinkerbell monorepo ([665e5a3](https://github.com/activescott/auth/commit/665e5a3d3cf11cc484a66b083df158f52dc0fd95))

## 0.1.1 (2026-03-16)

### Features

* add CI release workflow to publish packages to NPM ([82b9850](https://github.com/activescott/auth/commit/82b9850702efb7c418154e776e4679a52b34e593))
* initial extraction from tinkerbell monorepo ([665e5a3](https://github.com/activescott/auth/commit/665e5a3d3cf11cc484a66b083df158f52dc0fd95))

## [0.1.1](https://github.com/activescott/tinkerbell/compare/auth@0.1.0...auth@0.1.1) (2026-01-30)

### Bug Fixes

* bump the minor-and-patch group across 1 directory with 23 updates ([d7d7fdb](https://github.com/activescott/tinkerbell/commit/d7d7fdbf1e81e84ad6d7238f6fae603e8843c400))

## [0.1.0](https://github.com/activescott/tinkerbell/compare/auth@0.1.0...auth@0.1.0) (2026-01-24)

## 0.1.0 (2026-01-06)
