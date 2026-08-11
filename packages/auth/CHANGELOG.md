# Changelog

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [4.1.0](https://github.com/activescott/auth/compare/auth@4.0.0...auth@4.1.0) (2026-08-11)

### Features

* identity linking and account merge ([b60adb1](https://github.com/activescott/auth/commit/b60adb132d453d8bf6c8005a22df72f6636e9262)), closes [#70](https://github.com/activescott/auth/issues/70)
* merge-review hardening and onIdentityLinked hook ([840a9d9](https://github.com/activescott/auth/commit/840a9d96fdee5781d77db1a4209df584e658f7c6)), closes [#70](https://github.com/activescott/auth/issues/70)

## [4.0.0](https://github.com/activescott/auth/compare/auth@3.1.0...auth@4.0.0) (2026-08-08)

### ⚠ BREAKING CHANGES

* AuthProvider.describe() is now required. It reports a
provider's non-secret settings for the configuration page. Only a provider
knows which of its own settings are secret, so redaction is its job rather
than the dashboard's -- omit API keys, passwords, tokens, and signing
secrets rather than masking them. A provider with nothing to show returns
{ settings: {} }, so the migration is one method.

### Features

* opaque filter criteria on ListUsersOptions ([2d95e2d](https://github.com/activescott/auth/commit/2d95e2df4cf33996b8372e68d163e4717aa319ca))
* user listing and config introspection for the admin dashboard ([5aeb443](https://github.com/activescott/auth/commit/5aeb443ab20563eebbdf8872d8c69660bfa2cf5c)), closes [#58](https://github.com/activescott/auth/issues/58)

## [3.1.0](https://github.com/activescott/auth/compare/auth@3.0.1...auth@3.1.0) (2026-08-06)

### Features

* abuse protection on the initiate endpoints ([534c67f](https://github.com/activescott/auth/commit/534c67f5ee03f7fd254ae57516974313f8f5c5fd)), closes [#56](https://github.com/activescott/auth/issues/56)

## [3.0.1](https://github.com/activescott/auth/compare/auth@3.0.0...auth@3.0.1) (2026-08-02)

### Bug Fixes

* rewrite readme with project intro, features, and current v3 facts ([863b91f](https://github.com/activescott/auth/commit/863b91f92da0be242e8d59910f73c1b76c012ad1))

## [3.0.0](https://github.com/activescott/auth/compare/auth@2.1.0...auth@3.0.0) (2026-08-02)

### ⚠ BREAKING CHANGES

* Identity.metadata and the metadata argument of
IdentityStore.create are required, and IdentityStore.update is a
required method.

### Features

* add provider handleAction and context getSession ([4269a6c](https://github.com/activescott/auth/commit/4269a6cc90d8a875a21dda886ec079da6952432b))
* require Identity.metadata and IdentityStore.update ([b5c3c7b](https://github.com/activescott/auth/commit/b5c3c7b70c8c35c6d8841a19a35926705f1403a8))

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
