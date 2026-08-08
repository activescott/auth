# Changelog

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [1.0.0](https://github.com/activescott/auth/compare/auth-provider-sms@0.3.0...auth-provider-sms@1.0.0) (2026-08-08)

### ⚠ BREAKING CHANGES

* requires @activescott/auth v4, where AuthProvider.describe()
became a required member.

### Features

* describe() for the admin configuration page ([b7ae3bd](https://github.com/activescott/auth/commit/b7ae3bd30f7957763fab17abf628f9c5d1db1b01))

### Bug Fixes

* require @activescott/auth v4 as a peer ([310906f](https://github.com/activescott/auth/commit/310906fa669773a582de6f4f04d5e1e39c091a24))

## [0.3.0](https://github.com/activescott/auth/compare/auth-provider-sms@0.2.0...auth-provider-sms@0.3.0) (2026-08-07)

### Features

* accept a hosted VerificationTransport ([adb60b2](https://github.com/activescott/auth/commit/adb60b226fbf90fcc19987f9e11023d841155d30))

## [0.2.0](https://github.com/activescott/auth/compare/auth-provider-sms@0.1.3...auth-provider-sms@0.2.0) (2026-08-07)

### Features

* ship CaptureSmsTransport for e2e tests ([4d7fff5](https://github.com/activescott/auth/commit/4d7fff5b36f57495e47ddcf4411ed910fb440d09))

## [0.1.3](https://github.com/activescott/auth/compare/auth-provider-sms@0.1.2...auth-provider-sms@0.1.3) (2026-08-06)

### Bug Fixes

* throttle sends per recipient number ([7e0ce5e](https://github.com/activescott/auth/commit/7e0ce5e556423640026bf30718f4c95d95572397)), closes [#56](https://github.com/activescott/auth/issues/56)

## [0.1.2](https://github.com/activescott/auth/compare/auth-provider-sms@0.1.1...auth-provider-sms@0.1.2) (2026-08-02)

### Bug Fixes

* allow @activescott/auth v3 in peer range ([2891f2e](https://github.com/activescott/auth/commit/2891f2ea25da5f800efe04df2d478fc57f2c661d))
* require @activescott/auth v3 ([5aedd33](https://github.com/activescott/auth/commit/5aedd33614625bf2df8847bf9320a55a8dbe828d))

## [0.1.1](https://github.com/activescott/auth/compare/auth-provider-sms@0.1.0...auth-provider-sms@0.1.1) (2026-08-01)

### Bug Fixes

* link the runnable example from the readme ([3b4d4ff](https://github.com/activescott/auth/commit/3b4d4ffb40df8068e9f9d92b2e73eb9747da2765))

## 0.0.0 (2026-08-01)

### Features

* add vendor-neutral sms one-time-code provider ([6097a80](https://github.com/activescott/auth/commit/6097a805da26dbf5365eda44f5b2b38130d7f8b0))
