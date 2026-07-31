# Changelog

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [1.0.0](https://github.com/activescott/auth/compare/auth-provider-email@0.1.5...auth-provider-email@1.0.0) (2026-07-31)

### ⚠ BREAKING CHANGES

* magicLinkSecret, additionalSecrets, and
magicLinkExpiry are removed from EmailProviderConfig; sign-in emails
need no signing secrets. Link and code share one top-level expiry
(default 15m). The jsonwebtoken dependency is gone. JWT ?token= links
no longer verify. otp.enabled is removed — codes are always included.
For e2e testing, replace additionalSecrets token minting with a
capture transport + gated readback route (see the example app).

### Features

* challenge-backed single-use links with confirm page ([c83eaa5](https://github.com/activescott/auth/commit/c83eaa53bae323551cbc39aa98ec7dd3cf360132))
* default otp codes on when challengeStore configured ([c678637](https://github.com/activescott/auth/commit/c678637bcd147a12668ae0c544c6859881b2cc23))
* optional one-time code alongside magic link ([03c2182](https://github.com/activescott/auth/commit/03c2182110ebddc41541b16277dd3ca16ce3a34d))

## [0.1.5](https://github.com/activescott/auth/compare/auth-provider-email@0.1.4...auth-provider-email@0.1.5) (2026-05-20)

### Bug Fixes

* bump nodemailer and @types/nodemailer to v8 ([c5f48ea](https://github.com/activescott/auth/commit/c5f48ea2c96e24ccc40bcf93ed27a4d155810bd2)), closes [activescott/tinkerbell#66](https://github.com/activescott/tinkerbell/issues/66)

## [0.1.4](https://github.com/activescott/auth/compare/auth-provider-email@0.1.3...auth-provider-email@0.1.4) (2026-05-09)

### Bug Fixes

* add npm version and license badges to README ([82c2870](https://github.com/activescott/auth/commit/82c2870baebe542cdfdbefb917443f632f4de0f7)), closes [#6](https://github.com/activescott/auth/issues/6)

## [0.1.3](https://github.com/activescott/auth/compare/auth-provider-email@0.1.2...auth-provider-email@0.1.3) (2026-05-09)

### Bug Fixes

* add package README so npm page is no longer blank ([e04af71](https://github.com/activescott/auth/commit/e04af719b2dc9dc690f1098df76134c9a4c66b3f))

## 0.1.2 (2026-03-16)

## 0.1.2 (2026-03-16)

## 0.1.2 (2026-03-16)

## 0.1.2 (2026-03-16)

## [0.1.2](https://github.com/activescott/tinkerbell/compare/auth-provider-email@0.1.1...auth-provider-email@0.1.2) (2026-02-24)

### Bug Fixes

* correct magic link expiry text from 15 to 5 minutes ([b2a8fe6](https://github.com/activescott/tinkerbell/commit/b2a8fe6a76ad750e507d27d820ba683b3f9f4b31))

## [0.1.1](https://github.com/activescott/tinkerbell/compare/auth-provider-email@0.1.0...auth-provider-email@0.1.1) (2026-01-30)

### Bug Fixes

* bump the minor-and-patch group across 1 directory with 23 updates ([d7d7fdb](https://github.com/activescott/tinkerbell/commit/d7d7fdbf1e81e84ad6d7238f6fae603e8843c400))

## [0.1.0](https://github.com/activescott/tinkerbell/compare/auth-provider-email@0.1.0...auth-provider-email@0.1.0) (2026-01-24)

## 0.1.0 (2026-01-06)
