# Changelog

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [1.0.0](https://github.com/activescott/auth/compare/auth-provider-passkey@0.1.0...auth-provider-passkey@1.0.0) (2026-08-08)

### ⚠ BREAKING CHANGES

* requires @activescott/auth v4, where AuthProvider.describe()
became a required member.

### Features

* describe() for the admin configuration page ([f17306c](https://github.com/activescott/auth/commit/f17306cb3641dd9a783f578cc68d24a1788e82a9))

### Bug Fixes

* require @activescott/auth v4 as a peer ([d2105bb](https://github.com/activescott/auth/commit/d2105bba03796c56de000a0041097f3ef97ba2c6))

## 0.1.0 (2026-08-02)

### Features

* add passkey (webauthn) provider package ([f6755cd](https://github.com/activescott/auth/commit/f6755cdaaa62fd5456ae423e4d3d16219434c6fd))
* make challenges single-use via the core challenge store ([27adf84](https://github.com/activescott/auth/commit/27adf84df3c89045fd2e550666d0a589258ba08b))
* store credentials in identity metadata ([c6757d8](https://github.com/activescott/auth/commit/c6757d8529c95871fae13c244fa40b5cd3367bf7))
