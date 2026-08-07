# Changelog

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [1.0.0](https://github.com/activescott/auth/compare/auth-sms-twilio@0.1.1...auth-sms-twilio@1.0.0) (2026-08-07)

### ⚠ BREAKING CHANGES

* TwilioTransport is now TwilioMessagingTransport and
TwilioTransportConfig is now TwilioMessagingTransportConfig. No alias is
left behind; update the import and the constructor call.

### Features

* add a Twilio Verify transport ([ebc53a5](https://github.com/activescott/auth/commit/ebc53a5b370d75ad451e9076d3a725fdff8a16cc))
* rename TwilioTransport to TwilioMessagingTransport ([23b907c](https://github.com/activescott/auth/commit/23b907cb0b1effa96e165e9552ae6a0dbc33505a))

### Bug Fixes

* correct the Verify log URL ([556b6b4](https://github.com/activescott/auth/commit/556b6b41fe2da645a141397f1c2c70bc8a68ffb1))
* log why a Verify check was not approved ([3a238cd](https://github.com/activescott/auth/commit/3a238cdfa9b9f6748a285604d0026ca6fd603851))
* use the singular VerificationCheck endpoint ([b624ecf](https://github.com/activescott/auth/commit/b624ecfc5a2610da3a22fbd1c7cb66489d1a7293))

## [0.1.1](https://github.com/activescott/auth/compare/auth-sms-twilio@0.1.0...auth-sms-twilio@0.1.1) (2026-08-01)

### Bug Fixes

* correct the setup script description in the readme ([463330a](https://github.com/activescott/auth/commit/463330a78b0348b1004ca29b83c03828ecda8cdb))

## 0.0.0 (2026-08-01)

### Features

* add twilio transport ([ea4b025](https://github.com/activescott/auth/commit/ea4b025a3ff7bf2e04b8da2cfaec5a2453f58bc6))
