export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "scope-enum": [
      2,
      "always",
      [
        "auth",
        "auth-provider-email",
        "auth-provider-sms",
        "auth-provider-passkey",
        "auth-sms-twilio",
        "auth-botcheck-turnstile",
        "auth-adapter-react-router",
        "examples",
      ],
    ],
  },
}
