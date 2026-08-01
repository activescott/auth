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
        "auth-sms-twilio",
        "auth-sms-aws",
        "auth-adapter-react-router",
        "examples",
      ],
    ],
  },
}
