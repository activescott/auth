export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "scope-enum": [
      2,
      "always",
      ["auth", "auth-provider-email", "auth-provider-oauth", "auth-adapter-react-router", "examples"],
    ],
  },
}
