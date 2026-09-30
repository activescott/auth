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
        "auth-store-prisma",
        "auth-adapter-react-router",
        "examples",
        // Repo infrastructure (workflows, commitlint, release script):
        // matches no package path, so it never triggers a release.
        "ci",
        // Dependabot's commit scopes (.github/dependabot.yml). Neither
        // matches a package name, so like "ci" they never trigger a
        // release regardless of the fix/chore type prefix.
        "deps",
        "deps-dev",
      ],
    ],
  },
}
