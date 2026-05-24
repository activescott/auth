# Semver Release

Cut a new semver release: bump `package.json`, create an annotated git tag, push it, and create a GitHub release with auto-generated notes.

## Usage

`/semver <bump>` — where `<bump>` is one of:

- `patch` — `0.2.0` → `0.2.1` (bug fixes, docs, chores; no new features, no breaking changes)
- `minor` — `0.2.0` → `0.3.0` (new features; for pre-1.0 also use this for breaking changes)
- `major` — `0.2.0` → `1.0.0` (breaking changes once the API is stable; rarely used pre-1.0)

If the user did not specify a bump type, ask them which one before proceeding.

## Steps

### Step 1: Verify the working tree is clean and on master

Run in parallel:

- `git status --porcelain` — must be empty. If not, stop and tell the user to commit or stash first.
- `git rev-parse --abbrev-ref HEAD` — must be `main`. If not, ask the user to confirm before proceeding.
- `git fetch origin && git rev-list --count HEAD..origin/main` — must be `0`. If the local branch is behind, stop and tell the user to pull first.

### Step 2: Determine current and next version

- Read individual `packages/*/package.json` `version` fields (this is a monorepo — each package is versioned independently via `@simple-release`).
- Note: For coordinated releases, `scripts/release.ts` handles this automatically on CI. Use `/semver` only for manual releases.
- Show the user the current versions and confirm before continuing.

### Step 3: Summarize what's in the release

- Run `git log <last-tag>..HEAD --oneline` to list commits since the previous tag.
- If there are zero commits since the last tag, stop and tell the user there's nothing to release.

### Step 4: Bump the version

- Edit the target `package.json` to the new version.
- Run `npm install --package-lock-only` to sync `package-lock.json`.
- Stage both files.

### Step 5: Commit, tag, and push

Run sequentially:

- `git commit -m "chore(release): bump <package> to v<next>"` (with the standard `Co-Authored-By` trailer).
- `git tag -a <package>@v<next> -m "<package>@v<next>"` — keep the tag message short.
- `git push origin main` — push the commit first.
- `git push origin <package>@v<next>` — then the tag.

### Step 6: Create the GitHub release

- `gh release create <package>@v<next> --title "<package>@v<next>" --generate-notes --notes-start-tag <package>@v<previous>`

### Step 7: Report

Output to the user:

- Old version → new version
- Tag URL
- Number of commits in this release

## Rules

- Never tag if the working tree is dirty.
- Never tag a commit that hasn't been pushed.
- Use annotated tags (`-a`), never lightweight tags.
- Tag names use the `<package>@v<version>` format (e.g., `@activescott/auth@v0.2.1`).
