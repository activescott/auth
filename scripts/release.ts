#!/usr/bin/env tsx
/* eslint-disable no-console */
import { Releaser } from "@simple-release/core"
import { NpmWorkspacesProject } from "@simple-release/npm"
import { GithubHosting } from "@simple-release/github"
import { writeFileSync } from "node:fs"
import { execSync } from "node:child_process"

/**
 * Creates releases using simple-release for all bumped packages.
 * Outputs packages-to-publish.json with the list of packages that were bumped.
 */

function getAllTags(): Set<string> {
  try {
    const output = execSync("git tag -l", { encoding: "utf8" })
    return new Set(output.trim().split("\n").filter(Boolean))
  } catch {
    return new Set()
  }
}

try {
  const project = new NpmWorkspacesProject({
    mode: "independent",
  })

  const tagsBefore = getAllTags()
  console.log(`Tags before release: ${tagsBefore.size} total`)

  // If no tags exist yet, this is the first release — use firstRelease
  // to publish current versions without requiring conventional commit history.
  const hasExistingTags = tagsBefore.size > 0
  const bumpOptions = hasExistingTags ? {} : { firstRelease: true }

  await new Releaser({
    project,
    hosting: new GithubHosting({
      token: process.env.GITHUB_TOKEN,
    }),
    verbose: true,
  })
    .bump(bumpOptions)
    .commit()
    .tag()
    .push()
    .release({})
    .run()

  const tagsAfter = getAllTags()
  console.log(`Tags after release: ${tagsAfter.size} total`)

  const newTags = [...tagsAfter].filter((t) => !tagsBefore.has(t))
  console.log(`New tags created: ${newTags.length}`)
  if (newTags.length > 0) {
    console.log(`  Tags: ${newTags.join(", ")}`)
  }

  // Map tag prefixes to package directories for npm publish.
  // simple-release creates tags like "auth@0.1.1" (package dir name, not npm name).
  const tagPrefixToPackage: Record<string, { name: string; dir: string }> = {
    auth: { name: "@activescott/auth", dir: "packages/auth" },
    "auth-provider-email": {
      name: "@activescott/auth-provider-email",
      dir: "packages/auth-provider-email",
    },
    "auth-adapter-react-router": {
      name: "@activescott/auth-adapter-react-router",
      dir: "packages/auth-adapter-react-router",
    },
  }

  const packagesToPublish = newTags
    .map((tag) => {
      const prefix = tag.replace(/@[^@]+$/, "")
      const pkg = tagPrefixToPackage[prefix]
      return pkg ? { name: pkg.name, dir: pkg.dir, tag } : null
    })
    .filter(Boolean)

  writeFileSync("packages-to-publish.json", JSON.stringify(packagesToPublish))
  console.log(
    `Packages to publish: ${packagesToPublish.length > 0 ? packagesToPublish.map((p) => p!.name).join(", ") : "none"}`,
  )
} catch (error) {
  console.error("Release failed:", error)
  process.exit(1)
}
