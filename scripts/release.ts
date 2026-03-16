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

  await new Releaser({
    project,
    hosting: new GithubHosting({
      token: process.env.GITHUB_TOKEN,
    }),
    verbose: true,
  })
    .bump({})
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

  // Map tags to package directories for npm publish
  const tagToDir: Record<string, string> = {
    "@activescott/auth": "packages/auth",
    "@activescott/auth-provider-email": "packages/auth-provider-email",
    "@activescott/auth-adapter-react-router":
      "packages/auth-adapter-react-router",
  }

  const packagesToPublish = newTags
    .map((tag) => {
      const name = tag.replace(/@[^@]+$/, "")
      return tagToDir[name] ? { name, dir: tagToDir[name], tag } : null
    })
    .filter(Boolean)

  writeFileSync(
    "packages-to-publish.json",
    JSON.stringify(packagesToPublish, null, 2),
  )
  console.log(
    `Packages to publish: ${packagesToPublish.length > 0 ? packagesToPublish.map((p) => p!.name).join(", ") : "none"}`,
  )
} catch (error) {
  console.error("Release failed:", error)
  process.exit(1)
}
