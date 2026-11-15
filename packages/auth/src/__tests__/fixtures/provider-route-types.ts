// Compiled by provider-route-types.test.ts, never run. The test fails if any
// expect-error directive below is unused, so each line must stay an error.
// prettier-ignore keeps each erroring statement on its directive's line.
import type { ProviderRoute } from "../../types.js"

const post = { method: "POST", path: "/fake/route" } as const

export const action: ProviderRoute = { ...post, handler: "action" }
export const limited: ProviderRoute = {
  ...post,
  handler: "action",
  rateLimitByIp: true,
}

// prettier-ignore
// @ts-expect-error rateLimitByIp exists only on "action" routes
export const verify: ProviderRoute = { ...post, handler: "verify", rateLimitByIp: true }

// prettier-ignore
// @ts-expect-error rateLimitByIp exists only on "action" routes
export const initiate: ProviderRoute = { ...post, handler: "initiate", rateLimitByIp: true }

export function isLimited(route: ProviderRoute): boolean {
  return route.handler === "action" && route.rateLimitByIp === true
}
