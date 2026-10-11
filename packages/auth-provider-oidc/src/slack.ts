import type { Identity } from "@activescott/auth"
import type {
  IdTokenClaims,
  OidcIdentity,
  OidcProviderConfig,
} from "./types.js"
import { OidcError } from "./oidc-error.js"
import { OidcProvider } from "./oidc-provider.js"

/** Sign in with Slack's issuer */
export const SLACK_ISSUER = "https://slack.com"
/** Where Slack publishes its discovery document */
export const SLACK_DISCOVERY_URL =
  "https://slack.com/.well-known/openid-configuration"
/** Scopes Sign in with Slack accepts */
export const SLACK_SCOPES = ["openid", "profile", "email"]
/** ID token claim carrying the workspace (team) ID */
export const SLACK_TEAM_ID_CLAIM = "https://slack.com/team_id"
/** ID token claim carrying the Slack user ID */
export const SLACK_USER_ID_CLAIM = "https://slack.com/user_id"

/**
 * What a Slack identity stores as provider state: the workspace and the user
 * within it, as Slack's ID token states them.
 */
export interface SlackIdentityState {
  teamId: string
  userId: string
}

/**
 * Configuration for {@link createSlackProvider}: the Slack app's credentials
 * plus the {@link OidcProvider} options that are not fixed by Slack.
 */
export interface SlackProviderConfig extends Omit<
  OidcProviderConfig,
  "id" | "name" | "issuer" | "discoveryUrl" | "scopes" | "identify"
> {
  /** Provider id, the `{provider}` segment of the routes. Defaults to "slack". */
  id?: string
  /** Human-readable name. Defaults to "Slack". */
  name?: string
}

/**
 * Key a Slack identity on workspace plus user, and store both. Slack user IDs
 * are only guaranteed unique within a workspace, so the user ID alone could
 * collide across workspaces.
 *
 * @throws OidcError with reason "claims" when either ID is missing
 */
export function identifySlackUser(claims: IdTokenClaims): OidcIdentity {
  const teamId = claims[SLACK_TEAM_ID_CLAIM]
  const userId = claims[SLACK_USER_ID_CLAIM] ?? claims.sub
  if (typeof teamId !== "string" || !teamId) {
    throw new OidcError("claims", "Slack ID token has no team ID")
  }
  if (typeof userId !== "string" || !userId) {
    throw new OidcError("claims", "Slack ID token has no user ID")
  }
  const state: SlackIdentityState = { teamId, userId }
  return { identifier: `${teamId}:${userId}`, providerState: { ...state } }
}

/**
 * Sign in with Slack: an {@link OidcProvider} with Slack's issuer, discovery
 * document and scopes, whose identities carry the Slack team and user IDs.
 * Read them back with {@link slackIdentityState}.
 *
 * Register `{baseUrl}/auth/slack/callback` (or `redirectUri`) as a redirect
 * URL in the Slack app's OAuth settings.
 *
 * @example
 * ```ts
 * const slack = createSlackProvider({
 *   clientId: process.env.SLACK_CLIENT_ID!,
 *   clientSecret: process.env.SLACK_CLIENT_SECRET!,
 * })
 * ```
 */
export function createSlackProvider(config: SlackProviderConfig): OidcProvider {
  return new OidcProvider({
    ...config,
    id: config.id ?? "slack",
    name: config.name ?? "Slack",
    issuer: SLACK_ISSUER,
    discoveryUrl: SLACK_DISCOVERY_URL,
    scopes: SLACK_SCOPES,
    identify: identifySlackUser,
  })
}

/**
 * The Slack team and user IDs stored on an identity created by
 * {@link createSlackProvider}, or undefined for any other identity.
 */
export function slackIdentityState(
  identity: Pick<Identity, "providerState">,
): SlackIdentityState | undefined {
  const { teamId, userId } = identity.providerState
  return typeof teamId === "string" && typeof userId === "string"
    ? { teamId, userId }
    : undefined
}
