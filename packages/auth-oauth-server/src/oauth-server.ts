import {
  verifyAccessToken,
  type RejectedAccessToken,
  type VerifiedAccessToken,
} from "./access-token.js"
import { handleAuthorization } from "./authorization-endpoint.js"
import {
  authorizationServerMetadata,
  authorizationServerMetadataUrl,
  protectedResourceMetadata,
  protectedResourceMetadataUrl,
} from "./metadata.js"
import { handleRegistration } from "./registration-endpoint.js"
import { handleRevocation } from "./revocation-endpoint.js"
import { createServerContext, type ServerContext } from "./server-context.js"
import { handleToken } from "./token-endpoint.js"
import type { OAuthClientKind, OAuthGrant, OAuthServerConfig } from "./types.js"

const SECONDS_PER_HOUR = 3600
const HOURS_BEFORE_PRUNE = 24
const MS_PER_SECOND = 1000

/** A grant with what Connected apps shows about its client. */
export interface ConnectedApp {
  grant: OAuthGrant
  client: {
    clientId: string
    kind: OAuthClientKind
    name: string | null
    /** The `client_id` host for CIMD clients, else the first redirect host. */
    host: string | null
  } | null
}

/**
 * An OAuth 2.1 authorization server for one protected resource (such as an
 * MCP endpoint), speaking Fetch `Request`/`Response`. The app mounts each
 * handler on a route, signs the user in before {@link handleAuthorization},
 * renders the consent page through `config.renderConsent`, and implements
 * {@link OAuthStore} against its database.
 */
export class OAuthServer {
  private readonly context: ServerContext

  public constructor(config: OAuthServerConfig) {
    this.context = createServerContext(config)
  }

  /** URL to serve {@link handleProtectedResourceMetadata} at. */
  public get protectedResourceMetadataUrl(): string {
    return protectedResourceMetadataUrl(this.context.config.resource.uri)
  }

  /** URL to serve {@link handleAuthorizationServerMetadata} at. */
  public get authorizationServerMetadataUrl(): string {
    return authorizationServerMetadataUrl(this.context.issuer)
  }

  /** RFC 9728 protected resource metadata document. */
  public protectedResourceMetadata(): Record<string, unknown> {
    return protectedResourceMetadata(this.context)
  }

  /** RFC 8414 authorization server metadata document. */
  public authorizationServerMetadata(): Record<string, unknown> {
    return authorizationServerMetadata(this.context)
  }

  /** GET handler for {@link protectedResourceMetadataUrl}. */
  public handleProtectedResourceMetadata(): Response {
    return metadataResponse(this.protectedResourceMetadata())
  }

  /** GET handler for {@link authorizationServerMetadataUrl}. */
  public handleAuthorizationServerMetadata(): Response {
    return metadataResponse(this.authorizationServerMetadata())
  }

  /**
   * Dynamic Client Registration endpoint. Pass the client address the app's
   * own proxy observed; never a client-supplied `X-Forwarded-For`.
   */
  public handleRegistration(
    request: Request,
    options: { clientIp: string | null },
  ): Promise<Response> {
    return handleRegistration(this.context, request, options.clientIp)
  }

  /**
   * Authorization endpoint, GET and POST, for a signed-in user. The app
   * sends signed-out users to sign in first, back to this same URL.
   */
  public handleAuthorization(
    request: Request,
    options: { userId: string },
  ): Promise<Response> {
    return handleAuthorization(this.context, request, options.userId)
  }

  /** Token endpoint. */
  public handleToken(request: Request): Promise<Response> {
    return handleToken(this.context, request)
  }

  /** RFC 7009 revocation endpoint. */
  public handleRevocation(request: Request): Promise<Response> {
    return handleRevocation(this.context, request)
  }

  /**
   * Check the bearer token on a request to the protected resource. On
   * failure, send `response` as is: it carries the `WWW-Authenticate`
   * challenge clients use to discover and step up.
   */
  public verifyAccessToken(
    request: Request,
    options: { scopes?: string[] } = {},
  ): Promise<VerifiedAccessToken | RejectedAccessToken> {
    return verifyAccessToken(this.context, request, options.scopes ?? [])
  }

  /** The user's unrevoked grants, for a Connected apps list. */
  public async listConnectedApps(userId: string): Promise<ConnectedApp[]> {
    const { store } = this.context.config
    const grants = (await store.listGrants(userId)).filter(
      (grant) => !grant.revokedAt,
    )
    return Promise.all(
      grants.map(async (grant) => {
        const client = await store.getClient(grant.clientId)
        return {
          grant,
          client: client && {
            clientId: client.clientId,
            kind: client.kind,
            name: client.name,
            host:
              client.kind === "cimd"
                ? new URL(client.clientId).hostname
                : client.redirectUris[0]
                  ? new URL(client.redirectUris[0]).hostname
                  : null,
          },
        }
      }),
    )
  }

  /**
   * Disconnect: revoke one of the user's grants and every token under it.
   * Returns false when the grant is not this user's.
   */
  public async revokeGrant(userId: string, grantId: string): Promise<boolean> {
    const { store } = this.context.config
    const grant = await store.getGrant(grantId)
    if (!grant || grant.userId !== userId) return false
    await store.revokeGrant(grantId, this.context.now())
    return true
  }

  /**
   * Delete dynamic clients registered more than 24 hours ago that never got
   * a grant. Run it on a schedule.
   */
  public pruneDynamicClients(): Promise<number> {
    const cutoff = new Date(
      this.context.now().getTime() -
        HOURS_BEFORE_PRUNE * SECONDS_PER_HOUR * MS_PER_SECOND,
    )
    return this.context.config.store.deleteUnusedDynamicClients(cutoff)
  }

  /** Stop the default in-memory rate-limit store's sweep timer. */
  public destroy(): void {
    this.context.ownedRateLimitStore?.destroy()
  }
}

function metadataResponse(body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": `public, max-age=${SECONDS_PER_HOUR}`,
    },
  })
}
