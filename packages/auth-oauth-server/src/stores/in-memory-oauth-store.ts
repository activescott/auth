import type {
  OAuthAuthorizationRequest,
  OAuthClient,
  OAuthCode,
  OAuthGrant,
  OAuthStore,
  OAuthToken,
  OAuthTokenRevocationReason,
} from "../types.js"

/**
 * In-memory OAuthStore for tests and development. Nothing survives a
 * restart and nothing is shared between instances; production apps
 * implement OAuthStore against their database. Expired rows are never
 * swept.
 */
export class InMemoryOAuthStore implements OAuthStore {
  public readonly clients = new Map<string, OAuthClient>()
  public readonly authorizationRequests = new Map<
    string,
    OAuthAuthorizationRequest
  >()
  public readonly codes = new Map<string, OAuthCode>()
  public readonly grants = new Map<string, OAuthGrant>()
  public readonly tokens = new Map<string, OAuthToken>()

  public getClient(clientId: string): Promise<OAuthClient | null> {
    return Promise.resolve(copy(this.clients.get(clientId)))
  }

  public saveClient(client: OAuthClient): Promise<void> {
    this.clients.set(client.clientId, { ...client })
    return Promise.resolve()
  }

  public deleteUnusedDynamicClients(createdBefore: Date): Promise<number> {
    const granted = new Set(
      [...this.grants.values()].map((grant) => grant.clientId),
    )
    let deleted = 0
    for (const client of this.clients.values()) {
      if (
        client.kind === "dynamic" &&
        client.createdAt < createdBefore &&
        !granted.has(client.clientId)
      ) {
        this.clients.delete(client.clientId)
        deleted++
      }
    }
    return Promise.resolve(deleted)
  }

  public createAuthorizationRequest(
    request: OAuthAuthorizationRequest,
  ): Promise<void> {
    this.authorizationRequests.set(requestKey(request.userId, request.id), {
      ...request,
    })
    return Promise.resolve()
  }

  public consumeAuthorizationRequest(
    userId: string,
    id: string,
  ): Promise<OAuthAuthorizationRequest | null> {
    const key = requestKey(userId, id)
    const request = this.authorizationRequests.get(key)
    this.authorizationRequests.delete(key)
    return Promise.resolve(copy(request))
  }

  public createCode(code: OAuthCode): Promise<void> {
    this.codes.set(code.codeHash, { ...code })
    return Promise.resolve()
  }

  public findCode(codeHash: string): Promise<OAuthCode | null> {
    return Promise.resolve(copy(this.codes.get(codeHash)))
  }

  public markCodeUsed(codeHash: string, usedAt: Date): Promise<boolean> {
    const code = this.codes.get(codeHash)
    if (!code || code.usedAt) return Promise.resolve(false)
    code.usedAt = usedAt
    return Promise.resolve(true)
  }

  public upsertGrant(
    input: Pick<OAuthGrant, "userId" | "clientId" | "scopes" | "resource">,
    at: Date,
  ): Promise<OAuthGrant> {
    const existing = [...this.grants.values()].find(
      (grant) =>
        grant.userId === input.userId && grant.clientId === input.clientId,
    )
    if (existing) {
      existing.scopes = [...input.scopes]
      existing.resource = input.resource
      existing.revokedAt = null
      return Promise.resolve({ ...existing })
    }
    const grant: OAuthGrant = {
      id: crypto.randomUUID(),
      ...input,
      scopes: [...input.scopes],
      createdAt: at,
      lastUsedAt: null,
      revokedAt: null,
    }
    this.grants.set(grant.id, grant)
    return Promise.resolve({ ...grant })
  }

  public getGrant(grantId: string): Promise<OAuthGrant | null> {
    return Promise.resolve(copy(this.grants.get(grantId)))
  }

  public listGrants(userId: string): Promise<OAuthGrant[]> {
    return Promise.resolve(
      [...this.grants.values()]
        .filter((grant) => grant.userId === userId)
        .map((grant) => ({ ...grant })),
    )
  }

  public touchGrant(grantId: string, at: Date): Promise<void> {
    const grant = this.grants.get(grantId)
    if (grant) grant.lastUsedAt = at
    return Promise.resolve()
  }

  public revokeGrant(grantId: string, at: Date): Promise<void> {
    const grant = this.grants.get(grantId)
    if (grant && !grant.revokedAt) grant.revokedAt = at
    for (const token of this.tokens.values()) {
      if (token.grantId === grantId) revoke(token, at, "grant")
    }
    return Promise.resolve()
  }

  public createToken(token: OAuthToken): Promise<void> {
    this.tokens.set(token.id, { ...token })
    return Promise.resolve()
  }

  public findTokenByAccessHash(
    accessTokenHash: string,
  ): Promise<OAuthToken | null> {
    return Promise.resolve(
      copy(
        [...this.tokens.values()].find(
          (token) => token.accessTokenHash === accessTokenHash,
        ),
      ),
    )
  }

  public findTokenByRefreshHash(
    refreshTokenHash: string,
  ): Promise<OAuthToken | null> {
    return Promise.resolve(
      copy(
        [...this.tokens.values()].find(
          (token) => token.refreshTokenHash === refreshTokenHash,
        ),
      ),
    )
  }

  public findTokensRotatedFrom(tokenId: string): Promise<OAuthToken[]> {
    return Promise.resolve(
      [...this.tokens.values()]
        .filter((token) => token.rotatedFromId === tokenId)
        .map((token) => ({ ...token })),
    )
  }

  public markTokenRotated(tokenId: string, at: Date): Promise<boolean> {
    const token = this.tokens.get(tokenId)
    if (!token || token.rotatedAt || token.revokedAt) {
      return Promise.resolve(false)
    }
    token.rotatedAt = at
    return Promise.resolve(true)
  }

  public revokeUnrotatedToken(tokenId: string, at: Date): Promise<boolean> {
    const token = this.tokens.get(tokenId)
    if (!token || token.rotatedAt || token.revokedAt) {
      return Promise.resolve(false)
    }
    revoke(token, at, "grace")
    return Promise.resolve(true)
  }

  public revokeToken(
    tokenId: string,
    at: Date,
    reason: OAuthTokenRevocationReason,
  ): Promise<void> {
    const token = this.tokens.get(tokenId)
    if (token) revoke(token, at, reason)
    return Promise.resolve()
  }

  public revokeTokensForCode(
    codeHash: string,
    at: Date,
    reason: OAuthTokenRevocationReason,
  ): Promise<void> {
    for (const token of this.tokens.values()) {
      if (token.codeHash === codeHash) revoke(token, at, reason)
    }
    return Promise.resolve()
  }
}

function requestKey(userId: string, id: string): string {
  return JSON.stringify([userId, id])
}

function revoke(
  token: OAuthToken,
  at: Date,
  reason: OAuthTokenRevocationReason,
): void {
  if (token.revokedAt) return
  token.revokedAt = at
  token.revokedReason = reason
}

function copy<T extends object>(value: T | undefined): T | null {
  return value ? { ...value } : null
}
