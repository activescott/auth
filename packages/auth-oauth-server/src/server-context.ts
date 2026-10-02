import {
  InMemoryRateLimitStore,
  RateLimiter,
  type RateLimitStore,
} from "@activescott/auth"
import { normalizeHost } from "./client-id-metadata-document.js"
import type {
  OAuthLifetimes,
  OAuthRateLimits,
  OAuthServerConfig,
} from "./types.js"

const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600
const SECONDS_PER_DAY = 86_400
const REFRESH_TOKEN_DAYS = 30

const DEFAULT_LIFETIMES: OAuthLifetimes = {
  accessToken: SECONDS_PER_HOUR,
  refreshToken: REFRESH_TOKEN_DAYS * SECONDS_PER_DAY,
  code: 10 * SECONDS_PER_MINUTE,
  authorizationRequest: 10 * SECONDS_PER_MINUTE,
  refreshReuseGrace: 60,
}

const DEFAULT_RATE_LIMITS: OAuthRateLimits = {
  registrationPerIp: [
    { windowSeconds: SECONDS_PER_MINUTE, max: 5 },
    { windowSeconds: SECONDS_PER_HOUR, max: 20 },
  ],
  metadataFetchPerUser: [
    { windowSeconds: SECONDS_PER_MINUTE, max: 10 },
    { windowSeconds: SECONDS_PER_HOUR, max: 50 },
  ],
  metadataFetchGlobal: [{ windowSeconds: SECONDS_PER_MINUTE, max: 100 }],
  authorizationRequestsPerUser: [
    { windowSeconds: SECONDS_PER_MINUTE, max: 20 },
    { windowSeconds: SECONDS_PER_HOUR, max: 200 },
  ],
}

/**
 * Configuration with defaults applied, shared by the endpoint modules.
 */
export interface ServerContext {
  config: OAuthServerConfig
  issuer: string
  endpoints: {
    authorization: string
    token: string
    registration: string
    revocation: string
  }
  ownHosts: ReadonlySet<string>
  optionalScopes: ReadonlySet<string>
  dynamicRegistration: boolean
  dynamicClientIdPrefix: string
  reservedClientNames: readonly string[]
  accessTokenPrefix: string
  refreshTokenPrefix: string
  lifetimes: OAuthLifetimes
  rateLimits: OAuthRateLimits
  rateLimiter: RateLimiter
  /** Set when the server created the store and must destroy it. */
  ownedRateLimitStore: InMemoryRateLimitStore | null
  now(): Date
  isUserActive(userId: string): Promise<boolean>
}

export function createServerContext(config: OAuthServerConfig): ServerContext {
  const issuerUrl = new URL(config.issuer)
  if (issuerUrl.search || issuerUrl.hash) {
    throw new Error("issuer must not contain a query or fragment")
  }
  const issuer = config.issuer.replace(/\/+$/, "")
  for (const scope of config.resource.defaultScopes) {
    if (!config.resource.scopes.includes(scope)) {
      throw new Error(`default scope ${scope} is not in resource.scopes`)
    }
  }
  const endpoint = (path: string) => new URL(path, issuer + "/").toString()
  let ownedRateLimitStore: InMemoryRateLimitStore | null = null
  let rateLimitStore: RateLimitStore
  if (config.rateLimitStore) {
    rateLimitStore = config.rateLimitStore
  } else {
    ownedRateLimitStore = new InMemoryRateLimitStore()
    rateLimitStore = ownedRateLimitStore
  }
  return {
    config,
    issuer,
    endpoints: {
      authorization: endpoint(
        config.endpoints?.authorization ?? "/oauth/authorize",
      ),
      token: endpoint(config.endpoints?.token ?? "/oauth/token"),
      registration: endpoint(
        config.endpoints?.registration ?? "/oauth/register",
      ),
      revocation: endpoint(config.endpoints?.revocation ?? "/oauth/revoke"),
    },
    ownHosts: new Set(
      [issuerUrl.hostname, ...(config.ownHosts ?? [])].map(normalizeHost),
    ),
    optionalScopes: new Set(config.resource.optionalScopes ?? []),
    dynamicRegistration: config.dynamicRegistration ?? true,
    dynamicClientIdPrefix: config.dynamicClientIdPrefix ?? "dyn_",
    reservedClientNames: config.reservedClientNames ?? [],
    accessTokenPrefix: config.tokenPrefixes?.access ?? "oat_",
    refreshTokenPrefix: config.tokenPrefixes?.refresh ?? "ort_",
    lifetimes: { ...DEFAULT_LIFETIMES, ...config.lifetimes },
    rateLimits: { ...DEFAULT_RATE_LIMITS, ...config.rateLimits },
    rateLimiter: new RateLimiter(rateLimitStore),
    ownedRateLimitStore,
    now: config.now ?? (() => new Date()),
    isUserActive: async (userId) =>
      config.isUserActive ? await config.isUserActive(userId) : true,
  }
}

/** `at` plus `seconds`. */
export function addSeconds(at: Date, seconds: number): Date {
  return new Date(at.getTime() + seconds * 1000)
}
