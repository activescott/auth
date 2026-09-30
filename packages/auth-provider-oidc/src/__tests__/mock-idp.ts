import { SignJWT, exportJWK, generateKeyPair } from "jose"
import type { CryptoKey, JWTPayload } from "jose"
import { codeChallengeFor } from "../pkce.js"

export const MOCK_ISSUER = "https://idp.example"
export const MOCK_CLIENT_ID = "client-123"
export const MOCK_CLIENT_SECRET = "secret-456"
const KID = "key-1"

interface IssuedCode {
  clientId: string
  redirectUri: string
  codeChallenge: string
  nonce: string
  claims: JWTPayload
}

/** Changes a test applies to the next ID token the token endpoint mints */
export interface IdTokenTamper {
  claims?: JWTPayload
  /** Sign with a key that is not in the JWKS, under the published kid */
  signWithForeignKey?: boolean
}

/**
 * An OpenID Provider in memory: its own RSA keypair and JWKS, a discovery
 * document, an authorization step that issues codes, and a token endpoint
 * that checks the client secret, redirect URI and PKCE verifier before
 * minting an RS256 ID token. Serve it to the client through `fetch`.
 */
export class MockIdp {
  public tamper: IdTokenTamper = {}
  public discoveryOverrides: Record<string, unknown> = {}
  public tokenRequests: { headers: Headers; body: URLSearchParams }[] = []
  private readonly codes = new Map<string, IssuedCode>()

  private constructor(
    private readonly privateKey: CryptoKey,
    private readonly foreignKey: CryptoKey,
    private readonly jwks: { keys: JsonWebKey[] },
    public readonly issuer: string,
  ) {}

  public static async create(issuer = MOCK_ISSUER): Promise<MockIdp> {
    const { privateKey, publicKey } = await generateKeyPair("RS256")
    const foreign = await generateKeyPair("RS256")
    const jwk = {
      ...(await exportJWK(publicKey)),
      kid: KID,
      alg: "RS256",
      use: "sig",
    }
    return new MockIdp(privateKey, foreign.privateKey, { keys: [jwk] }, issuer)
  }

  public get discoveryDocument(): Record<string, unknown> {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/authorize`,
      token_endpoint: `${this.issuer}/token`,
      jwks_uri: `${this.issuer}/jwks`,
      response_types_supported: ["code"],
      id_token_signing_alg_values_supported: ["RS256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic"],
      code_challenge_methods_supported: ["S256"],
      ...this.discoveryOverrides,
    }
  }

  /** A `fetch` that answers discovery, JWKS and token requests */
  public readonly fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init)
    const url = new URL(request.url)
    const path = `${url.origin}${url.pathname}`
    if (path === `${this.issuer}/.well-known/openid-configuration`) {
      return Response.json(this.discoveryDocument)
    }
    if (path === `${this.issuer}/jwks`) return Response.json(this.jwks)
    if (path === `${this.issuer}/token` && request.method === "POST") {
      return this.token(request)
    }
    return new Response("Not Found", { status: 404 })
  }

  /**
   * Play the user approving the request at the authorization endpoint:
   * record the code's binding and return the callback URL the browser would
   * be sent to.
   */
  public authorize(authorizationUrl: string, claims: JWTPayload = {}): string {
    const url = new URL(authorizationUrl)
    const params = url.searchParams
    if (`${url.origin}${url.pathname}` !== `${this.issuer}/authorize`) {
      throw new Error(`Unexpected authorization endpoint: ${authorizationUrl}`)
    }
    if (
      params.get("response_type") !== "code" ||
      params.get("code_challenge_method") !== "S256"
    ) {
      throw new Error("Expected the code flow with PKCE S256")
    }
    const code = crypto.randomUUID()
    this.codes.set(code, {
      clientId: params.get("client_id") ?? "",
      redirectUri: params.get("redirect_uri") ?? "",
      codeChallenge: params.get("code_challenge") ?? "",
      nonce: params.get("nonce") ?? "",
      claims,
    })
    const callback = new URL(params.get("redirect_uri") ?? "")
    callback.searchParams.set("code", code)
    callback.searchParams.set("state", params.get("state") ?? "")
    return callback.toString()
  }

  private async token(request: Request): Promise<Response> {
    const body = new URLSearchParams(await request.text())
    this.tokenRequests.push({ headers: request.headers, body })
    const invalid = (error: string) => Response.json({ error }, { status: 400 })

    const expectedAuth = `Basic ${btoa(`${MOCK_CLIENT_ID}:${MOCK_CLIENT_SECRET}`)}`
    const postAuth =
      body.get("client_id") === MOCK_CLIENT_ID &&
      body.get("client_secret") === MOCK_CLIENT_SECRET
    if (request.headers.get("authorization") !== expectedAuth && !postAuth) {
      return Response.json({ error: "invalid_client" }, { status: 401 })
    }
    if (body.get("grant_type") !== "authorization_code") {
      return invalid("unsupported_grant_type")
    }

    const code = body.get("code") ?? ""
    const issued = this.codes.get(code)
    this.codes.delete(code)
    if (!issued || issued.clientId !== MOCK_CLIENT_ID) {
      return invalid("invalid_grant")
    }
    if (issued.redirectUri !== body.get("redirect_uri")) {
      return invalid("invalid_grant")
    }
    const verifier = body.get("code_verifier") ?? ""
    if ((await codeChallengeFor(verifier)) !== issued.codeChallenge) {
      return invalid("invalid_grant")
    }

    const now = Math.floor(Date.now() / 1000)
    const idToken = await new SignJWT({
      iss: this.issuer,
      sub: "subject-1",
      aud: MOCK_CLIENT_ID,
      iat: now,
      exp: now + 300,
      nonce: issued.nonce,
      ...issued.claims,
      ...this.tamper.claims,
    })
      .setProtectedHeader({ alg: "RS256", kid: KID })
      .sign(this.tamper.signWithForeignKey ? this.foreignKey : this.privateKey)

    return Response.json({
      access_token: "access-token-not-for-storage",
      token_type: "Bearer",
      id_token: idToken,
    })
  }
}
