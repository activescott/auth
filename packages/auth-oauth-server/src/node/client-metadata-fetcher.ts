import type { IncomingHttpHeaders } from "node:http"
import https from "node:https"
import { isIP } from "node:net"
import type { ClientMetadataFetcher } from "../types.js"
import { createGuardedLookup, type ResolveHost } from "./address-guard.js"

const DEFAULT_TIMEOUT_MS = 5000
const DEFAULT_MAX_BYTES = 64 * 1024
const HTTP_OK = 200
const MS_PER_SECOND = 1000

/** Options for {@link createClientMetadataFetcher}. */
export interface ClientMetadataFetcherOptions {
  /** Total time for the fetch, connection to last byte (default 5000). */
  timeoutMs?: number
  /** Largest body accepted (default 64 KiB). */
  maxBytes?: number
  /** Host name resolution; defaults to `dns.lookup`. */
  resolve?: ResolveHost
}

/**
 * Fetch Client ID Metadata Documents from Node with an SSRF guard: https on
 * port 443 only, every resolved address checked to be public and the
 * connection pinned to it, a redirect treated as an error (the CIMD draft
 * says not to follow one), only a `200` with `Content-Type:
 * application/json` accepted, and the body and total time capped. Returns
 * the cache lifetime the response headers allow; the server clamps it.
 */
export function createClientMetadataFetcher(
  options: ClientMetadataFetcherOptions = {},
): ClientMetadataFetcher {
  const lookup = createGuardedLookup(options.resolve)
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES

  return (url) =>
    new Promise((resolve, reject) => {
      if (
        url.protocol !== "https:" ||
        (url.port !== "" && url.port !== "443")
      ) {
        reject(
          new Error("client metadata must be fetched over https on port 443"),
        )
        return
      }
      if (url.username || url.password) {
        reject(new Error("client metadata URL must not contain userinfo"))
        return
      }
      // Node skips `lookup` for an IP literal, which would skip the guard.
      if (isIP(url.hostname.replace(/^\[|\]$/g, "")) !== 0) {
        reject(new Error("client metadata URL must use a host name"))
        return
      }

      let settled = false
      const finish = (
        error: Error | null,
        value?: Awaited<ReturnType<ClientMetadataFetcher>>,
      ) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (error) {
          request.destroy()
          reject(error)
        } else {
          resolve(value!)
        }
      }

      const request = https.request(
        url,
        {
          method: "GET",
          lookup,
          // A fresh connection, never a pooled socket another request opened.
          agent: false,
          headers: { Accept: "application/json" },
        },
        (response) => {
          const status = response.statusCode ?? 0
          if (status !== HTTP_OK) {
            response.resume()
            finish(
              new Error(
                status >= 300 && status < 400
                  ? "client metadata responded with a redirect, which is not followed"
                  : `client metadata responded with ${status}`,
              ),
            )
            return
          }
          const type = (response.headers["content-type"] ?? "")
            .split(";")[0]!
            .trim()
            .toLowerCase()
          if (type !== "application/json") {
            response.resume()
            finish(new Error("client metadata is not application/json"))
            return
          }
          if (Number(response.headers["content-length"] ?? "0") > maxBytes) {
            response.resume()
            finish(new Error("client metadata is too large"))
            return
          }
          const chunks: Buffer[] = []
          let received = 0
          response.on("data", (chunk: Buffer) => {
            received += chunk.length
            if (received > maxBytes) {
              finish(new Error("client metadata is too large"))
              return
            }
            chunks.push(chunk)
          })
          response.on("error", (error) => finish(error))
          response.on("end", () => {
            let document: unknown
            try {
              document = JSON.parse(Buffer.concat(chunks).toString("utf8"))
            } catch {
              finish(new Error("client metadata is not valid JSON"))
              return
            }
            finish(null, {
              document,
              maxAgeSeconds: cacheLifetimeSeconds(response.headers),
            })
          })
        },
      )
      const timer = setTimeout(
        () => finish(new Error("client metadata fetch timed out")),
        timeoutMs,
      )
      request.on("error", (error) => finish(error))
      request.end()
    })
}

/**
 * How long a response may be cached per its headers: 0 for `no-store` or
 * `no-cache`, `max-age` when present, else `Expires` minus `Date`, else
 * null.
 */
export function cacheLifetimeSeconds(
  headers: IncomingHttpHeaders,
): number | null {
  const cacheControl = (headers["cache-control"] ?? "").toLowerCase()
  const directives = cacheControl.split(",").map((part) => part.trim())
  if (directives.some((part) => part === "no-store" || part === "no-cache")) {
    return 0
  }
  for (const part of directives) {
    const match = /^max-age\s*=\s*"?(\d+)"?$/.exec(part)
    if (match) return Number(match[1])
  }
  const expires = headers.expires ? Date.parse(headers.expires) : NaN
  if (!Number.isNaN(expires)) {
    const date = headers.date ? Date.parse(headers.date) : Date.now()
    const base = Number.isNaN(date) ? Date.now() : date
    return Math.max(0, Math.floor((expires - base) / MS_PER_SECOND))
  }
  return null
}
