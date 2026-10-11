import { EventEmitter } from "node:events"
import { PassThrough } from "node:stream"
import { beforeEach, describe, expect, it, vi } from "vitest"

interface FakeResponse {
  status: number
  headers: Record<string, string>
  chunks?: string[]
  /** Never send the body, to test the timeout. */
  stall?: boolean
}

const calls: Array<{ url: URL; options: Record<string, unknown> }> = []
let next: FakeResponse

vi.mock("node:https", () => ({
  default: {
    request: (
      url: URL,
      options: Record<string, unknown>,
      onResponse: (response: unknown) => void,
    ) => {
      calls.push({ url, options })
      const request = new EventEmitter() as EventEmitter & {
        end(): void
        destroy(): void
      }
      request.destroy = () => {}
      request.end = () => {
        const body = new PassThrough() as PassThrough & {
          statusCode: number
          headers: Record<string, string>
        }
        body.statusCode = next.status
        body.headers = next.headers
        setImmediate(() => {
          onResponse(body)
          if (next.stall) return
          for (const chunk of next.chunks ?? []) body.write(chunk)
          body.end()
        })
      }
      return request
    },
  },
}))

const { createClientMetadataFetcher, cacheLifetimeSeconds } =
  await import("../node/client-metadata-fetcher.js")

const URL_ = new URL("https://client.example/client.json")
const JSON_HEADERS = { "content-type": "application/json" }

beforeEach(() => {
  calls.length = 0
})

describe("createClientMetadataFetcher response rules", () => {
  it("returns the parsed document and its cache lifetime", async () => {
    next = {
      status: 200,
      headers: { ...JSON_HEADERS, "cache-control": "public, max-age=600" },
      chunks: ['{"client_id":', '"https://client.example/client.json"}'],
    }
    const result = await createClientMetadataFetcher()(URL_)
    expect(result).toEqual({
      document: { client_id: "https://client.example/client.json" },
      maxAgeSeconds: 600,
    })
  })

  it("connects through the guarded lookup on a fresh connection", async () => {
    next = { status: 200, headers: JSON_HEADERS, chunks: ["{}"] }
    await createClientMetadataFetcher()(URL_)
    expect(calls[0]!.options.lookup).toBeTypeOf("function")
    expect(calls[0]!.options.agent).toBe(false)
  })

  it("accepts a charset parameter on the content type", async () => {
    next = {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8" },
      chunks: ["{}"],
    }
    await expect(createClientMetadataFetcher()(URL_)).resolves.toBeDefined()
  })

  it.each([301, 302, 307, 308])(
    "treats a %i redirect as an error",
    async (status) => {
      next = {
        status,
        headers: { location: "http://169.254.169.254/latest/meta-data" },
      }
      await expect(createClientMetadataFetcher()(URL_)).rejects.toThrow(
        /redirect/,
      )
    },
  )

  it.each([204, 404, 500])("refuses status %i", async (status) => {
    next = { status, headers: JSON_HEADERS, chunks: ["{}"] }
    await expect(createClientMetadataFetcher()(URL_)).rejects.toThrow()
  })

  it.each(["text/html", "application/javascript", "text/json", ""])(
    "refuses content type %j",
    async (type) => {
      next = { status: 200, headers: { "content-type": type }, chunks: ["{}"] }
      await expect(createClientMetadataFetcher()(URL_)).rejects.toThrow(
        /application\/json/,
      )
    },
  )

  it("refuses a body over the cap as it streams", async () => {
    next = {
      status: 200,
      headers: JSON_HEADERS,
      chunks: ['{"a":"', "x".repeat(40 * 1024), "x".repeat(40 * 1024), '"}'],
    }
    await expect(createClientMetadataFetcher()(URL_)).rejects.toThrow(
      /too large/,
    )
  })

  it("refuses a declared content-length over the cap", async () => {
    next = {
      status: 200,
      headers: { ...JSON_HEADERS, "content-length": String(65 * 1024) },
      chunks: ["{}"],
    }
    await expect(createClientMetadataFetcher()(URL_)).rejects.toThrow(
      /too large/,
    )
  })

  it("refuses invalid JSON", async () => {
    next = { status: 200, headers: JSON_HEADERS, chunks: ["{nope"] }
    await expect(createClientMetadataFetcher()(URL_)).rejects.toThrow(/JSON/)
  })

  it("gives up after the total timeout", async () => {
    next = { status: 200, headers: JSON_HEADERS, stall: true }
    await expect(
      createClientMetadataFetcher({ timeoutMs: 20 })(URL_),
    ).rejects.toThrow(/timed out/)
  })
})

describe("cacheLifetimeSeconds", () => {
  it.each([
    [{ "cache-control": "max-age=300" }, 300],
    [{ "cache-control": "public, max-age=86400, immutable" }, 86400],
    [{ "cache-control": "no-store" }, 0],
    [{ "cache-control": "no-cache, max-age=600" }, 0],
    [
      {
        date: "Thu, 01 Oct 2026 12:00:00 GMT",
        expires: "Thu, 01 Oct 2026 13:00:00 GMT",
      },
      3600,
    ],
    [{}, null],
  ])("reads %j as %s", (headers, expected) => {
    expect(cacheLifetimeSeconds(headers)).toBe(expected)
  })
})
