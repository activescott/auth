import type { LookupAddress } from "node:dns"
import { describe, expect, it } from "vitest"
import { createGuardedLookup, isPublicAddress } from "../node/address-guard.js"
import { createClientMetadataFetcher } from "../node/client-metadata-fetcher.js"

describe("isPublicAddress", () => {
  it.each(["8.8.8.8", "203.0.114.1", "2606:4700::1111", "::ffff:8.8.8.8"])(
    "accepts public %s",
    (address) => {
      expect(isPublicAddress(address)).toBe(true)
    },
  )

  it.each([
    ["loopback", "127.0.0.1"],
    ["loopback, high", "127.255.255.254"],
    ["private 10/8", "10.1.2.3"],
    ["private 172.16/12", "172.16.0.1"],
    ["private 192.168/16", "192.168.1.1"],
    ["this network 0/8", "0.1.2.3"],
    ["unspecified", "0.0.0.0"],
    ["carrier-grade NAT 100.64/10", "100.64.0.1"],
    ["link-local (cloud metadata)", "169.254.169.254"],
    ["multicast", "224.0.0.1"],
    ["reserved 240/4", "240.0.0.1"],
    ["broadcast", "255.255.255.255"],
    ["documentation", "192.0.2.1"],
    ["benchmarking", "198.18.0.1"],
    ["IPv6 loopback", "::1"],
    ["IPv6 unspecified", "::"],
    ["IPv4-mapped loopback", "::ffff:127.0.0.1"],
    ["IPv4-mapped private", "::ffff:10.0.0.1"],
    ["unique local", "fd00::1"],
    ["IPv6 link-local", "fe80::1"],
    ["NAT64", "64:ff9b::a00:1"],
    ["6to4", "2002:a00:1::"],
    ["Teredo", "2001::1"],
    ["IPv6 multicast", "ff02::1"],
    ["IPv6 documentation", "2001:db8::1"],
    ["not an address", "example.com"],
  ])("refuses %s (%s)", (_label, address) => {
    expect(isPublicAddress(address)).toBe(false)
  })
})

function lookupWith(addresses: LookupAddress[]) {
  return createGuardedLookup(() => Promise.resolve(addresses))
}

function callLookup(
  lookup: ReturnType<typeof createGuardedLookup>,
  options: { all?: boolean; family?: number },
): Promise<{ error: Error | null; address: unknown; family?: number }> {
  return new Promise((resolve) => {
    lookup("client.example", options as never, (error, address, family) => {
      resolve({ error, address, family })
    })
  })
}

describe("createGuardedLookup", () => {
  it("returns the checked address for a public host", async () => {
    const lookup = lookupWith([{ address: "203.0.114.1", family: 4 }])
    const result = await callLookup(lookup, {})
    expect(result).toEqual({ error: null, address: "203.0.114.1", family: 4 })
  })

  it("returns every address when asked for all", async () => {
    const addresses = [
      { address: "203.0.114.1", family: 4 },
      { address: "2606:4700::1111", family: 6 },
    ]
    const result = await callLookup(lookupWith(addresses), { all: true })
    expect(result.address).toEqual(addresses)
  })

  it("refuses a host with any non-public address, even alongside a public one", async () => {
    const lookup = lookupWith([
      { address: "203.0.114.1", family: 4 },
      { address: "10.0.0.5", family: 4 },
    ])
    const result = await callLookup(lookup, { all: true })
    expect(result.error?.message).toMatch(/10\.0\.0\.5.*not a public address/)
  })

  it("refuses a host with no addresses", async () => {
    const result = await callLookup(lookupWith([]), {})
    expect(result.error).not.toBeNull()
  })

  it("honours a requested address family", async () => {
    const lookup = lookupWith([
      { address: "203.0.114.1", family: 4 },
      { address: "2606:4700::1111", family: 6 },
    ])
    const result = await callLookup(lookup, { family: 6 })
    expect(result.address).toBe("2606:4700::1111")
  })
})

describe("createClientMetadataFetcher connection guard", () => {
  /**
   * A real https.request: the guarded lookup runs inside the connection and
   * refuses before any socket opens, so nothing here touches the network.
   */
  it.each(["127.0.0.1", "169.254.169.254", "::1", "10.96.0.1"])(
    "refuses to connect when the host resolves to %s",
    async (address) => {
      const fetcher = createClientMetadataFetcher({
        resolve: () =>
          Promise.resolve([{ address, family: address.includes(":") ? 6 : 4 }]),
      })
      await expect(
        fetcher(new URL("https://client.example/client.json")),
      ).rejects.toThrow(/not a public address/)
    },
  )

  it.each([
    ["http", "http://client.example/client.json"],
    ["another port", "https://client.example:8443/client.json"],
    ["userinfo", "https://u:p@client.example/client.json"],
    ["an IPv4 literal", "https://10.0.0.1/client.json"],
    ["an IPv6 literal", "https://[::1]/client.json"],
  ])("refuses %s before resolving", async (_label, url) => {
    let resolved = false
    const fetcher = createClientMetadataFetcher({
      resolve: () => {
        resolved = true
        return Promise.resolve([{ address: "203.0.114.1", family: 4 }])
      },
    })
    await expect(fetcher(new URL(url))).rejects.toThrow()
    expect(resolved).toBe(false)
  })
})
