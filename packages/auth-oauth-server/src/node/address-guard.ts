import { promises as dns, type LookupAddress } from "node:dns"
import type { LookupFunction } from "node:net"
import ipaddr from "ipaddr.js"

/** Resolves a host name to every address it has. */
export type ResolveHost = (hostname: string) => Promise<LookupAddress[]>

const resolveWithDns: ResolveHost = (hostname) =>
  dns.lookup(hostname, { all: true, verbatim: true })

/**
 * Whether an address is ordinary public unicast. ipaddr.js classifies every
 * special-use range (private, loopback, link-local, `0.0.0.0/8`,
 * `100.64.0.0/10`, multicast, reserved, unique-local, NAT64, 6to4, Teredo
 * and more) as something other than `unicast`, and `process` unwraps
 * IPv4-mapped IPv6 so `::ffff:127.0.0.1` is checked as `127.0.0.1`.
 */
export function isPublicAddress(address: string): boolean {
  try {
    return ipaddr.process(address).range() === "unicast"
  } catch {
    return false
  }
}

/**
 * A `lookup` for `net`/`tls` connections that resolves the host once and
 * refuses the connection if any address is not public. The socket connects
 * to the address checked here, so DNS rebinding cannot swap it, while TLS
 * still sends the host name as SNI and verifies the certificate against it.
 */
export function createGuardedLookup(
  resolve: ResolveHost = resolveWithDns,
): LookupFunction {
  return (hostname, options, callback) => {
    resolve(hostname)
      .then((addresses) => {
        if (addresses.length === 0) {
          throw new Error(`${hostname} has no addresses`)
        }
        const blocked = addresses.find(
          (entry) => !isPublicAddress(entry.address),
        )
        if (blocked) {
          throw new Error(
            `${hostname} resolves to ${blocked.address}, which is not a public address`,
          )
        }
        const family =
          options.family === 4 || options.family === 6 ? options.family : null
        const usable = family
          ? addresses.filter((entry) => entry.family === family)
          : addresses
        if (usable.length === 0) {
          throw new Error(`${hostname} has no IPv${family} address`)
        }
        if (options.all) {
          callback(null, usable)
        } else {
          callback(null, usable[0]!.address, usable[0]!.family)
        }
      })
      .catch((error: unknown) => {
        callback(
          error instanceof Error ? error : new Error(String(error)),
          "",
          0,
        )
      })
  }
}
