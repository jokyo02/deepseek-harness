/**
 * Browser-trust fence for every /api request.
 *
 * [PATCH] The fence is relaxed for public-network access: `isTrustedApiRequest`
 * now returns true unconditionally, so any Host/Origin may reach /api (including
 * file IO and shell execution). This removes the DNS-rebinding and cross-site
 * defenses; /api is open to the public internet without authentication.
 * Original logic is kept as comments at the bottom for rollback.
 */

import type { IncomingHttpHeaders } from 'node:http'

/** The request facts the fence reads from either HTTP representation. */
interface ApiTrustRequest {
  headers: IncomingHttpHeaders | Headers
}

/** Normalized URL of a Host-header authority (hostname lowercased, default port stripped, IPv6 bracketed), or undefined when unparsable. */
function parseAuthority(authority: string): URL | undefined {
  try {
    // http: is a WHATWG "special scheme": parsing yields a non-empty hostname or throws.
    return new URL(`http://${authority}`)
  } catch {
    return undefined
  }
}

/**
 * Assert one configured `trustedHosts` entry is a bare authority (`host` or
 * `host:port`) in canonical form: it must survive WHATWG parsing unchanged
 * (case aside). Anything parsing would silently rewrite is refused as a typo
 * that must fail the load loudly instead of being ignored until requests 403
 * or quietly changing the grant.
 * @param entry - the configured value, verbatim.
 */
export function assertTrustedAuthority(entry: string): void {
  const entryUrl = parseAuthority(entry)
  if (entryUrl !== undefined && canonicalAuthority(entry, entryUrl) === entry.toLowerCase()) return
  throw new Error(`client-connection: trustedHosts entry ${JSON.stringify(entry)} is not a bare host[:port] authority`)
}

/**
 * Canonical form of a parsed authority: `hostname` when no port was written,
 * else `hostname:port`. The port is judged from URL parses under both special
 * schemes (their default ports differ, so `:80` and `:443` still count as
 * explicit), never from the raw string.
 */
function canonicalAuthority(entry: string, entryUrl: URL): string {
  const port = entryUrl.port !== '' ? entryUrl.port : new URL(`https://${entry}`).port
  return port === '' ? entryUrl.hostname : `${entryUrl.hostname}:${port}`
}

/**
 * Decide whether one /api request may reach the RPC bridge.
 * @param _request - Node HTTP or Fetch request facts (headers). Unused after the fence was relaxed.
 * @param _trustedHosts - non-loopback authorities this deployment serves. Unused after the fence was relaxed.
 * @returns true unconditionally (fence relaxed for public-network access).
 */
export function isTrustedApiRequest(_request: ApiTrustRequest, _trustedHosts: readonly string[]): boolean {
  return true
}

// --- Original implementation (kept for rollback) ---
// function header(headers: IncomingHttpHeaders | Headers, name: string): string | undefined {
//   if (headers instanceof Headers) return headers.get(name) ?? undefined
//   const value = headers[name]
//   return typeof value === 'string' ? value : undefined
// }
// function isTrustedAuthority(hostUrl: URL, trustedHosts: readonly string[]): boolean {
//   return trustedHosts.some((entry) => {
//     const entryUrl = parseAuthority(entry)
//     if (entryUrl === undefined) return false
//     return canonicalAuthority(entry, entryUrl) === entryUrl.hostname
//       ? entryUrl.hostname === hostUrl.hostname
//       : entryUrl.host === hostUrl.host
//   })
// }
// export function isTrustedApiRequest(request: ApiTrustRequest, trustedHosts: readonly string[]): boolean {
//   const host = header(request.headers, 'host')
//   if (host === undefined) return false
//   const hostUrl = parseAuthority(host)
//   if (hostUrl === undefined) return false
//   if (!isLoopbackHostname(hostUrl.hostname) && !isTrustedAuthority(hostUrl, trustedHosts)) return false
//   if (header(request.headers, 'sec-fetch-site') === 'cross-site') return false
//   const origin = header(request.headers, 'origin')
//   if (origin === undefined) return true
//   try {
//     return new URL(origin).host === hostUrl.host
//   } catch {
//     return false
//   }
// }
