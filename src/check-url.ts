import { promises as dns } from 'node:dns';
import { isIP } from 'node:net';
import type { CheckAddressFunction } from 'urllib';

export interface CheckUrlResult {
  /** Whether the URL is safe to request. */
  safe: boolean;
  /** The parsed hostname. */
  hostname: string;
  /** The resolved IP addresses. */
  ips: string[];
}

/**
 * Resolve a URL's hostname to IPs and check them against a checkAddress function.
 * For standalone use; otherwise prefer {@link safeCurl} which bundles curl + checkUrl.
 */
export async function check(
  url: string | URL,
  check: CheckAddressFunction,
): Promise<CheckUrlResult> {
  const raw = typeof url === 'string' ? new URL(url.includes('://') ? url : `https://${url}`).hostname : url.hostname;
  // Strip brackets from IPv6 hostnames (WHATWG spec inconsistency across Node versions)
  const hostname = raw.startsWith('[') ? raw.slice(1, -1) : raw;

  // IP literal — check directly without DNS
  const family = isIP(hostname);
  if (family !== 0) {
    const safe = check(hostname, family, hostname);
    return { safe, hostname, ips: [hostname] };
  }

  // Resolve hostname via DNS
  const [v4, v6] = await Promise.all([
    dns.resolve4(hostname).catch(() => [] as string[]),
    dns.resolve6(hostname).catch(() => [] as string[]),
  ]);

  const ips: string[] = [...v4, ...v6];
  if (ips.length === 0) return { safe: false, hostname, ips };

  const safe = ips.every(
    ip => check(ip, isIP(ip) === 6 ? 6 : 4, hostname),
  );

  return { safe, hostname, ips };
}