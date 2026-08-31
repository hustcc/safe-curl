import { isIP } from 'node:net';

/**
 * Convert an IPv4 string to a 32-bit unsigned integer.
 */
export function ip4ToInt(ip: string): number {
  const octets = ip.split('.');
  if (octets.length !== 4) return 0;
  return (((+octets[0]! << 24) >>> 0) +
    ((+octets[1]! << 16) >>> 0) +
    ((+octets[2]! << 8) >>> 0) +
    (+octets[3]! >>> 0)) >>> 0;
}

/**
 * Create a netmask from a prefix length (0–32).
 */
export function prefixToMask(prefixLen: number): number {
  if (prefixLen < 0 || prefixLen > 32) return 0;
  return prefixLen === 0 ? 0 : (~((1 << (32 - prefixLen)) - 1)) >>> 0;
}

/**
 * Parse a CIDR string like "10.0.0.0/8" into { network, mask } (integers),
 * or a single IP like "127.0.0.1" (treated as /32).
 * Returns null for IPv6 or invalid input.
 */
export function cidrParse(cidr: string): { network: number; mask: number } | null {
  const idx = cidr.indexOf('/');
  const ip = idx === -1 ? cidr : cidr.slice(0, idx);
  const prefix = idx === -1 ? 32 : parseInt(cidr.slice(idx + 1), 10);

  // Only handle IPv4
  if (isIP(ip) !== 4) return null;
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;

  const network = ip4ToInt(ip);
  const mask = prefixToMask(prefix);
  return { network: (network & mask) >>> 0, mask };
}

/**
 * Build a predicate that tests whether an IP address matches a list of
 * CIDR/IP entries.
 */
export function cidrMatcher(entries: string[]): (ip: string) => boolean {
  const rules = entries.map(entry => cidrParse(entry))
    .filter(Boolean) as { network: number; mask: number }[];

  return (ip: string): boolean => {
    if (isIP(ip) !== 4) return false;
    const ipInt = ip4ToInt(ip);
    return rules.some(r => ((ipInt & r.mask) >>> 0) === r.network);
  };
}