import { isIP } from 'node:net';

type CidrRule =
  | { type: 'ipv4'; network: number; mask: number }
  | { type: 'ipv6'; network: bigint; mask: bigint };

/** Convert an IPv4 string to a 32-bit unsigned integer. */
export function ip4ToInt(ip: string): number {
  const octets = ip.split('.');
  if (octets.length !== 4) return 0;
  return (((+octets[0]! << 24) >>> 0) +
    ((+octets[1]! << 16) >>> 0) +
    ((+octets[2]! << 8) >>> 0) +
    (+octets[3]! >>> 0)) >>> 0;
}

/** Create a netmask from a prefix length (0–32). */
export function prefixToMask(prefixLen: number): number {
  if (prefixLen < 0 || prefixLen > 32) return 0;
  return prefixLen === 0 ? 0 : (~((1 << (32 - prefixLen)) - 1)) >>> 0;
}

/** Expand a compressed IPv6 string into groups (default 8, or 6 for mixed notation). */
function expandIPv6(ip: string, target = 8): number[] {
  const parts = ip.split('::');
  const left = parts[0] ? parts[0].split(':').filter(Boolean).map(h => parseInt(h || '0', 16)) : [];
  const right = parts[1] ? parts[1].split(':').filter(Boolean).map(h => parseInt(h || '0', 16)) : [];
  const missing = target - left.length - right.length;
  return [...left, ...Array(Math.max(0, missing)).fill(0), ...right];
}

/** Convert an IPv6 string to a 128-bit BigInt. */
function ip6ToBigInt(ip: string): bigint {
  // Mixed notation ::ffff:x.x.x.x or ::x.x.x.x
  if (ip.includes('.')) {
    const idx = ip.lastIndexOf(':');
    // Handle '::' — the separator might be the second colon
    const v6End = idx > 0 && ip[idx - 1] === ':' ? idx - 1 : idx;
    const v6part = ip.slice(0, v6End);
    const v4part = ip.slice(idx + 1);
    const groups = expandIPv6(v6part, 6);
    const v4 = ip4ToInt(v4part);
    groups.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
    let result = 0n;
    for (let i = 0; i < 8; i++) result = (result << 16n) | BigInt(groups[i]!);
    return result;
  }
  const groups = expandIPv6(ip);
  let result = 0n;
  for (let i = 0; i < 8; i++) result = (result << 16n) | BigInt(groups[i]!);
  return result;
}

/** Create a 128-bit netmask from a prefix length (0–128). */
function ip6PrefixToMask(prefix: number): bigint {
  if (prefix === 0) return 0n;
  const hostBits = BigInt(128 - prefix);
  return ~((1n << hostBits) - 1n) & ((1n << 128n) - 1n);
}

/**
 * Parse a CIDR string into a CidrRule.
 * IPv4: "10.0.0.0/8" → { type:'ipv4', network, mask }
 * IPv6: "fe80::/10"  → { type:'ipv6', network, mask }
 * Bare IP treated as /32 (v4) or /128 (v6).
 * Returns null for invalid input.
 */
export function cidrParse(cidr: string): CidrRule | null {
  const idx = cidr.indexOf('/');
  const ip = idx === -1 ? cidr : cidr.slice(0, idx);
  const prefix = idx === -1 ? null : parseInt(cidr.slice(idx + 1), 10);

  const family = isIP(ip);
  if (family === 0) return null;
  if (prefix !== null && (isNaN(prefix) || prefix < 0)) return null;

  if (family === 4) {
    const pfx = prefix ?? 32;
    if (pfx > 32) return null;
    const network = ip4ToInt(ip);
    const mask = prefixToMask(pfx);
    return { type: 'ipv4', network: (network & mask) >>> 0, mask };
  }

  // IPv6
  const pfx = prefix ?? 128;
  if (pfx > 128) return null;
  const net = ip6ToBigInt(ip);
  const mask = ip6PrefixToMask(pfx);
  return { type: 'ipv6', network: net & mask, mask };
}

/**
 * Build a predicate that tests whether an IP matches a list of CIDR entries.
 * Supports both IPv4 and IPv6 addresses and CIDRs.
 */
export function cidrMatcher(entries: string[]): (ip: string) => boolean {
  const rules = entries
    .map(entry => cidrParse(entry))
    .filter(Boolean) as CidrRule[];

  return (ip: string): boolean => {
    const family = isIP(ip);

    if (family === 4) {
      const ipInt = ip4ToInt(ip);
      return rules.some(r =>
        r.type === 'ipv4' && ((ipInt & r.mask) >>> 0) === r.network,
      );
    }

    if (family === 6) {
      const ipBig = ip6ToBigInt(ip);
      return rules.some(r =>
        r.type === 'ipv6' && (ipBig & r.mask) === r.network,
      );
    }

    return false;
  };
}