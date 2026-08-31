import type { CheckAddressFunction } from 'urllib';
import { cidrMatcher } from './cidr.js';
import type { SafeCurlOptions } from './types.js';

/**
 * Build a checkAddress callback from declarative config
 * (ipBlackList, ipWhiteList, hostnameExceptionList).
 *
 * Mirrors egg-security's preprocessConfig logic.
 */
function warnIPv6(label: string, entries: string[]): void {
  const ipv6 = entries.filter(e => /:/.test(e));
  if (ipv6.length) {
    console.warn(`[safe-curl] ${label}: IPv6 entries are ignored (only IPv4 is supported) — ${ipv6.join(', ')}`);
  }
}

export function buildCheckAddress(opts: SafeCurlOptions): CheckAddressFunction {
  const blackList = opts.ipBlackList || [];
  const whiteList = opts.ipWhiteList || [];

  warnIPv6('ipBlackList', blackList);
  warnIPv6('ipWhiteList', whiteList);

  const containsList = blackList.length
    ? [cidrMatcher(blackList)]
    : [];

  const exceptionList = whiteList.length
    ? [cidrMatcher(whiteList)]
    : [];

  const hostnameExceptionList = opts.hostnameExceptionList || [];

  return (ip, family, hostname) => {
    // 1. Hostname exception — always allow
    if (hostname && hostnameExceptionList.includes(hostname)) {
      return true;
    }

    // 2. Skip IPv6 — same as egg-security
    if (family === 6) return true;

    // 3. Whitelist (exceptionList) checked first
    for (const isAllowed of exceptionList) {
      if (isAllowed(ip)) return true;
    }

    // 4. Blacklist (containsList)
    for (const isBlocked of containsList) {
      if (isBlocked(ip)) return false;
    }

    // Not in any blocked range — allow
    return true;
  };
}