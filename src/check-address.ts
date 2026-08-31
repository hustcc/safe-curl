import type { CheckAddressFunction } from 'urllib';
import { cidrMatcher } from './cidr.js';
import type { SafeCurlOptions } from './types.js';

/**
 * Build a checkAddress callback from declarative config
 * (ipBlackList, ipWhiteList, hostnameWhiteList).
 *
 * Mirrors egg-security's preprocessConfig logic.
 */
export function buildCheckAddress(opts: SafeCurlOptions): CheckAddressFunction {
  const containsList = (opts.ipBlackList || []).length
    ? [cidrMatcher(opts.ipBlackList!)]
    : [];

  const exceptionList = (opts.ipWhiteList || []).length
    ? [cidrMatcher(opts.ipWhiteList!)]
    : [];

  const hostnameWhiteList = opts.hostnameWhiteList || [];

  return (ip, _family, hostname) => {
    // 1. Hostname exception — always allow
    if (hostname && hostnameWhiteList.includes(hostname)) {
      return true;
    }

    // 2. Whitelist (exceptionList) checked first
    for (const isAllowed of exceptionList) {
      if (isAllowed(ip)) return true;
    }

    // 3. Blacklist (containsList)
    for (const isBlocked of containsList) {
      if (isBlocked(ip)) return false;
    }

    // Not in any blocked range — allow
    return true;
  };
}