import type { CheckAddressFunction } from 'urllib';

/**
 * Options for the safeCurl factory function.
 * Priority: checkAddress > ipWhiteList > ipBlackList
 */
export interface SafeCurlOptions {
  /**
   * Custom address check function.
   * Return `true` to allow the connection, `false` to block it.
   */
  checkAddress?: CheckAddressFunction;

  /**
   * IP/CIDR blacklist.
   * e.g. ['127.0.0.1', '10.0.0.0/8', 'fe80::/10']
   */
  ipBlackList?: string[];

  /**
   * IP/CIDR whitelist — exceptions to the blacklist.
   * Checked before blacklist, so a whitelisted IP is always allowed.
   */
  ipWhiteList?: string[];

  /**
   * Hostnames that should always be allowed, bypassing IP checks.
   */
  hostnameExceptionList?: string[];
}