import { HttpClient } from 'urllib';
import type { HttpClientResponse, RequestOptions } from 'urllib';
import { buildCheckAddress } from './check-address.js';
import { check as checkImpl } from './check-url.js';
import type { CheckUrlResult } from './check-url.js';
import type { SafeCurlOptions } from './types.js';

// Re-export types for consumers
export type { CheckAddressFunction, RequestOptions, HttpClientResponse } from 'urllib';
export type { SafeCurlOptions } from './types.js';
export type { CheckUrlResult } from './check-url.js';

export interface SafeCurl {
  /** Send an SSRF-safe HTTP request. */
  curl<T = any>(url: string | URL, options?: RequestOptions): Promise<HttpClientResponse<T>>;
  /** Check whether a URL is safe to request without actually sending it. */
  check(url: string | URL): Promise<CheckUrlResult>;
}

/**
 * Create an SSRF-safe HTTP client.
 *
 * @example
 * ```ts
 * import { safeCurl } from 'safe-curl';
 *
 * const { curl, check } = safeCurl({
 *   ipBlackList: ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
 * });
 *
 * // Pre-flight check
 * const { safe } = await check('http://localhost:3000/api');
 *
 * // Send request
 * const { data, status } = await curl('https://example.com/api');
 * ```
 */
export function safeCurl(opts: SafeCurlOptions = {}): SafeCurl {
  const checkAddress = opts.checkAddress || buildCheckAddress(opts);
  const client = new HttpClient({ checkAddress });

  return {
    curl: <T = any>(url: string | URL, options?: RequestOptions) =>
      client.request<T>(url, options),

    check: (url: string | URL) => checkImpl(url, checkAddress),
  };
}