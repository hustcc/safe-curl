import { HttpClient } from 'urllib';
import type { HttpClientResponse, RequestOptions } from 'urllib';
import { buildCheckAddress } from './check-address.js';
import type { SafeCurlOptions } from './types.js';

// Re-export types for consumers
export type { CheckAddressFunction, RequestOptions, HttpClientResponse } from 'urllib';
export type { SafeCurlOptions } from './types.js';

/**
 * Create an SSRF-safe HTTP request function.
 *
 * @example
 * ```ts
 * import { safeCurl } from 'safe-curl';
 *
 * const curl = safeCurl({
 *   ipBlackList: ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
 * });
 *
 * const { data, status } = await curl('https://example.com/api');
 * ```
 */
export function safeCurl(opts: SafeCurlOptions = {}) {
  const checkAddress = opts.checkAddress || buildCheckAddress(opts);

  const client = new HttpClient({ checkAddress });

  return async function curl<T = any>(
    url: string | URL,
    options?: RequestOptions,
  ): Promise<HttpClientResponse<T>> {
    return client.request<T>(url, options);
  };
}