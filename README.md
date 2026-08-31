# safe-curl

[![npm version](https://img.shields.io/npm/v/safe-curl.svg)](https://www.npmjs.com/package/safe-curl)
[![npm downloads](https://img.shields.io/npm/dm/safe-curl.svg)](https://www.npmjs.com/package/safe-curl)
[![build](https://github.com/hustcc/safe-curl/actions/workflows/build.yml/badge.svg)](https://github.com/hustcc/safe-curl/actions/workflows/build.yml)
[![license](https://img.shields.io/npm/l/safe-curl.svg)](LICENSE)

👮🏻‍♀️ Secure `cURL` for preventing `SSRF` Attacks for AI agent in NodeJS runtime. SSRF-safe HTTP client — prevent Server-Side Request Forgery by IP filtering.

`safe-curl` wraps [urllib](https://github.com/node-modules/urllib) with a `checkAddress` callback that blocks requests to internal/blacklisted IP addresses.

## Installation

```bash
npm install safe-curl
```

## Usage

```ts
import { safeCurl } from 'safe-curl';

const curl = safeCurl({
  ipBlackList: [
    '127.0.0.0/8',    // loopback
    '10.0.0.0/8',     // private
    '172.16.0.0/12',  // private
    '192.168.0.0/16', // private
    '169.254.0.0/16', // link-local
    '100.64.0.0/10',  // CGNAT
  ],
});

// Blocks requests to internal IPs → throws
await curl('http://10.0.0.1/admin');
// → Error: illegal address

// Requests to public endpoints work normally
const { data, status } = await curl('https://api.example.com/data', {
  dataType: 'json',
});
```

## API

### `safeCurl(opts) → curl(url, options)`

Creates an SSRF-safe HTTP request function.

#### Options

| Option | Type | Description |
|--------|------|-------------|
| `checkAddress` | `(ip, family, hostname) => boolean` | Custom address check. Return `true` to allow, `false` to block. Has the highest priority. |
| `ipBlackList` | `string[]` | IP/CIDR entries to block. e.g. `['127.0.0.1', '10.0.0.0/8']` |
| `ipWhiteList` | `string[]` | IP/CIDR entries exempt from the blacklist. Checked before blacklist. |
| `hostnameExceptionList` | `string[]` | Hostnames that bypass IP checking entirely. |

Priority: `checkAddress` > `hostnameExceptionList` > `ipWhiteList` > `ipBlackList`

#### Return value

Returns `curl(url, options)` — an async function with the same signature as [urllib's `request`](https://github.com/node-modules/urllib). Returns `HttpClientResponse<T>`.

## Examples

### Custom checkAddress

```ts
const curl = safeCurl({
  checkAddress(ip, family, hostname) {
    // Only allow requests to 1.1.1.1
    return ip === '1.1.1.1';
  },
});
```

### Whitelist exceptions

```ts
const curl = safeCurl({
  ipBlackList: ['10.0.0.0/8'],
  ipWhiteList: ['10.0.1.5'], // allow this specific IP
});
```

### Hostname exceptions

```ts
const curl = safeCurl({
  ipBlackList: ['127.0.0.0/8'],
  hostnameExceptionList: ['localhost'], // always allow localhost
});
```

## How It Works

1. When a request is made, the target hostname is resolved via DNS.
2. Before the TCP connection is established, every resolved IP is checked by `checkAddress`.
3. If an IP is blocked (`false`), the connection is aborted with an error before any data is sent.
4. Direct IP requests (e.g. `http://10.0.0.1/`) are also caught — no DNS bypass.

```
curl('http://internal.corp.com')
  → DNS lookup → [10.0.0.5]
  → checkAddress('10.0.0.5', 4, 'internal.corp.com')
  → false → throw Error('illegal address')
```

## License

MIT