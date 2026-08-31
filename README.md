# safe-curl

[![npm version](https://img.shields.io/npm/v/safe-curl.svg)](https://www.npmjs.com/package/safe-curl)
[![npm downloads](https://img.shields.io/npm/dm/safe-curl.svg)](https://www.npmjs.com/package/safe-curl)
[![build](https://github.com/hustcc/safe-curl/actions/workflows/build.yml/badge.svg)](https://github.com/hustcc/safe-curl/actions/workflows/build.yml)
[![license](https://img.shields.io/npm/l/safe-curl.svg)](LICENSE)

👮🏻‍♀️ SSRF-safe HTTP client for Node.js — prevent Server-Side Request Forgery by IP/CIDR filtering. Supports **IPv4 and IPv6**.

Wraps [urllib](https://github.com/node-modules/urllib) with a `checkAddress` callback that blocks requests to internal/blacklisted IPs.

## Installation

```bash
npm install safe-curl
```

## Usage

```ts
import { safeCurl } from 'safe-curl';

const { check, curl } = safeCurl({
  ipBlackList: [
    '127.0.0.0/8',    // loopback
    '10.0.0.0/8',     // private
    '172.16.0.0/12',  // private
    '192.168.0.0/16', // private
    '169.254.0.0/16', // link-local
    '100.64.0.0/10',  // CGNAT
  ],
});

// Pre-flight check
const { safe } = await check('http://localhost:3000/api');
// → { safe: false, hostname: 'localhost', ips: ['127.0.0.1', '::1'] }

// Blocks requests to internal IPs → throws
await curl('http://10.0.0.1/admin');
// → Error: illegal address

// Public endpoints work normally
const { data, status } = await curl('https://api.example.com/data', {
  dataType: 'json',
});
```

## API

### `safeCurl(opts) → { curl, check }`

Returns an object with two methods sharing the same security config.

#### Options

| Option | Type | Description |
|--------|------|-------------|
| `checkAddress` | `(ip, family, hostname) => boolean` | Custom address check. `true` = allow, `false` = block. Highest priority. |
| `ipBlackList` | `string[]` | IPv4/IPv6 CIDR entries to block. e.g. `['127.0.0.1', '10.0.0.0/8', 'fe80::/10']` |
| `ipWhiteList` | `string[]` | CIDR entries exempt from the blacklist. Checked before blacklist. |
| `hostnameWhiteList` | `string[]` | Hostnames that bypass IP checking entirely. |

Priority: `checkAddress` > `hostnameWhiteList` > `ipWhiteList` > `ipBlackList`

#### `curl(url, options?)`

Same signature as [urllib's `request`](https://github.com/node-modules/urllib). Returns `HttpClientResponse<T>`.

#### `check(url)`

Pre-flight check — resolves the URL's hostname and checks all IPs against the security rules. No HTTP request is made.

Returns `{ safe: boolean, hostname: string, ips: string[] }`.

## Examples

### Custom checkAddress

```ts
const { curl } = safeCurl({
  checkAddress(ip) {
    return ip === '1.1.1.1';
  },
});
```

### IP whitelist exceptions

```ts
const { curl } = safeCurl({
  ipBlackList: ['10.0.0.0/8'],
  ipWhiteList: ['10.0.1.5'],
});
```

### Hostname whitelist

```ts
const { curl } = safeCurl({
  ipBlackList: ['127.0.0.0/8'],
  hostnameWhiteList: ['localhost'],
});
```

### Pre-flight check

```ts
const { check, curl } = safeCurl({ ipBlackList: ['127.0.0.0/8', '10.0.0.0/8'] });

const { safe, ips } = await check('http://user-input-url/api');
if (!safe) throw new Error(`Blocked IPs: ${ips.join(', ')}`);
```

## How It Works

1. `curl()` — DNS resolves the target hostname, then `checkAddress` blocks blacklisted IPs **before** the TCP connection.
2. `check()` — same DNS + IP check, but doesn't connect. Useful for validating user-supplied URLs.
3. Direct IP requests (`http://10.0.0.1/`) are also caught — no DNS bypass.

```
check('http://internal.corp.com')
  → DNS lookup → [10.0.0.5]
  → checkAddress('10.0.0.5', 4, 'internal.corp.com')
  → false → { safe: false }
```

## License

MIT