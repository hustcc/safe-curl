import { describe, it, expect } from 'vitest';
import { safeCurl } from '../src/index.js';

describe('safeCurl — factory', () => {
  it('returns a function', () => {
    const curl = safeCurl();
    expect(typeof curl).toBe('function');
  });

  it('works with empty config', async () => {
    const curl = safeCurl();
    const { status } = await curl('https://httpbin.org/get');
    expect(status).toBe(200);
  });

  it('accepts a URL object', async () => {
    const curl = safeCurl({ ipBlackList: ['127.0.0.0/8'] });
    const { status } = await curl(new URL('https://httpbin.org/get'));
    expect(status).toBe(200);
  });
});

describe('safeCurl — ipBlackList integration', () => {
  it('blocks direct IP in blacklist', async () => {
    const curl = safeCurl({ ipBlackList: ['127.0.0.1'] });
    await expect(curl('http://127.0.0.1:61234/noop')).rejects.toThrow();
  });

  it('blocks IP within CIDR range', async () => {
    const curl = safeCurl({ ipBlackList: ['127.0.0.0/8'] });
    await expect(curl('http://127.99.99.99:61234/noop')).rejects.toThrow();
  });

  it('allows public endpoint not in blacklist', async () => {
    const curl = safeCurl({ ipBlackList: ['10.0.0.0/8'] });
    const { status } = await curl('https://httpbin.org/get');
    expect(status).toBe(200);
  });
});

describe('safeCurl — ipWhiteList integration', () => {
  it('allows whitelisted IP in blacklist range', async () => {
    const curl = safeCurl({
      ipBlackList: ['127.0.0.0/8'],
      ipWhiteList: ['127.0.0.1'],
    });
    const err = await curl('http://127.0.0.1:61234/noop').catch(e => e);
    expect(err).toBeDefined();
    expect(err.message).not.toContain('illegal');
  });

  it('blocks non-whitelisted IP in same range', async () => {
    const curl = safeCurl({
      ipBlackList: ['127.0.0.0/8'],
      ipWhiteList: ['127.0.0.1'],
    });
    const err = await curl('http://127.0.0.2:61234/noop').catch(e => e);
    expect(err).toBeDefined();
    expect(err.message).toContain('illegal');
  });
});

describe('safeCurl — hostnameExceptionList integration', () => {
  it('allows excepted hostname even in blacklist', async () => {
    const curl = safeCurl({
      ipBlackList: ['127.0.0.0/8'],
      hostnameExceptionList: ['localhost'],
    });
    const err = await curl('http://localhost:61234/noop').catch(e => e);
    expect(err).toBeDefined();
    expect(err.message).not.toContain('illegal');
  });
});

describe('safeCurl — custom checkAddress integration', () => {
  it('uses custom checkAddress (takes priority)', async () => {
    const curl = safeCurl({
      ipBlackList: ['10.0.0.0/8'],
      checkAddress(ip) {
        return ip === '1.2.3.4';
      },
    });
    await expect(curl('https://httpbin.org/get')).rejects.toThrow();
  });

  it('allows everything when checkAddress returns true', async () => {
    const curl = safeCurl({ checkAddress() { return true; } });
    const { status } = await curl('https://httpbin.org/get');
    expect(status).toBe(200);
  });
});

describe('safeCurl — request options passthrough', () => {
  it('passes through POST data', async () => {
    const curl = safeCurl();
    const { data } = await curl('https://httpbin.org/anything', {
      method: 'POST',
      data: JSON.stringify({ hello: 'world' }),
      contentType: 'json',
      dataType: 'json',
    });
    expect(data.data).toContain('hello');
  });

  it('returns JSON response data', async () => {
    const curl = safeCurl();
    const { data, status } = await curl('https://httpbin.org/get', {
      dataType: 'json',
    });
    expect(status).toBe(200);
    expect(data.url).toContain('httpbin.org/get');
  });
});

describe('safeCurl — edge cases', () => {
  it('/32 blocks exact single IP', async () => {
    const curl = safeCurl({ ipBlackList: ['192.0.2.1/32'] });
    await expect(curl('http://192.0.2.1:61234/noop')).rejects.toThrow();
  });

  it('/32 allows other IPs in same /24', async () => {
    const curl = safeCurl({ ipBlackList: ['192.0.2.1/32'] });
    const { status } = await curl('https://httpbin.org/get');
    expect(status).toBe(200);
  });

  it('/0 blocks all IPv4', async () => {
    const curl = safeCurl({ ipBlackList: ['0.0.0.0/0'], ipWhiteList: [] });
    await expect(curl('https://httpbin.org/get')).rejects.toThrow();
  });
});