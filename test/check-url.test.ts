import { describe, it, expect } from 'vitest';
import { check } from '../src/check-url.js';
import { buildCheckAddress } from '../src/check-address.js';

describe('check — IP literal', () => {
  it('blocks blacklisted IPv4 literal', async () => {
    const addr = buildCheckAddress({ ipBlackList: ['127.0.0.0/8'] });
    const r = await check('http://127.0.0.1:3000/api', addr);
    expect(r.safe).toBe(false);
    expect(r.ips).toEqual(['127.0.0.1']);
  });

  it('allows non-blacklisted IPv4 literal', async () => {
    const addr = buildCheckAddress({ ipBlackList: ['127.0.0.0/8'] });
    const r = await check('http://93.184.216.34/', addr);
    expect(r.safe).toBe(true);
  });

  it('blocks blacklisted IPv6 literal', async () => {
    const addr = buildCheckAddress({ ipBlackList: ['::1'] });
    const r = await check('http://[::1]:3000/', addr);
    expect(r.safe).toBe(false);
    expect(r.ips).toEqual(['::1']);
  });

  it('allows non-blacklisted IPv6 literal', async () => {
    const addr = buildCheckAddress({ ipBlackList: ['::1'] });
    const r = await check('http://[::2]/', addr);
    expect(r.safe).toBe(true);
  });
});

describe('check — hostname (DNS)', () => {
  it('blocks hostname resolving to blacklisted range', async () => {
    const addr = buildCheckAddress({ ipBlackList: ['127.0.0.0/8'] });
    const r = await check('http://localhost:61234/', addr);
    expect(r.safe).toBe(false);
  });

  it('allows public hostname', async () => {
    const addr = buildCheckAddress({ ipBlackList: ['127.0.0.0/8', '10.0.0.0/8'] });
    const r = await check('https://httpbin.org/get', addr);
    expect(r.safe).toBe(true);
  });

  it('auto-prepends https:// for bare hostname', async () => {
    const addr = buildCheckAddress({ ipBlackList: ['127.0.0.0/8', '10.0.0.0/8'] });
    const r = await check('httpbin.org/get', addr);
    expect(r.safe).toBe(true);
    expect(r.hostname).toBe('httpbin.org');
  });

  it('keeps http:// protocol when present', async () => {
    const addr = buildCheckAddress({ ipBlackList: ['127.0.0.0/8'] });
    const r = await check('http://example.com/', addr);
    expect(r.hostname).toBe('example.com');
  });

  it('returns safe:false for unresolvable hostname', async () => {
    const addr = buildCheckAddress({});
    const r = await check('http://invalid.local.test/', addr);
    expect(r.safe).toBe(false);
    expect(r.ips).toEqual([]);
  });
});

describe('check — via safeCurl', () => {
  it('bundled check works', async () => {
    const { check } = await import('../src/index.js').then(m => m.safeCurl({
      ipBlackList: ['127.0.0.0/8'],
    }));
    const r = await check('http://127.0.0.1/');
    expect(r.safe).toBe(false);
  });
});