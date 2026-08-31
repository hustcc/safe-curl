import { describe, it, expect } from 'vitest';
import { ip4ToInt, prefixToMask, cidrParse, cidrMatcher } from '../src/cidr.js';

describe('ip4ToInt', () => {
  it('converts "0.0.0.0" to 0', () => {
    expect(ip4ToInt('0.0.0.0')).toBe(0);
  });

  it('converts "255.255.255.255" to max uint32', () => {
    expect(ip4ToInt('255.255.255.255')).toBe(0xffffffff);
  });

  it('converts "127.0.0.1" correctly', () => {
    expect(ip4ToInt('127.0.0.1')).toBe(0x7f000001);
  });

  it('converts "10.0.0.1" correctly', () => {
    expect(ip4ToInt('10.0.0.1')).toBe(0x0a000001);
  });
});

describe('prefixToMask', () => {
  it('/0 → 0', () => {
    expect(prefixToMask(0)).toBe(0);
  });

  it('/8 → 0xff000000', () => {
    expect(prefixToMask(8)).toBe(0xff000000);
  });

  it('/24 → 0xffffff00', () => {
    expect(prefixToMask(24)).toBe(0xffffff00);
  });

  it('/32 → 0xffffffff', () => {
    expect(prefixToMask(32)).toBe(0xffffffff);
  });
});

describe('cidrParse — IPv4', () => {
  it('parses "127.0.0.1" as /32 single IP', () => {
    const r = cidrParse('127.0.0.1');
    expect(r).not.toBeNull();
    expect(r!.type).toBe('ipv4');
    expect(r!.network).toBe(ip4ToInt('127.0.0.1'));
    expect(r!.mask).toBe(0xffffffff);
  });

  it('parses "10.0.0.0/8" correctly', () => {
    const r = cidrParse('10.0.0.0/8');
    expect(r).not.toBeNull();
    expect(r!.type).toBe('ipv4');
    expect(r!.network).toBe(ip4ToInt('10.0.0.0'));
    expect(r!.mask).toBe(0xff000000);
  });

  it('parses "172.16.0.0/12" correctly', () => {
    const r = cidrParse('172.16.0.0/12');
    expect(r).not.toBeNull();
    expect(r!.network).toBe(ip4ToInt('172.16.0.0'));
    expect(r!.mask).toBe(0xfff00000);
  });

  it('parses "192.168.0.0/16" correctly', () => {
    const r = cidrParse('192.168.0.0/16');
    expect(r).not.toBeNull();
    expect(r!.mask).toBe(0xffff0000);
  });

  it('returns null for invalid prefix', () => {
    expect(cidrParse('10.0.0.0/33')).toBeNull();
  });
});

describe('cidrParse — IPv6', () => {
  it('parses "fe80::/10" correctly', () => {
    const r = cidrParse('fe80::/10');
    expect(r).not.toBeNull();
    expect(r!.type).toBe('ipv6');
    expect(r!.mask).toBe(0xffc00000000000000000000000000000n);
  });

  it('parses "::1" as /128 single IP', () => {
    const r = cidrParse('::1');
    expect(r).not.toBeNull();
    expect(r!.type).toBe('ipv6');
    expect(r!.mask).toBe(0xffffffffffffffffffffffffffffffffn);
  });

  it('parses "2001:db8::/32" correctly', () => {
    const r = cidrParse('2001:db8::/32');
    expect(r).not.toBeNull();
    expect(r!.type).toBe('ipv6');
  });

  it('returns null for invalid prefix', () => {
    expect(cidrParse('fe80::/129')).toBeNull();
  });
});

describe('cidrMatcher — IPv4', () => {
  it('matches an exact IP', () => {
    const m = cidrMatcher(['127.0.0.1']);
    expect(m('127.0.0.1')).toBe(true);
    expect(m('127.0.0.2')).toBe(false);
  });

  it('matches IP within a CIDR range', () => {
    const m = cidrMatcher(['10.0.0.0/8']);
    expect(m('10.0.0.1')).toBe(true);
    expect(m('10.255.255.255')).toBe(true);
    expect(m('11.0.0.1')).toBe(false);
  });

  it('matches against multiple entries', () => {
    const m = cidrMatcher(['10.0.0.0/8', '192.168.0.0/16']);
    expect(m('10.1.2.3')).toBe(true);
    expect(m('192.168.1.1')).toBe(true);
    expect(m('172.16.0.1')).toBe(false);
  });

  it('returns false for invalid IP input', () => {
    const m = cidrMatcher(['127.0.0.0/8']);
    expect(m('not-an-ip')).toBe(false);
  });

  it('handles /0 (matches everything IPv4)', () => {
    const m = cidrMatcher(['0.0.0.0/0']);
    expect(m('1.2.3.4')).toBe(true);
    expect(m('255.255.255.255')).toBe(true);
  });
});

describe('cidrMatcher — IPv6', () => {
  it('matches an exact IPv6', () => {
    const m = cidrMatcher(['::1']);
    expect(m('::1')).toBe(true);
    expect(m('::2')).toBe(false);
  });

  it('matches within an IPv6 CIDR range', () => {
    const m = cidrMatcher(['fe80::/10']);
    expect(m('fe80::1')).toBe(true);
    expect(m('fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff')).toBe(true);
    expect(m('ff00::1')).toBe(false);
  });

  it('does not match IPv4 against IPv6 rule', () => {
    const m = cidrMatcher(['fe80::/10']);
    expect(m('10.0.0.1')).toBe(false);
  });

  it('does not match IPv6 against IPv4 rule', () => {
    const m = cidrMatcher(['10.0.0.0/8']);
    expect(m('fe80::1')).toBe(false);
  });

  it('handles mixed IPv4/IPv6 rule lists', () => {
    const m = cidrMatcher(['10.0.0.0/8', 'fe80::/10']);
    expect(m('10.0.0.1')).toBe(true);
    expect(m('fe80::1')).toBe(true);
    expect(m('192.168.1.1')).toBe(false);
    expect(m('ff00::1')).toBe(false);
  });
});