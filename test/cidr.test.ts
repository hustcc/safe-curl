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

describe('cidrParse', () => {
  it('parses "127.0.0.1" as /32 single IP', () => {
    const r = cidrParse('127.0.0.1');
    expect(r).not.toBeNull();
    expect(r!.network).toBe(ip4ToInt('127.0.0.1'));
    expect(r!.mask).toBe(0xffffffff);
  });

  it('parses "10.0.0.0/8" correctly', () => {
    const r = cidrParse('10.0.0.0/8');
    expect(r).not.toBeNull();
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

  it('returns null for IPv6', () => {
    expect(cidrParse('fe80::/10')).toBeNull();
  });

  it('returns null for invalid prefix', () => {
    expect(cidrParse('10.0.0.0/33')).toBeNull();
  });
});

describe('cidrMatcher', () => {
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

  it('returns false for IPv6 input', () => {
    const m = cidrMatcher(['127.0.0.0/8']);
    expect(m('::1')).toBe(false);
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