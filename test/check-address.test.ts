import { describe, it, expect } from 'vitest';
import { buildCheckAddress } from '../src/check-address.js';

describe('buildCheckAddress', () => {
  it('blocks exact IP in blacklist', () => {
    const fn = buildCheckAddress({ ipBlackList: ['127.0.0.1'] });
    expect(fn('127.0.0.1', 4, '')).toBe(false);
    expect(fn('192.168.1.1', 4, '')).toBe(true);
  });

  it('blocks IPs within CIDR subnet', () => {
    const fn = buildCheckAddress({ ipBlackList: ['10.0.0.0/8'] });
    expect(fn('10.255.255.255', 4, '')).toBe(false);
    expect(fn('11.0.0.1', 4, '')).toBe(true);
  });

  it('allows whitelisted IP even when in blacklist', () => {
    const fn = buildCheckAddress({ ipBlackList: ['10.0.0.0/8'], ipWhiteList: ['10.0.0.1'] });
    expect(fn('10.0.0.1', 4, '')).toBe(true);
    expect(fn('10.0.0.2', 4, '')).toBe(false);
  });

  it('allows by hostname exception first', () => {
    const fn = buildCheckAddress({
      ipBlackList: ['127.0.0.0/8'],
      hostnameWhiteList: ['localhost'],
    });
    expect(fn('127.0.0.1', 4, 'localhost')).toBe(true);
    expect(fn('127.0.0.1', 4, 'other.host')).toBe(false);
  });

  it('blocks IPv6 when in blacklist', () => {
    const fn = buildCheckAddress({ ipBlackList: ['fe80::/10'] });
    expect(fn('fe80::1', 6, '')).toBe(false);
  });

  it('allows IPv6 when not in blacklist', () => {
    const fn = buildCheckAddress({ ipBlackList: ['10.0.0.0/8'] });
    expect(fn('fe80::1', 6, '')).toBe(true);
  });

  it('allows when no rules are configured', () => {
    const fn = buildCheckAddress({});
    expect(fn('10.0.0.1', 4, '')).toBe(true);
    expect(fn('192.168.1.1', 4, '')).toBe(true);
  });

  it('allows when blacklist is empty', () => {
    const fn = buildCheckAddress({ ipBlackList: [] });
    expect(fn('127.0.0.1', 4, '')).toBe(true);
  });

  it('supports multiple blacklist entries', () => {
    const fn = buildCheckAddress({
      ipBlackList: ['127.0.0.0/8', '10.0.0.0/8'],
    });
    expect(fn('127.0.0.1', 4, '')).toBe(false);
    expect(fn('10.0.0.1', 4, '')).toBe(false);
    expect(fn('192.168.1.1', 4, '')).toBe(true);
  });
});