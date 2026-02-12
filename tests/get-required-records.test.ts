import { describe, it, expect } from 'vitest';
import { getRequiredDnsRecords } from '../src/get-required-records.js';
import {
  RULE_CNAME_TARGET,
  RULE_DKIM_TARGET,
  RULE_DMARC_POLICY,
} from '../src/constants.js';
import type { DnsCheckResult } from '../src/types.js';

describe('getRequiredDnsRecords', () => {
  it('returns all 3 records when no checkResult provided', () => {
    const records = getRequiredDnsRecords('example.com');
    expect(records).toHaveLength(3);

    expect(records[0]).toEqual({
      type: 'CNAME',
      name: 'rm.example.com',
      value: RULE_CNAME_TARGET,
      purpose: 'mx-spf',
    });
    expect(records[1]).toEqual({
      type: 'CNAME',
      name: 'keyse._domainkey.example.com',
      value: RULE_DKIM_TARGET,
      purpose: 'dkim',
    });
    expect(records[2]).toEqual({
      type: 'TXT',
      name: '_dmarc.rm.example.com',
      value: RULE_DMARC_POLICY,
      purpose: 'dmarc',
    });
  });

  it('cleans domain from input', () => {
    const records = getRequiredDnsRecords('user@EXAMPLE.COM');
    expect(records[0]!.name).toBe('rm.example.com');
  });

  it('returns empty array when all checks pass', () => {
    const checkResult: DnsCheckResult = {
      domain: 'example.com',
      allPassed: true,
      warnings: [],
      checks: {
        ns: { status: 'pass' },
        mx: { status: 'pass' },
        spf: { status: 'pass' },
        dkim: { status: 'pass' },
        dmarc: { status: 'pass' },
      },
    };

    const records = getRequiredDnsRecords('example.com', checkResult);
    expect(records).toHaveLength(0);
  });

  it('returns only DKIM record when only DKIM fails', () => {
    const checkResult: DnsCheckResult = {
      domain: 'example.com',
      allPassed: false,
      warnings: [],
      checks: {
        ns: { status: 'pass' },
        mx: { status: 'pass' },
        spf: { status: 'pass' },
        dkim: { status: 'fail', expected: RULE_DKIM_TARGET },
        dmarc: { status: 'pass' },
      },
    };

    const records = getRequiredDnsRecords('example.com', checkResult);
    expect(records).toHaveLength(1);
    expect(records[0]!.purpose).toBe('dkim');
  });

  it('returns CNAME record when MX is missing (even if SPF passes)', () => {
    const checkResult: DnsCheckResult = {
      domain: 'example.com',
      allPassed: false,
      warnings: [],
      checks: {
        ns: { status: 'pass' },
        mx: { status: 'missing' },
        spf: { status: 'pass' },
        dkim: { status: 'pass' },
        dmarc: { status: 'pass' },
      },
    };

    const records = getRequiredDnsRecords('example.com', checkResult);
    expect(records).toHaveLength(1);
    expect(records[0]!.purpose).toBe('mx-spf');
  });

  it('returns all records when everything is missing', () => {
    const checkResult: DnsCheckResult = {
      domain: 'example.com',
      allPassed: false,
      warnings: [],
      checks: {
        ns: { status: 'missing' },
        mx: { status: 'missing' },
        spf: { status: 'missing' },
        dkim: { status: 'missing' },
        dmarc: { status: 'missing' },
      },
    };

    const records = getRequiredDnsRecords('example.com', checkResult);
    expect(records).toHaveLength(3);
  });

  it('returns DMARC record when DMARC is missing', () => {
    const checkResult: DnsCheckResult = {
      domain: 'example.com',
      allPassed: false,
      warnings: [],
      checks: {
        ns: { status: 'pass' },
        mx: { status: 'pass' },
        spf: { status: 'pass' },
        dkim: { status: 'pass' },
        dmarc: { status: 'missing' },
      },
    };

    const records = getRequiredDnsRecords('example.com', checkResult);
    expect(records).toHaveLength(1);
    expect(records[0]!.purpose).toBe('dmarc');
  });
});
