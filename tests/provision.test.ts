import { describe, it, expect, vi, beforeEach } from 'vitest';
import { provisionDns } from '../src/provision.js';
import type { DnsProvider, ProviderRecord } from '../src/provider.js';
import {
  RULE_CNAME_TARGET,
  RULE_DKIM_TARGET,
  RULE_DMARC_POLICY,
} from '../src/constants.js';

// Mock checkDns — avoid real DNS lookups
vi.mock('../src/check-dns.js', () => ({
  checkDns: vi.fn(),
}));

import { checkDns } from '../src/check-dns.js';
const mockCheckDns = vi.mocked(checkDns);

function allMissing(domain: string) {
  return {
    domain,
    allPassed: false,
    warnings: [],
    checks: {
      ns: { status: 'missing' as const },
      mx: { status: 'missing' as const },
      spf: { status: 'missing' as const },
      dkim: { status: 'missing' as const },
      dmarc: { status: 'missing' as const },
    },
  };
}

function allPassing(domain: string) {
  return {
    domain,
    allPassed: true,
    warnings: [],
    checks: {
      ns: { status: 'pass' as const },
      mx: { status: 'pass' as const },
      spf: { status: 'pass' as const },
      dkim: { status: 'pass' as const },
      dmarc: { status: 'pass' as const },
    },
  };
}

function createMockProvider(
  existing: Map<string, ProviderRecord[]> = new Map()
): DnsProvider & {
  created: { type: string; name: string; value: string }[];
  deletedIds: string[];
} {
  const created: { type: string; name: string; value: string }[] = [];
  const deletedIds: string[] = [];
  let nextId = 1;

  return {
    created,
    deletedIds,
    async getRecords(name: string) {
      return existing.get(name) ?? [];
    },
    async createRecord(record) {
      created.push(record);
      return {
        id: `new-${nextId++}`,
        type: record.type,
        name: record.name,
        value: record.value,
      };
    },
    async deleteRecord(id: string) {
      deletedIds.push(id);
    },
  };
}

describe('provisionDns', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('creates all 3 records when everything is missing', async () => {
    mockCheckDns.mockResolvedValue(allMissing('example.com'));
    const provider = createMockProvider();

    const result = await provisionDns('example.com', provider);

    expect(result.domain).toBe('example.com');
    expect(result.created).toHaveLength(3);
    expect(result.deleted).toHaveLength(0);
    expect(result.skipped).toHaveLength(0);

    expect(provider.created).toEqual([
      { type: 'CNAME', name: 'rm.example.com', value: RULE_CNAME_TARGET },
      {
        type: 'CNAME',
        name: 'keyse._domainkey.example.com',
        value: RULE_DKIM_TARGET,
      },
      {
        type: 'TXT',
        name: '_dmarc.rm.example.com',
        value: RULE_DMARC_POLICY,
      },
    ]);
  });

  it('skips all records when everything passes', async () => {
    mockCheckDns.mockResolvedValue(allPassing('example.com'));
    const provider = createMockProvider();

    const result = await provisionDns('example.com', provider);

    expect(result.created).toHaveLength(0);
    expect(result.deleted).toHaveLength(0);
    expect(result.skipped).toHaveLength(3);
    expect(provider.created).toHaveLength(0);
  });

  it('deletes conflicting records before creating', async () => {
    mockCheckDns.mockResolvedValue(allMissing('example.com'));
    const existing = new Map<string, ProviderRecord[]>([
      [
        'rm.example.com',
        [
          { id: 'old-1', type: 'A', name: 'rm.example.com', value: '1.2.3.4' },
        ],
      ],
    ]);
    const provider = createMockProvider(existing);

    const result = await provisionDns('example.com', provider);

    expect(result.deleted).toHaveLength(1);
    expect(result.deleted[0]!.id).toBe('old-1');
    expect(provider.deletedIds).toEqual(['old-1']);
    expect(result.created).toHaveLength(3);
  });

  it('skips record if provider already has the correct one', async () => {
    mockCheckDns.mockResolvedValue(allMissing('example.com'));
    const existing = new Map<string, ProviderRecord[]>([
      [
        'rm.example.com',
        [
          {
            id: 'existing-cname',
            type: 'CNAME',
            name: 'rm.example.com',
            value: RULE_CNAME_TARGET,
          },
        ],
      ],
    ]);
    const provider = createMockProvider(existing);

    const result = await provisionDns('example.com', provider);

    // MX/SPF record already exists at provider → skipped (even though checkDns said missing)
    expect(result.created).toHaveLength(2);
    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0]!.name).toBe('rm.example.com');
    expect(provider.deletedIds).toHaveLength(0);
  });

  it('passes through warnings from checkDns', async () => {
    const warnings = [
      {
        code: 'STRICT_SPF_ALIGNMENT',
        severity: 'warning' as const,
        message: 'test warning',
      },
    ];
    mockCheckDns.mockResolvedValue({
      ...allMissing('example.com'),
      warnings,
    });
    const provider = createMockProvider();

    const result = await provisionDns('example.com', provider);

    expect(result.warnings).toEqual(warnings);
  });

  it('deletes multiple conflicting records at the same name', async () => {
    mockCheckDns.mockResolvedValue(allMissing('example.com'));
    const existing = new Map<string, ProviderRecord[]>([
      [
        'rm.example.com',
        [
          { id: 'old-a', type: 'A', name: 'rm.example.com', value: '1.2.3.4' },
          {
            id: 'old-txt',
            type: 'TXT',
            name: 'rm.example.com',
            value: 'v=spf1 -all',
          },
        ],
      ],
    ]);
    const provider = createMockProvider(existing);

    const result = await provisionDns('example.com', provider);

    expect(result.deleted).toHaveLength(2);
    expect(provider.deletedIds).toContain('old-a');
    expect(provider.deletedIds).toContain('old-txt');
  });
});
