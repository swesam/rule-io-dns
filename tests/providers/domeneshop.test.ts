import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';
import { domeneshop, listDomeneshopDomains } from '../../src/providers/domeneshop.js';

const mockFetch = vi.fn();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal('fetch', mockFetch);
});

afterAll(() => {
  vi.unstubAllGlobals();
});

function dsResponse<T>(result: T, status = 200) {
  return {
    ok: true,
    status,
    json: () => Promise.resolve(result),
    text: () => Promise.resolve(''),
  };
}

function dsNoContent() {
  return {
    ok: true,
    status: 204,
    json: () => Promise.resolve(undefined),
    text: () => Promise.resolve(''),
  };
}

function dsError(status: number, body: string) {
  return {
    ok: false,
    status,
    text: () => Promise.resolve(body),
  };
}

describe('domeneshop', () => {
  it('throws if token is missing', () => {
    expect(() => domeneshop({ token: '', secret: 's', domainId: 1 })).toThrow(
      'Domeneshop: token is required'
    );
  });

  it('throws if secret is missing', () => {
    expect(() => domeneshop({ token: 't', secret: '', domainId: 1 })).toThrow(
      'Domeneshop: secret is required'
    );
  });

  it('throws if neither domainId nor domain is provided', () => {
    expect(() => domeneshop({ token: 't', secret: 's' })).toThrow(
      'Domeneshop: either domainId or domain is required'
    );
  });

  describe('with domainId', () => {
    it('getRecords fetches records by host', async () => {
      // First call: domain name lookup
      mockFetch.mockResolvedValueOnce(
        dsResponse([{ id: 123, domain: 'example.com' }])
      );
      // Second call: actual getRecords
      mockFetch.mockResolvedValueOnce(
        dsResponse([
          { id: 1, host: 'rm', type: 'CNAME', data: 'to.rulemailer.se', ttl: 3600 },
          { id: 2, host: 'rm', type: 'A', data: '1.2.3.4', ttl: 3600 },
        ])
      );

      const provider = domeneshop({ token: 't', secret: 's', domainId: 123 });
      const records = await provider.getRecords('rm.example.com');

      expect(records).toEqual([
        { id: '1', type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se' },
        { id: '2', type: 'A', name: 'rm.example.com', value: '1.2.3.4' },
      ]);

      const [url, callInit] = mockFetch.mock.calls[1]!;
      const headers = callInit.headers as Headers;
      expect(headers.get('Authorization')).toBe(`Basic ${btoa('t:s')}`);
      expect(headers.get('Content-Type')).toBe('application/json');
      expect(url).toBe(
        'https://api.domeneshop.no/v0/domains/123/dns?host=rm'
      );
    });

    it('createRecord posts a new record', async () => {
      // Domain name lookup
      mockFetch.mockResolvedValueOnce(
        dsResponse([{ id: 123, domain: 'example.com' }])
      );
      // Create record
      mockFetch.mockResolvedValueOnce(
        dsResponse({
          id: 10,
          host: 'rm',
          type: 'CNAME',
          data: 'to.rulemailer.se',
          ttl: 3600,
        })
      );

      const provider = domeneshop({ token: 't', secret: 's', domainId: 123 });
      const result = await provider.createRecord({
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se',
      });

      expect(result).toEqual({
        id: '10',
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se',
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.domeneshop.no/v0/domains/123/dns',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            host: 'rm',
            type: 'CNAME',
            data: 'to.rulemailer.se',
            ttl: 3600,
          }),
        })
      );
    });

    it('deleteRecord sends DELETE request', async () => {
      mockFetch.mockResolvedValueOnce(dsNoContent());

      const provider = domeneshop({ token: 't', secret: 's', domainId: 123 });
      await provider.deleteRecord('5');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.domeneshop.no/v0/domains/123/dns/5',
        expect.objectContaining({ method: 'DELETE' })
      );
    });

    it('throws on API error', async () => {
      // Domain name lookup
      mockFetch.mockResolvedValueOnce(
        dsResponse([{ id: 123, domain: 'example.com' }])
      );
      // Error response
      mockFetch.mockResolvedValueOnce(dsError(403, 'Forbidden'));

      const provider = domeneshop({ token: 't', secret: 's', domainId: 123 });
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'Domeneshop API error 403: Forbidden'
      );
    });

    it('converts apex domain to @ host', async () => {
      // Domain name lookup
      mockFetch.mockResolvedValueOnce(
        dsResponse([{ id: 123, domain: 'example.com' }])
      );
      // getRecords
      mockFetch.mockResolvedValueOnce(
        dsResponse([
          { id: 3, host: '@', type: 'A', data: '1.2.3.4', ttl: 3600 },
        ])
      );

      const provider = domeneshop({ token: 't', secret: 's', domainId: 123 });
      const records = await provider.getRecords('example.com');

      expect(records).toEqual([
        { id: '3', type: 'A', name: 'example.com', value: '1.2.3.4' },
      ]);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.domeneshop.no/v0/domains/123/dns?host=%40',
        expect.anything()
      );
    });

    it('converts record IDs from number to string', async () => {
      mockFetch.mockResolvedValueOnce(
        dsResponse([{ id: 123, domain: 'example.com' }])
      );
      mockFetch.mockResolvedValueOnce(
        dsResponse([
          { id: 42, host: 'rm', type: 'TXT', data: 'v=spf1', ttl: 3600 },
        ])
      );

      const provider = domeneshop({ token: 't', secret: 's', domainId: 123 });
      const records = await provider.getRecords('rm.example.com');

      expect(records[0]!.id).toBe('42');
      expect(typeof records[0]!.id).toBe('string');
    });
  });

  describe('with domain (auto-lookup)', () => {
    it('looks up domainId from domain name', async () => {
      // Domain list lookup
      mockFetch.mockResolvedValueOnce(
        dsResponse([
          { id: 100, domain: 'other.com' },
          { id: 200, domain: 'example.com' },
        ])
      );
      // getRecords
      mockFetch.mockResolvedValueOnce(dsResponse([]));

      const provider = domeneshop({ token: 't', secret: 's', domain: 'example.com' });
      await provider.getRecords('rm.example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.domeneshop.no/v0/domains',
        expect.anything()
      );
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.domeneshop.no/v0/domains/200/dns?host=rm',
        expect.anything()
      );
    });

    it('caches domainId after first lookup', async () => {
      mockFetch.mockResolvedValueOnce(
        dsResponse([{ id: 200, domain: 'example.com' }])
      );
      mockFetch.mockResolvedValueOnce(dsResponse([]));
      mockFetch.mockResolvedValueOnce(dsResponse([]));

      const provider = domeneshop({ token: 't', secret: 's', domain: 'example.com' });
      await provider.getRecords('rm.example.com');
      await provider.getRecords('_dmarc.rm.example.com');

      // Domain lookup should happen only once (3 total calls, not 4)
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('throws if no domain found', async () => {
      mockFetch.mockResolvedValueOnce(dsResponse([]));

      const provider = domeneshop({ token: 't', secret: 's', domain: 'nonexistent.com' });
      await expect(provider.getRecords('rm.nonexistent.com')).rejects.toThrow(
        'Domeneshop: no domain found for "nonexistent.com"'
      );
    });

    it('deduplicates concurrent domainId lookups', async () => {
      let resolveDomainLookup!: (value: unknown) => void;
      mockFetch.mockImplementationOnce(
        () => new Promise((resolve) => { resolveDomainLookup = resolve; })
      );
      mockFetch.mockResolvedValue(dsResponse([]));

      const provider = domeneshop({ token: 't', secret: 's', domain: 'example.com' });
      const p1 = provider.getRecords('rm.example.com');
      const p2 = provider.getRecords('_dmarc.rm.example.com');

      resolveDomainLookup(dsResponse([{ id: 200, domain: 'example.com' }]));
      await Promise.all([p1, p2]);

      // 1 domain lookup + 2 getRecords = 3 total
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('normalizes domain input via cleanDomain', async () => {
      mockFetch.mockResolvedValueOnce(
        dsResponse([{ id: 200, domain: 'example.com' }])
      );
      mockFetch.mockResolvedValueOnce(dsResponse([]));

      const provider = domeneshop({ token: 't', secret: 's', domain: 'https://www.example.com/' });
      await provider.getRecords('rm.example.com');

      // Should match against cleaned domain "example.com"
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.domeneshop.no/v0/domains/200/dns?host=rm',
        expect.anything()
      );
    });
  });
});

describe('listDomeneshopDomains', () => {
  it('returns all domains for the credentials', async () => {
    mockFetch.mockResolvedValueOnce(
      dsResponse([
        { id: 1, domain: 'example.com', extra: 'ignored' },
        { id: 2, domain: 'alright.se', extra: 'ignored' },
      ])
    );

    const domains = await listDomeneshopDomains('t', 's');

    expect(domains).toEqual([
      { id: 1, domain: 'example.com' },
      { id: 2, domain: 'alright.se' },
    ]);
    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.domeneshop.no/v0/domains',
      expect.anything()
    );
  });

  it('returns empty array when no domains exist', async () => {
    mockFetch.mockResolvedValueOnce(dsResponse([]));

    const domains = await listDomeneshopDomains('t', 's');

    expect(domains).toEqual([]);
  });

  it('throws if token or secret is missing', async () => {
    await expect(listDomeneshopDomains('', 's')).rejects.toThrow(
      'Domeneshop: token and secret are required'
    );
    await expect(listDomeneshopDomains('t', '')).rejects.toThrow(
      'Domeneshop: token and secret are required'
    );
  });
});
