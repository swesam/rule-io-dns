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

function dsOk<T>(body: T) {
  return {
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
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
      'token is required'
    );
  });

  it('throws if secret is missing', () => {
    expect(() => domeneshop({ token: 't', secret: '', domainId: 1 })).toThrow(
      'secret is required'
    );
  });

  it('throws if neither domainId nor domain is provided', () => {
    expect(() => domeneshop({ token: 't', secret: 's' })).toThrow(
      'either domainId or domain is required'
    );
  });

  describe('with domainId and domain', () => {
    it('getRecords fetches records by relative host', async () => {
      mockFetch.mockResolvedValueOnce(
        dsOk([
          { id: 1, host: 'rm', type: 'CNAME', data: 'to.rulemailer.se', ttl: 3600 },
          { id: 2, host: 'rm', type: 'A', data: '1.2.3.4', ttl: 3600 },
        ])
      );

      const provider = domeneshop({ token: 't', secret: 's', domainId: 123, domain: 'example.com' });
      const records = await provider.getRecords('rm.example.com');

      expect(records).toEqual([
        { id: '1', type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se' },
        { id: '2', type: 'A', name: 'rm.example.com', value: '1.2.3.4' },
      ]);

      const [url, callInit] = mockFetch.mock.calls[0]!;
      const headers = callInit.headers as Headers;
      expect(headers.get('Authorization')).toMatch(/^Basic /);
      expect(url).toBe('https://api.domeneshop.no/v0/domains/123/dns?host=rm');
    });

    it('createRecord posts a new record', async () => {
      mockFetch.mockResolvedValueOnce(
        dsOk({
          id: 99,
          host: 'rm',
          type: 'CNAME',
          data: 'to.rulemailer.se',
          ttl: 3600,
        })
      );

      const provider = domeneshop({ token: 't', secret: 's', domainId: 123, domain: 'example.com' });
      const result = await provider.createRecord({
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se',
      });

      expect(result).toEqual({
        id: '99',
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se',
      });
    });

    it('deleteRecord sends DELETE request', async () => {
      mockFetch.mockResolvedValueOnce(dsNoContent());

      const provider = domeneshop({ token: 't', secret: 's', domainId: 123, domain: 'example.com' });
      await provider.deleteRecord('42');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.domeneshop.no/v0/domains/123/dns/42',
        expect.objectContaining({ method: 'DELETE' })
      );
    });

    it('throws on API error', async () => {
      mockFetch.mockResolvedValueOnce(dsError(403, 'Forbidden'));

      const provider = domeneshop({ token: 't', secret: 's', domainId: 123, domain: 'example.com' });
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'Domeneshop API error 403: Forbidden'
      );
    });
  });

  describe('with domain auto-lookup', () => {
    it('looks up domainId from domain name', async () => {
      mockFetch.mockResolvedValueOnce(
        dsOk([
          { id: 100, domain: 'example.com' },
          { id: 200, domain: 'other.com' },
        ])
      );
      mockFetch.mockResolvedValueOnce(dsOk([]));

      const provider = domeneshop({ token: 't', secret: 's', domain: 'example.com' });
      await provider.getRecords('rm.example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.domeneshop.no/v0/domains',
        expect.anything()
      );
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.domeneshop.no/v0/domains/100/dns?host=rm',
        expect.anything()
      );
    });

    it('caches domainId after first lookup', async () => {
      mockFetch.mockResolvedValueOnce(
        dsOk([{ id: 100, domain: 'example.com' }])
      );
      mockFetch.mockResolvedValueOnce(dsOk([]));
      mockFetch.mockResolvedValueOnce(dsOk([]));

      const provider = domeneshop({ token: 't', secret: 's', domain: 'example.com' });
      await provider.getRecords('rm.example.com');
      await provider.getRecords('_dmarc.rm.example.com');

      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('throws if no domain found', async () => {
      mockFetch.mockResolvedValueOnce(dsOk([]));

      const provider = domeneshop({ token: 't', secret: 's', domain: 'nonexistent.com' });
      await expect(provider.getRecords('rm.nonexistent.com')).rejects.toThrow(
        'no domain found for "nonexistent.com"'
      );
    });
  });
});

describe('listDomeneshopDomains', () => {
  it('returns all domains', async () => {
    mockFetch.mockResolvedValueOnce(
      dsOk([
        { id: 1, domain: 'example.com' },
        { id: 2, domain: 'alright.se' },
      ])
    );

    const domains = await listDomeneshopDomains('t', 's');

    expect(domains).toEqual([
      { id: 1, domain: 'example.com' },
      { id: 2, domain: 'alright.se' },
    ]);
  });

  it('throws if token/secret missing', async () => {
    await expect(listDomeneshopDomains('', 's')).rejects.toThrow(
      'token and secret are required'
    );
  });
});
