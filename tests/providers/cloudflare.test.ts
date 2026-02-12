import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { cloudflare } from '../../src/providers/cloudflare.js';

const mockFetch = vi.fn();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal('fetch', mockFetch);
});

function cfResponse<T>(result: T) {
  return {
    ok: true,
    json: () => Promise.resolve({ success: true, errors: [], result }),
    text: () => Promise.resolve(''),
  };
}

function cfError(status: number, body: string) {
  return {
    ok: false,
    status,
    text: () => Promise.resolve(body),
  };
}

describe('cloudflare', () => {
  it('throws if apiToken is missing', () => {
    expect(() => cloudflare({ apiToken: '', zoneId: 'z1' })).toThrow(
      'apiToken is required'
    );
  });

  it('throws if neither zoneId nor domain is provided', () => {
    expect(() => cloudflare({ apiToken: 'tok' })).toThrow(
      'either zoneId or domain is required'
    );
  });

  describe('with zoneId', () => {
    it('getRecords fetches records by name', async () => {
      mockFetch.mockResolvedValueOnce(
        cfResponse([
          { id: 'r1', type: 'CNAME', name: 'rm.example.com', content: 'to.rulemailer.se' },
          { id: 'r2', type: 'A', name: 'rm.example.com', content: '1.2.3.4' },
        ])
      );

      const provider = cloudflare({ apiToken: 'tok', zoneId: 'z1' });
      const records = await provider.getRecords('rm.example.com');

      expect(records).toEqual([
        { id: 'r1', type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se' },
        { id: 'r2', type: 'A', name: 'rm.example.com', value: '1.2.3.4' },
      ]);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.cloudflare.com/client/v4/zones/z1/dns_records?name=rm.example.com',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer tok',
          }),
        })
      );
    });

    it('createRecord posts a new record', async () => {
      mockFetch.mockResolvedValueOnce(
        cfResponse({
          id: 'new-1',
          type: 'CNAME',
          name: 'rm.example.com',
          content: 'to.rulemailer.se',
        })
      );

      const provider = cloudflare({ apiToken: 'tok', zoneId: 'z1' });
      const result = await provider.createRecord({
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se',
      });

      expect(result).toEqual({
        id: 'new-1',
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se',
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.cloudflare.com/client/v4/zones/z1/dns_records',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            type: 'CNAME',
            name: 'rm.example.com',
            content: 'to.rulemailer.se',
          }),
        })
      );
    });

    it('deleteRecord sends DELETE request', async () => {
      mockFetch.mockResolvedValueOnce(cfResponse({ id: 'r1' }));

      const provider = cloudflare({ apiToken: 'tok', zoneId: 'z1' });
      await provider.deleteRecord('r1');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.cloudflare.com/client/v4/zones/z1/dns_records/r1',
        expect.objectContaining({ method: 'DELETE' })
      );
    });

    it('throws on API error', async () => {
      mockFetch.mockResolvedValueOnce(cfError(403, 'Forbidden'));

      const provider = cloudflare({ apiToken: 'bad-tok', zoneId: 'z1' });
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'Cloudflare API error 403: Forbidden'
      );
    });
  });

  describe('with domain (auto-lookup)', () => {
    it('looks up zoneId from domain', async () => {
      // First call: zone lookup
      mockFetch.mockResolvedValueOnce(
        cfResponse([{ id: 'auto-zone-1' }])
      );
      // Second call: actual getRecords
      mockFetch.mockResolvedValueOnce(cfResponse([]));

      const provider = cloudflare({ apiToken: 'tok', domain: 'example.com' });
      await provider.getRecords('rm.example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.cloudflare.com/client/v4/zones?name=example.com',
        expect.anything()
      );
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.cloudflare.com/client/v4/zones/auto-zone-1/dns_records?name=rm.example.com',
        expect.anything()
      );
    });

    it('caches zoneId after first lookup', async () => {
      mockFetch.mockResolvedValueOnce(
        cfResponse([{ id: 'auto-zone-1' }])
      );
      mockFetch.mockResolvedValueOnce(cfResponse([]));
      mockFetch.mockResolvedValueOnce(cfResponse([]));

      const provider = cloudflare({ apiToken: 'tok', domain: 'example.com' });
      await provider.getRecords('rm.example.com');
      await provider.getRecords('_dmarc.rm.example.com');

      // Zone lookup should happen only once (3 total calls, not 4)
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('throws if no zone found for domain', async () => {
      mockFetch.mockResolvedValueOnce(cfResponse([]));

      const provider = cloudflare({ apiToken: 'tok', domain: 'nonexistent.com' });
      await expect(provider.getRecords('rm.nonexistent.com')).rejects.toThrow(
        'no zone found for domain "nonexistent.com"'
      );
    });
  });
});
