import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';
import { hetzner, listHetznerZones } from '../../src/providers/hetzner.js';

const mockFetch = vi.fn();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal('fetch', mockFetch);
});

afterAll(() => {
  vi.unstubAllGlobals();
});

function hetznerOk<T>(body: T) {
  return {
    ok: true,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(''),
  };
}

function hetznerError(status: number, body: string) {
  return {
    ok: false,
    status,
    text: () => Promise.resolve(body),
  };
}

describe('hetzner', () => {
  it('throws if apiToken is missing', () => {
    expect(() => hetzner({ apiToken: '', zoneId: 'z1' })).toThrow(
      'apiToken is required'
    );
  });

  it('throws if neither zoneId nor domain is provided', () => {
    expect(() => hetzner({ apiToken: 'tok' })).toThrow(
      'either zoneId or domain is required'
    );
  });

  describe('with zoneId', () => {
    it('getRecords fetches and filters records by name', async () => {
      mockFetch.mockResolvedValueOnce(
        hetznerOk({
          records: [
            { id: 'r1', type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se', zone_id: 'z1', ttl: 300 },
            { id: 'r2', type: 'A', name: 'rm.example.com', value: '1.2.3.4', zone_id: 'z1', ttl: 300 },
            { id: 'r3', type: 'A', name: 'other.example.com', value: '5.6.7.8', zone_id: 'z1', ttl: 300 },
          ],
        })
      );

      const provider = hetzner({ apiToken: 'tok', zoneId: 'z1' });
      const records = await provider.getRecords('rm.example.com');

      expect(records).toEqual([
        { id: 'r1', type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se' },
        { id: 'r2', type: 'A', name: 'rm.example.com', value: '1.2.3.4' },
      ]);

      const [url, callInit] = mockFetch.mock.calls[0]!;
      const headers = callInit.headers as Headers;
      expect(headers.get('Auth-API-Token')).toBe('tok');
      expect(url).toBe('https://dns.hetzner.com/api/v1/records?zone_id=z1');
    });

    it('createRecord posts a new record', async () => {
      mockFetch.mockResolvedValueOnce(
        hetznerOk({
          record: {
            id: 'new-1',
            type: 'CNAME',
            name: 'rm.example.com',
            value: 'to.rulemailer.se',
            zone_id: 'z1',
            ttl: 300,
          },
        })
      );

      const provider = hetzner({ apiToken: 'tok', zoneId: 'z1' });
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
        'https://dns.hetzner.com/api/v1/records',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            zone_id: 'z1',
            type: 'CNAME',
            name: 'rm.example.com',
            value: 'to.rulemailer.se',
            ttl: 300,
          }),
        })
      );
    });

    it('deleteRecord sends DELETE request', async () => {
      mockFetch.mockResolvedValueOnce(hetznerOk({}));

      const provider = hetzner({ apiToken: 'tok', zoneId: 'z1' });
      await provider.deleteRecord('r1');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://dns.hetzner.com/api/v1/records/r1',
        expect.objectContaining({ method: 'DELETE' })
      );
    });

    it('throws on API error', async () => {
      mockFetch.mockResolvedValueOnce(hetznerError(403, 'Forbidden'));

      const provider = hetzner({ apiToken: 'bad-tok', zoneId: 'z1' });
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'Hetzner API error 403: Forbidden'
      );
    });
  });

  describe('with domain (auto-lookup)', () => {
    it('looks up zoneId from domain', async () => {
      mockFetch.mockResolvedValueOnce(
        hetznerOk({ zones: [{ id: 'auto-zone-1', name: 'example.com' }] })
      );
      mockFetch.mockResolvedValueOnce(hetznerOk({ records: [] }));

      const provider = hetzner({ apiToken: 'tok', domain: 'example.com' });
      await provider.getRecords('rm.example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://dns.hetzner.com/api/v1/zones?name=example.com',
        expect.anything()
      );
    });

    it('caches zoneId after first lookup', async () => {
      mockFetch.mockResolvedValueOnce(
        hetznerOk({ zones: [{ id: 'auto-zone-1', name: 'example.com' }] })
      );
      mockFetch.mockResolvedValueOnce(hetznerOk({ records: [] }));
      mockFetch.mockResolvedValueOnce(hetznerOk({ records: [] }));

      const provider = hetzner({ apiToken: 'tok', domain: 'example.com' });
      await provider.getRecords('rm.example.com');
      await provider.getRecords('_dmarc.rm.example.com');

      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('throws if no zone found for domain', async () => {
      mockFetch.mockResolvedValueOnce(hetznerOk({ zones: [] }));

      const provider = hetzner({ apiToken: 'tok', domain: 'nonexistent.com' });
      await expect(provider.getRecords('rm.nonexistent.com')).rejects.toThrow(
        'no zone found for domain "nonexistent.com"'
      );
    });
  });
});

describe('listHetznerZones', () => {
  it('returns all zones for the token', async () => {
    mockFetch.mockResolvedValueOnce(
      hetznerOk({
        zones: [
          { id: 'z1', name: 'example.com' },
          { id: 'z2', name: 'alright.se' },
        ],
      })
    );

    const zones = await listHetznerZones('tok');

    expect(zones).toEqual([
      { id: 'z1', name: 'example.com' },
      { id: 'z2', name: 'alright.se' },
    ]);
  });

  it('throws if apiToken is missing', async () => {
    await expect(listHetznerZones('')).rejects.toThrow(
      'apiToken is required'
    );
  });
});
