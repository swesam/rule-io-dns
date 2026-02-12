import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';
import { ionos, listIonosZones } from '../../src/providers/ionos.js';

const mockFetch = vi.fn();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal('fetch', mockFetch);
});

afterAll(() => {
  vi.unstubAllGlobals();
});

function ionosOk<T>(body: T) {
  return {
    ok: true,
    text: () => Promise.resolve(JSON.stringify(body)),
  };
}

function ionosEmpty() {
  return {
    ok: true,
    text: () => Promise.resolve(''),
  };
}

function ionosError(status: number, body: string) {
  return {
    ok: false,
    status,
    text: () => Promise.resolve(body),
  };
}

describe('ionos', () => {
  it('throws if apiKey is missing', () => {
    expect(() => ionos({ apiKey: '', zoneId: 'z1' })).toThrow(
      'apiKey is required'
    );
  });

  it('throws if neither zoneId nor domain is provided', () => {
    expect(() => ionos({ apiKey: 'prefix.secret' })).toThrow(
      'either zoneId or domain is required'
    );
  });

  describe('with zoneId', () => {
    it('getRecords fetches zone and returns filtered records', async () => {
      mockFetch.mockResolvedValueOnce(
        ionosOk({
          id: 'z1',
          name: 'example.com',
          type: 'NATIVE',
          records: [
            { id: 'r1', name: 'rm.example.com', type: 'CNAME', content: 'to.rulemailer.se', ttl: 3600, prio: 0 },
            { id: 'r2', name: 'rm.example.com', type: 'A', content: '1.2.3.4', ttl: 3600, prio: 0 },
          ],
        })
      );

      const provider = ionos({ apiKey: 'prefix.secret', zoneId: 'z1' });
      const records = await provider.getRecords('rm.example.com');

      expect(records).toEqual([
        { id: 'r1', type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se' },
        { id: 'r2', type: 'A', name: 'rm.example.com', value: '1.2.3.4' },
      ]);

      const [url, callInit] = mockFetch.mock.calls[0]!;
      const headers = callInit.headers as Headers;
      expect(headers.get('X-API-Key')).toBe('prefix.secret');
      expect(headers.get('Content-Type')).toBe('application/json');
      expect(url).toBe(
        'https://dns.de.api.ionos.com/v1/zones/z1?recordName=rm.example.com&recordType='
      );
    });

    it('createRecord posts a new record array', async () => {
      mockFetch.mockResolvedValueOnce(
        ionosOk([
          {
            id: 'new-1',
            type: 'CNAME',
            name: 'rm.example.com',
            content: 'to.rulemailer.se',
            ttl: 3600,
            prio: 0,
          },
        ])
      );

      const provider = ionos({ apiKey: 'prefix.secret', zoneId: 'z1' });
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
        'https://dns.de.api.ionos.com/v1/zones/z1/records',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify([
            {
              name: 'rm.example.com',
              type: 'CNAME',
              content: 'to.rulemailer.se',
              ttl: 3600,
              prio: 0,
            },
          ]),
        })
      );
    });

    it('deleteRecord sends DELETE request', async () => {
      mockFetch.mockResolvedValueOnce(ionosEmpty());

      const provider = ionos({ apiKey: 'prefix.secret', zoneId: 'z1' });
      await provider.deleteRecord('r1');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://dns.de.api.ionos.com/v1/zones/z1/records/r1',
        expect.objectContaining({ method: 'DELETE' })
      );
    });

    it('throws on API error', async () => {
      mockFetch.mockResolvedValueOnce(ionosError(403, 'Forbidden'));

      const provider = ionos({ apiKey: 'bad-key', zoneId: 'z1' });
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'IONOS API error 403: Forbidden'
      );
    });
  });

  describe('with domain (auto-lookup)', () => {
    it('looks up zoneId from domain', async () => {
      // First call: list zones
      mockFetch.mockResolvedValueOnce(
        ionosOk([
          { id: 'z1', name: 'example.com', type: 'NATIVE' },
          { id: 'z2', name: 'other.com', type: 'NATIVE' },
        ])
      );
      // Second call: getRecords
      mockFetch.mockResolvedValueOnce(
        ionosOk({ id: 'z1', name: 'example.com', type: 'NATIVE', records: [] })
      );

      const provider = ionos({ apiKey: 'prefix.secret', domain: 'example.com' });
      await provider.getRecords('rm.example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://dns.de.api.ionos.com/v1/zones',
        expect.anything()
      );
    });

    it('caches zoneId after first lookup', async () => {
      mockFetch.mockResolvedValueOnce(
        ionosOk([{ id: 'z1', name: 'example.com', type: 'NATIVE' }])
      );
      mockFetch.mockResolvedValueOnce(
        ionosOk({ id: 'z1', name: 'example.com', type: 'NATIVE', records: [] })
      );
      mockFetch.mockResolvedValueOnce(
        ionosOk({ id: 'z1', name: 'example.com', type: 'NATIVE', records: [] })
      );

      const provider = ionos({ apiKey: 'prefix.secret', domain: 'example.com' });
      await provider.getRecords('rm.example.com');
      await provider.getRecords('_dmarc.rm.example.com');

      // 1 zone lookup + 2 getRecords = 3 total
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('throws if no zone found for domain', async () => {
      mockFetch.mockResolvedValueOnce(
        ionosOk([{ id: 'z1', name: 'other.com', type: 'NATIVE' }])
      );

      const provider = ionos({ apiKey: 'prefix.secret', domain: 'nonexistent.com' });
      await expect(provider.getRecords('rm.nonexistent.com')).rejects.toThrow(
        'no zone found for domain "nonexistent.com"'
      );
    });

    it('deduplicates concurrent zoneId lookups', async () => {
      let resolveZoneLookup!: (value: unknown) => void;
      mockFetch.mockImplementationOnce(
        () => new Promise((resolve) => { resolveZoneLookup = resolve; })
      );
      mockFetch.mockResolvedValue(
        ionosOk({ id: 'z1', name: 'example.com', type: 'NATIVE', records: [] })
      );

      const provider = ionos({ apiKey: 'prefix.secret', domain: 'example.com' });
      const p1 = provider.getRecords('rm.example.com');
      const p2 = provider.getRecords('_dmarc.rm.example.com');

      resolveZoneLookup(
        ionosOk([{ id: 'z1', name: 'example.com', type: 'NATIVE' }])
      );
      await Promise.all([p1, p2]);

      // 1 zone lookup + 2 getRecords = 3 total
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('normalizes domain input via cleanDomain', async () => {
      mockFetch.mockResolvedValueOnce(
        ionosOk([{ id: 'z1', name: 'example.com', type: 'NATIVE' }])
      );
      mockFetch.mockResolvedValueOnce(
        ionosOk({ id: 'z1', name: 'example.com', type: 'NATIVE', records: [] })
      );

      const provider = ionos({ apiKey: 'prefix.secret', domain: 'https://www.example.com/' });
      await provider.getRecords('rm.example.com');

      // Should have looked up zones (cleanDomain strips the URL parts)
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });
});

describe('listIonosZones', () => {
  it('returns all zones for the API key', async () => {
    mockFetch.mockResolvedValueOnce(
      ionosOk([
        { id: 'z1', name: 'example.com', type: 'NATIVE' },
        { id: 'z2', name: 'alright.se', type: 'NATIVE' },
      ])
    );

    const zones = await listIonosZones('prefix.secret');

    expect(zones).toEqual([
      { id: 'z1', name: 'example.com', type: 'NATIVE' },
      { id: 'z2', name: 'alright.se', type: 'NATIVE' },
    ]);
    expect(mockFetch).toHaveBeenCalledWith(
      'https://dns.de.api.ionos.com/v1/zones',
      expect.anything()
    );
  });

  it('returns empty array when no zones exist', async () => {
    mockFetch.mockResolvedValueOnce(ionosOk([]));

    const zones = await listIonosZones('prefix.secret');
    expect(zones).toEqual([]);
  });

  it('throws if apiKey is missing', async () => {
    await expect(listIonosZones('')).rejects.toThrow('apiKey is required');
  });
});
