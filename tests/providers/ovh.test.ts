import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';
import { createHash } from 'node:crypto';
import { ovh } from '../../src/providers/ovh.js';

const mockFetch = vi.fn();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal('fetch', mockFetch);
});

afterAll(() => {
  vi.unstubAllGlobals();
});

const baseOptions = {
  appKey: 'ak-123',
  appSecret: 'as-secret',
  consumerKey: 'ck-456',
  zoneName: 'example.com',
};

/** Stub the /auth/time response */
function mockTime(timestamp = 1700000000) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    json: () => Promise.resolve(timestamp),
    text: () => Promise.resolve(String(timestamp)),
  });
}

function okJson<T>(data: T) {
  return {
    ok: true,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  };
}

function okEmpty() {
  return {
    ok: true,
    json: () => Promise.resolve(undefined),
    text: () => Promise.resolve(''),
  };
}

function apiError(status: number, body: string) {
  return {
    ok: false,
    status,
    text: () => Promise.resolve(body),
  };
}

describe('ovh', () => {
  describe('validation', () => {
    it('throws if appKey is missing', () => {
      expect(() => ovh({ ...baseOptions, appKey: '' })).toThrow('OVH: appKey is required');
    });

    it('throws if appSecret is missing', () => {
      expect(() => ovh({ ...baseOptions, appSecret: '' })).toThrow('OVH: appSecret is required');
    });

    it('throws if consumerKey is missing', () => {
      expect(() => ovh({ ...baseOptions, consumerKey: '' })).toThrow('OVH: consumerKey is required');
    });

    it('throws if zoneName is missing', () => {
      expect(() => ovh({ ...baseOptions, zoneName: '' })).toThrow('OVH: zoneName is required');
    });
  });

  describe('signature generation', () => {
    it('sends correct OVH authentication headers', async () => {
      const timestamp = 1700000000;
      mockTime(timestamp);
      mockFetch.mockResolvedValueOnce(okJson([]));

      const provider = ovh(baseOptions);
      await provider.getRecords('rm.example.com');

      // Second call is the actual API call (first is /auth/time)
      const [url, init] = mockFetch.mock.calls[1]!;
      const headers = init.headers as Record<string, string>;

      expect(headers['X-Ovh-Application']).toBe('ak-123');
      expect(headers['X-Ovh-Consumer']).toBe('ck-456');
      expect(headers['X-Ovh-Timestamp']).toBe(String(timestamp));

      // Verify signature
      const expectedUrl = url as string;
      const raw = `as-secret+ck-456+GET+${expectedUrl}++${timestamp}`;
      const expectedSig = `$1$${createHash('sha1').update(raw).digest('hex')}`;
      expect(headers['X-Ovh-Signature']).toBe(expectedSig);
    });
  });

  describe('subdomain conversion', () => {
    it('converts FQDN to relative subdomain for queries', async () => {
      mockTime();
      mockFetch.mockResolvedValueOnce(okJson([]));

      const provider = ovh(baseOptions);
      await provider.getRecords('rm.example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://eu.api.ovh.com/1.0/domain/zone/example.com/record?subDomain=rm',
        expect.anything()
      );
    });

    it('handles apex domain (zoneName == name)', async () => {
      mockTime();
      mockFetch.mockResolvedValueOnce(okJson([]));

      const provider = ovh(baseOptions);
      await provider.getRecords('example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://eu.api.ovh.com/1.0/domain/zone/example.com/record?subDomain=',
        expect.anything()
      );
    });

    it('handles deep subdomain', async () => {
      mockTime();
      mockFetch.mockResolvedValueOnce(okJson([]));

      const provider = ovh(baseOptions);
      await provider.getRecords('_dmarc.rm.example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://eu.api.ovh.com/1.0/domain/zone/example.com/record?subDomain=_dmarc.rm',
        expect.anything()
      );
    });
  });

  describe('getRecords', () => {
    it('fetches record IDs then each record detail', async () => {
      // auth/time for listing IDs
      mockTime();
      // GET record IDs
      mockFetch.mockResolvedValueOnce(okJson([101, 102]));
      // auth/time for record 101
      mockTime();
      // GET record 101 detail
      mockFetch.mockResolvedValueOnce(
        okJson({
          id: 101,
          fieldType: 'CNAME',
          subDomain: 'rm',
          target: 'to.rulemailer.se',
          ttl: 3600,
          zone: 'example.com',
        })
      );
      // auth/time for record 102
      mockTime();
      // GET record 102 detail
      mockFetch.mockResolvedValueOnce(
        okJson({
          id: 102,
          fieldType: 'A',
          subDomain: 'rm',
          target: '1.2.3.4',
          ttl: 3600,
          zone: 'example.com',
        })
      );

      const provider = ovh(baseOptions);
      const records = await provider.getRecords('rm.example.com');

      expect(records).toEqual([
        { id: '101', type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se' },
        { id: '102', type: 'A', name: 'rm.example.com', value: '1.2.3.4' },
      ]);
    });

    it('returns empty array when no records exist', async () => {
      mockTime();
      mockFetch.mockResolvedValueOnce(okJson([]));

      const provider = ovh(baseOptions);
      const records = await provider.getRecords('nonexistent.example.com');

      expect(records).toEqual([]);
    });
  });

  describe('createRecord', () => {
    it('creates a record and refreshes the zone', async () => {
      // auth/time for POST record
      mockTime();
      // POST create
      mockFetch.mockResolvedValueOnce(
        okJson({
          id: 201,
          fieldType: 'CNAME',
          subDomain: 'rm',
          target: 'to.rulemailer.se',
          ttl: 3600,
          zone: 'example.com',
        })
      );
      // auth/time for POST refresh
      mockTime();
      // POST refresh
      mockFetch.mockResolvedValueOnce(okEmpty());

      const provider = ovh(baseOptions);
      const result = await provider.createRecord({
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se',
      });

      expect(result).toEqual({
        id: '201',
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se',
      });

      // Verify POST body for create call (3rd call: time, create, time, refresh)
      const [createUrl, createInit] = mockFetch.mock.calls[1]!;
      expect(createUrl).toBe(
        'https://eu.api.ovh.com/1.0/domain/zone/example.com/record'
      );
      expect(createInit.method).toBe('POST');
      expect(JSON.parse(createInit.body)).toEqual({
        fieldType: 'CNAME',
        subDomain: 'rm',
        target: 'to.rulemailer.se',
        ttl: 3600,
      });

      // Verify refresh call
      const [refreshUrl, refreshInit] = mockFetch.mock.calls[3]!;
      expect(refreshUrl).toBe(
        'https://eu.api.ovh.com/1.0/domain/zone/example.com/refresh'
      );
      expect(refreshInit.method).toBe('POST');
    });
  });

  describe('deleteRecord', () => {
    it('deletes a record and refreshes the zone', async () => {
      // auth/time for DELETE
      mockTime();
      // DELETE record
      mockFetch.mockResolvedValueOnce(okEmpty());
      // auth/time for refresh
      mockTime();
      // POST refresh
      mockFetch.mockResolvedValueOnce(okEmpty());

      const provider = ovh(baseOptions);
      await provider.deleteRecord('301');

      const [deleteUrl, deleteInit] = mockFetch.mock.calls[1]!;
      expect(deleteUrl).toBe(
        'https://eu.api.ovh.com/1.0/domain/zone/example.com/record/301'
      );
      expect(deleteInit.method).toBe('DELETE');

      const [refreshUrl, refreshInit] = mockFetch.mock.calls[3]!;
      expect(refreshUrl).toBe(
        'https://eu.api.ovh.com/1.0/domain/zone/example.com/refresh'
      );
      expect(refreshInit.method).toBe('POST');
    });
  });

  describe('error handling', () => {
    it('throws on API error', async () => {
      mockTime();
      mockFetch.mockResolvedValueOnce(apiError(403, 'This application key is invalid'));

      const provider = ovh(baseOptions);
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'OVH: API error 403: This application key is invalid'
      );
    });

    it('throws when server time request fails', async () => {
      mockFetch.mockResolvedValueOnce(apiError(500, 'Internal Server Error'));

      const provider = ovh(baseOptions);
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'OVH: failed to get server time: 500 Internal Server Error'
      );
    });
  });
});
