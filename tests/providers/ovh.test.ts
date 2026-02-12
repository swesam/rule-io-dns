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

      const [url, init] = mockFetch.mock.calls[1]!;
      const headers = init.headers as Record<string, string>;

      expect(headers['X-Ovh-Application']).toBe('ak-123');
      expect(headers['X-Ovh-Consumer']).toBe('ck-456');
      expect(headers['X-Ovh-Timestamp']).toBe(String(timestamp));

      const expectedUrl = url as string;
      const raw = `as-secret+ck-456+GET+${expectedUrl}++${timestamp}`;
      const expectedSig = `$1$${createHash('sha1').update(raw).digest('hex')}`;
      expect(headers['X-Ovh-Signature']).toBe(expectedSig);
    });
  });

  describe('getRecords', () => {
    it('fetches record IDs then each record detail', async () => {
      mockTime();
      mockFetch.mockResolvedValueOnce(okJson([101, 102]));
      mockTime();
      mockFetch.mockResolvedValueOnce(
        okJson({
          id: 101, fieldType: 'CNAME', subDomain: 'rm',
          target: 'to.rulemailer.se', ttl: 3600, zone: 'example.com',
        })
      );
      mockTime();
      mockFetch.mockResolvedValueOnce(
        okJson({
          id: 102, fieldType: 'A', subDomain: 'rm',
          target: '1.2.3.4', ttl: 3600, zone: 'example.com',
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
      mockTime();
      mockFetch.mockResolvedValueOnce(
        okJson({
          id: 201, fieldType: 'CNAME', subDomain: 'rm',
          target: 'to.rulemailer.se', ttl: 3600, zone: 'example.com',
        })
      );
      mockTime();
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

      // Verify refresh was called
      const [refreshUrl] = mockFetch.mock.calls[3]!;
      expect(refreshUrl).toBe(
        'https://eu.api.ovh.com/1.0/domain/zone/example.com/refresh'
      );
    });
  });

  describe('deleteRecord', () => {
    it('deletes a record and refreshes the zone', async () => {
      mockTime();
      mockFetch.mockResolvedValueOnce(okEmpty());
      mockTime();
      mockFetch.mockResolvedValueOnce(okEmpty());

      const provider = ovh(baseOptions);
      await provider.deleteRecord('301');

      const [deleteUrl] = mockFetch.mock.calls[1]!;
      expect(deleteUrl).toBe(
        'https://eu.api.ovh.com/1.0/domain/zone/example.com/record/301'
      );
    });
  });

  describe('error handling', () => {
    it('throws on API error', async () => {
      mockTime();
      mockFetch.mockResolvedValueOnce(apiError(403, 'Invalid key'));

      const provider = ovh(baseOptions);
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'OVH: API error 403: Invalid key'
      );
    });

    it('throws when server time request fails', async () => {
      mockFetch.mockResolvedValueOnce(apiError(500, 'Internal Server Error'));

      const provider = ovh(baseOptions);
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'OVH: failed to get server time'
      );
    });
  });
});
