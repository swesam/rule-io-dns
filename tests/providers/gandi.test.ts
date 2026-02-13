import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';
import { gandi, listGandiDomains } from '../../src/providers/gandi.js';

const mockFetch = vi.fn();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal('fetch', mockFetch);
});

afterAll(() => {
  vi.unstubAllGlobals();
});

function gandiOk<T>(result: T) {
  return {
    ok: true,
    json: () => Promise.resolve(result),
    text: () => Promise.resolve(''),
  };
}

function gandiError(status: number, body: string) {
  return {
    ok: false,
    status,
    text: () => Promise.resolve(body),
  };
}

describe('gandi', () => {
  it('throws if apiToken is missing', () => {
    expect(() => gandi({ apiToken: '', domain: 'example.com' })).toThrow(
      'Gandi: apiToken is required'
    );
  });

  it('throws if domain is missing', () => {
    expect(() => gandi({ apiToken: 'tok', domain: '' })).toThrow(
      'Gandi: domain is required'
    );
  });

  describe('getRecords', () => {
    it('fetches records by relative name', async () => {
      mockFetch.mockResolvedValueOnce(
        gandiOk([
          {
            rrset_name: 'rm',
            rrset_type: 'CNAME',
            rrset_ttl: 300,
            rrset_values: ['to.rulemailer.se.'],
          },
        ])
      );

      const provider = gandi({ apiToken: 'tok', domain: 'example.com' });
      const records = await provider.getRecords('rm.example.com');

      expect(records).toEqual([
        { id: 'rm/CNAME/to.rulemailer.se.', type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se.' },
      ]);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.gandi.net/v5/livedns/domains/example.com/records/rm',
        expect.anything()
      );

      const [, callInit] = mockFetch.mock.calls[0]!;
      const headers = callInit.headers as Headers;
      expect(headers.get('Authorization')).toBe('Bearer tok');
    });

    it('converts apex domain to @ relative name', async () => {
      mockFetch.mockResolvedValueOnce(
        gandiOk([
          {
            rrset_name: '@',
            rrset_type: 'MX',
            rrset_ttl: 300,
            rrset_values: ['10 mail.example.com.'],
          },
        ])
      );

      const provider = gandi({ apiToken: 'tok', domain: 'example.com' });
      const records = await provider.getRecords('example.com');

      expect(records).toEqual([
        { id: '@/MX/10 mail.example.com.', type: 'MX', name: 'example.com', value: '10 mail.example.com.' },
      ]);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.gandi.net/v5/livedns/domains/example.com/records/%40',
        expect.anything()
      );
    });

    it('flattens rrsets with multiple values into unique IDs', async () => {
      mockFetch.mockResolvedValueOnce(
        gandiOk([
          {
            rrset_name: '@',
            rrset_type: 'TXT',
            rrset_ttl: 300,
            rrset_values: ['"v=spf1 ~all"', '"verification=abc"'],
          },
        ])
      );

      const provider = gandi({ apiToken: 'tok', domain: 'example.com' });
      const records = await provider.getRecords('example.com');

      expect(records).toHaveLength(2);
      expect(records[0]!.id).toBe('@/TXT/"v=spf1 ~all"');
      expect(records[1]!.id).toBe('@/TXT/"verification=abc"');
    });

    it('returns empty array on 404', async () => {
      mockFetch.mockResolvedValueOnce(gandiError(404, 'Not Found'));

      const provider = gandi({ apiToken: 'tok', domain: 'example.com' });
      const records = await provider.getRecords('nonexistent.example.com');

      expect(records).toEqual([]);
    });

    it('throws on non-404 API error', async () => {
      mockFetch.mockResolvedValueOnce(gandiError(403, 'Forbidden'));

      const provider = gandi({ apiToken: 'bad-tok', domain: 'example.com' });
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'Gandi API error 403: Forbidden'
      );
    });
  });

  describe('createRecord', () => {
    it('posts a new rrset', async () => {
      mockFetch.mockResolvedValueOnce(gandiOk({ message: 'DNS Record Created' }));

      const provider = gandi({ apiToken: 'tok', domain: 'example.com' });
      const result = await provider.createRecord({
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se.',
      });

      expect(result).toEqual({
        id: 'rm/CNAME/to.rulemailer.se.',
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se.',
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.gandi.net/v5/livedns/domains/example.com/records',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            rrset_name: 'rm',
            rrset_type: 'CNAME',
            rrset_ttl: 300,
            rrset_values: ['to.rulemailer.se.'],
          }),
        })
      );
    });
  });

  describe('deleteRecord', () => {
    it('deletes rrset when it is the only value', async () => {
      // GET rrset returns single value
      mockFetch.mockResolvedValueOnce(
        gandiOk({
          rrset_name: 'rm',
          rrset_type: 'CNAME',
          rrset_ttl: 300,
          rrset_values: ['to.rulemailer.se.'],
        })
      );
      // DELETE rrset
      mockFetch.mockResolvedValueOnce(gandiOk(null));

      const provider = gandi({ apiToken: 'tok', domain: 'example.com' });
      await provider.deleteRecord('rm/CNAME/to.rulemailer.se.');

      // First call: GET rrset to check values
      expect(mockFetch.mock.calls[0]![0]).toBe(
        'https://api.gandi.net/v5/livedns/domains/example.com/records/rm/CNAME'
      );
      // Second call: DELETE the entire rrset
      expect(mockFetch.mock.calls[1]![0]).toBe(
        'https://api.gandi.net/v5/livedns/domains/example.com/records/rm/CNAME'
      );
      expect(mockFetch.mock.calls[1]![1]).toEqual(
        expect.objectContaining({ method: 'DELETE' })
      );
    });

    it('updates rrset when other values remain', async () => {
      // GET rrset returns two values
      mockFetch.mockResolvedValueOnce(
        gandiOk({
          rrset_name: '@',
          rrset_type: 'TXT',
          rrset_ttl: 300,
          rrset_values: ['"v=spf1 ~all"', '"verification=abc"'],
        })
      );
      // PUT updated rrset
      mockFetch.mockResolvedValueOnce(gandiOk(null));

      const provider = gandi({ apiToken: 'tok', domain: 'example.com' });
      await provider.deleteRecord('@/TXT/"v=spf1 ~all"');

      // Second call: PUT with remaining value
      expect(mockFetch.mock.calls[1]![1]).toEqual(
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify({
            rrset_ttl: 300,
            rrset_values: ['"verification=abc"'],
          }),
        })
      );
    });

    it('throws on invalid record id', async () => {
      const provider = gandi({ apiToken: 'tok', domain: 'example.com' });
      await expect(provider.deleteRecord('invalid')).rejects.toThrow(
        'Gandi: invalid record id "invalid"'
      );
    });
  });
});

describe('listGandiDomains', () => {
  it('returns all domains', async () => {
    mockFetch.mockResolvedValueOnce(
      gandiOk([{ fqdn: 'example.com' }, { fqdn: 'alright.se' }])
    );

    const domains = await listGandiDomains('tok');

    expect(domains).toEqual([
      { fqdn: 'example.com' },
      { fqdn: 'alright.se' },
    ]);
  });

  it('throws if apiToken is missing', async () => {
    await expect(listGandiDomains('')).rejects.toThrow(
      'Gandi: apiToken is required'
    );
  });
});
