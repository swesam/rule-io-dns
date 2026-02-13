import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';
import { loopia } from '../../src/providers/loopia.js';

const mockFetch = vi.fn();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal('fetch', mockFetch);
});

afterAll(() => {
  vi.unstubAllGlobals();
});

function xmlRpcOk(value: string): { ok: true; text: () => Promise<string> } {
  return {
    ok: true,
    text: () =>
      Promise.resolve(
        `<?xml version="1.0"?><methodResponse><params><param><value><string>${value}</string></value></param></params></methodResponse>`
      ),
  };
}

function xmlRpcArray(
  records: { type: string; ttl: number; priority: number; rdata: string; record_id: number }[]
): { ok: true; text: () => Promise<string> } {
  const structs = records
    .map(
      (r) =>
        `<value><struct>` +
        `<member><name>type</name><value><string>${r.type}</string></value></member>` +
        `<member><name>ttl</name><value><int>${r.ttl}</int></value></member>` +
        `<member><name>priority</name><value><int>${r.priority}</int></value></member>` +
        `<member><name>rdata</name><value><string>${r.rdata}</string></value></member>` +
        `<member><name>record_id</name><value><int>${r.record_id}</int></value></member>` +
        `</struct></value>`
    )
    .join('');

  return {
    ok: true,
    text: () =>
      Promise.resolve(
        `<?xml version="1.0"?><methodResponse><params><param><value><array><data>${structs}</data></array></value></param></params></methodResponse>`
      ),
  };
}

function xmlRpcFault(code: number, message: string) {
  return {
    ok: true,
    text: () =>
      Promise.resolve(
        `<?xml version="1.0"?><methodResponse><fault><value><struct>` +
          `<member><name>faultCode</name><value><int>${code}</int></value></member>` +
          `<member><name>faultString</name><value><string>${message}</string></value></member>` +
          `</struct></value></fault></methodResponse>`
      ),
  };
}

function httpError(status: number, body: string) {
  return {
    ok: false,
    status,
    text: () => Promise.resolve(body),
  };
}

describe('loopia', () => {
  it('throws if username is missing', () => {
    expect(() =>
      loopia({ username: '', password: 'pass', domain: 'example.com' })
    ).toThrow('Loopia: username is required');
  });

  it('throws if password is missing', () => {
    expect(() =>
      loopia({ username: 'user', password: '', domain: 'example.com' })
    ).toThrow('Loopia: password is required');
  });

  it('throws if domain is missing', () => {
    expect(() =>
      loopia({ username: 'user', password: 'pass', domain: '' })
    ).toThrow('Loopia: domain is required');
  });

  describe('getRecords', () => {
    it('fetches records for a subdomain', async () => {
      mockFetch.mockResolvedValueOnce(
        xmlRpcArray([
          { type: 'CNAME', ttl: 300, priority: 0, rdata: 'to.rulemailer.se', record_id: 101 },
          { type: 'A', ttl: 300, priority: 0, rdata: '1.2.3.4', record_id: 102 },
        ])
      );

      const provider = loopia({ username: 'user', password: 'pass', domain: 'example.com' });
      const records = await provider.getRecords('rm.example.com');

      expect(records).toEqual([
        { id: 'rm:101', type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se' },
        { id: 'rm:102', type: 'A', name: 'rm.example.com', value: '1.2.3.4' },
      ]);

      const callBody = mockFetch.mock.calls[0]![1].body as string;
      expect(callBody).toContain('<methodName>getZoneRecords</methodName>');
      expect(callBody).toContain('<string>user</string>');
      expect(callBody).toContain('<string>pass</string>');
    });

    it('throws on error string response', async () => {
      mockFetch.mockResolvedValueOnce(xmlRpcOk('UNKNOWN_ERROR'));

      const provider = loopia({ username: 'user', password: 'pass', domain: 'example.com' });
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'Loopia: getZoneRecords failed: UNKNOWN_ERROR'
      );
    });

    it('throws on HTTP error', async () => {
      mockFetch.mockResolvedValueOnce(httpError(500, 'Internal Server Error'));

      const provider = loopia({ username: 'user', password: 'pass', domain: 'example.com' });
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'Loopia: API error 500: Internal Server Error'
      );
    });

    it('throws on XML-RPC fault', async () => {
      mockFetch.mockResolvedValueOnce(xmlRpcFault(403, 'AUTH_ERROR'));

      const provider = loopia({ username: 'user', password: 'pass', domain: 'example.com' });
      await expect(provider.getRecords('rm.example.com')).rejects.toThrow(
        'Loopia: XML-RPC fault 403: AUTH_ERROR'
      );
    });
  });

  describe('createRecord', () => {
    it('creates a record and returns the result', async () => {
      mockFetch.mockResolvedValueOnce(xmlRpcOk('OK'));
      mockFetch.mockResolvedValueOnce(
        xmlRpcArray([
          { type: 'CNAME', ttl: 300, priority: 0, rdata: 'to.rulemailer.se', record_id: 201 },
        ])
      );

      const provider = loopia({ username: 'user', password: 'pass', domain: 'example.com' });
      const result = await provider.createRecord({
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se',
      });

      expect(result).toEqual({
        id: 'rm:201',
        type: 'CNAME',
        name: 'rm.example.com',
        value: 'to.rulemailer.se',
      });

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('throws when addZoneRecord returns non-OK', async () => {
      mockFetch.mockResolvedValueOnce(xmlRpcOk('AUTH_ERROR'));

      const provider = loopia({ username: 'user', password: 'pass', domain: 'example.com' });
      await expect(
        provider.createRecord({ type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se' })
      ).rejects.toThrow('Loopia: addZoneRecord failed: AUTH_ERROR');
    });
  });

  describe('deleteRecord', () => {
    it('deletes a record by encoded id', async () => {
      mockFetch.mockResolvedValueOnce(xmlRpcOk('OK'));

      const provider = loopia({ username: 'user', password: 'pass', domain: 'example.com' });
      await provider.deleteRecord('rm:101');

      const callBody = mockFetch.mock.calls[0]![1].body as string;
      expect(callBody).toContain('<methodName>removeZoneRecord</methodName>');
      expect(callBody).toContain('<int>101</int>');
    });

    it('throws on invalid id format', async () => {
      const provider = loopia({ username: 'user', password: 'pass', domain: 'example.com' });
      await expect(provider.deleteRecord('invalid')).rejects.toThrow(
        'Loopia: invalid record id "invalid"'
      );
    });
  });
});
