import { describe, it, expect, vi, beforeEach } from 'vitest';
import dns from 'node:dns';
import { checkDns } from '../src/check-dns.js';
import {
  RULE_CNAME_TARGET,
  RULE_DKIM_TARGET,
  RULE_MX_HOST,
} from '../src/constants.js';

vi.mock('node:dns', () => {
  const mockPromises = {
    resolveNs: vi.fn(),
    resolveMx: vi.fn(),
    resolveCname: vi.fn(),
    resolveTxt: vi.fn(),
    resolve4: vi.fn(),
  };
  return {
    default: { promises: mockPromises },
    promises: mockPromises,
  };
});

const mockDns = dns.promises as unknown as {
  resolveNs: ReturnType<typeof vi.fn>;
  resolveMx: ReturnType<typeof vi.fn>;
  resolveCname: ReturnType<typeof vi.fn>;
  resolveTxt: ReturnType<typeof vi.fn>;
  resolve4: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
  vi.clearAllMocks();
  // Default: no A records exist (prevents CNAME conflict warnings)
  mockDns.resolve4.mockRejectedValue(new Error('ENOTFOUND'));
});

describe('checkDns', () => {
  it('returns allPassed: true when all records are correct', async () => {
    mockDns.resolveNs.mockResolvedValue(['ns1.example.com', 'ns2.example.com']);
    mockDns.resolveMx.mockResolvedValue([
      { exchange: RULE_MX_HOST, priority: 10 },
    ]);
    // SPF: CNAME check succeeds
    mockDns.resolveCname.mockImplementation((domain: string) => {
      if (domain === 'rm.example.com')
        return Promise.resolve([RULE_CNAME_TARGET]);
      if (domain === 'keyse._domainkey.example.com')
        return Promise.resolve([RULE_DKIM_TARGET]);
      return Promise.reject(new Error('ENOTFOUND'));
    });
    mockDns.resolveTxt.mockImplementation((domain: string) => {
      if (domain === '_dmarc.example.com')
        return Promise.resolve([
          [
            'v=DMARC1; p=none; rua=mailto:dmarc@rule.se; ruf=mailto:authfail@rule.se',
          ],
        ]);
      return Promise.reject(new Error('ENOTFOUND'));
    });

    const result = await checkDns('example.com');

    expect(result.domain).toBe('example.com');
    expect(result.allPassed).toBe(true);
    expect(result.checks.ns.status).toBe('pass');
    expect(result.checks.mx.status).toBe('pass');
    expect(result.checks.spf.status).toBe('pass');
    expect(result.checks.dkim.status).toBe('pass');
    expect(result.checks.dmarc.status).toBe('pass');
  });

  it('cleans domain from email input', async () => {
    mockDns.resolveNs.mockRejectedValue(new Error('ENOTFOUND'));
    mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
    mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
    mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));

    const result = await checkDns('user@example.com');
    expect(result.domain).toBe('example.com');
  });

  describe('NS check', () => {
    it('returns pass when nameservers exist', async () => {
      mockDns.resolveNs.mockResolvedValue(['ns1.dns.com']);
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));

      const result = await checkDns('example.com');
      expect(result.checks.ns.status).toBe('pass');
      expect(result.checks.ns.actual).toEqual(['ns1.dns.com']);
    });

    it('returns missing when no nameservers found', async () => {
      mockDns.resolveNs.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));

      const result = await checkDns('example.com');
      expect(result.checks.ns.status).toBe('missing');
    });
  });

  describe('MX check', () => {
    beforeEach(() => {
      mockDns.resolveNs.mockResolvedValue(['ns1.dns.com']);
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));
    });

    it('returns pass when MX points to rule host', async () => {
      mockDns.resolveMx.mockResolvedValue([
        { exchange: RULE_MX_HOST, priority: 10 },
      ]);
      mockDns.resolveCname.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve([RULE_CNAME_TARGET]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.checks.mx.status).toBe('pass');
    });

    it('returns fail when MX points elsewhere', async () => {
      mockDns.resolveMx.mockResolvedValue([
        { exchange: 'mail.other.com', priority: 10 },
      ]);
      mockDns.resolveCname.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve([RULE_CNAME_TARGET]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.checks.mx.status).toBe('fail');
    });

    it('falls back to CNAME check when MX lookup fails', async () => {
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveCname.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve([RULE_CNAME_TARGET]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.checks.mx.status).toBe('pass');
    });

    it('returns missing when both MX and CNAME fail', async () => {
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));

      const result = await checkDns('example.com');
      expect(result.checks.mx.status).toBe('missing');
    });
  });

  describe('SPF check', () => {
    beforeEach(() => {
      mockDns.resolveNs.mockResolvedValue(['ns1.dns.com']);
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
    });

    it('returns pass when CNAME points to rule target', async () => {
      mockDns.resolveCname.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve([RULE_CNAME_TARGET]);
        return Promise.reject(new Error('ENOTFOUND'));
      });
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));

      const result = await checkDns('example.com');
      expect(result.checks.spf.status).toBe('pass');
    });

    it('returns pass when TXT includes rulemailer SPF', async () => {
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve([
            ['v=spf1 include:spf.rulemailer.se ~all'],
          ]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.checks.spf.status).toBe('pass');
    });

    it('returns fail when SPF exists but without rulemailer', async () => {
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve([['v=spf1 include:other.com ~all']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.checks.spf.status).toBe('fail');
    });

    it('returns missing when no CNAME or TXT found', async () => {
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));

      const result = await checkDns('example.com');
      expect(result.checks.spf.status).toBe('missing');
    });
  });

  describe('DKIM check', () => {
    beforeEach(() => {
      mockDns.resolveNs.mockResolvedValue(['ns1.dns.com']);
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));
    });

    it('returns pass when CNAME points to rule DKIM target', async () => {
      mockDns.resolveCname.mockImplementation((domain: string) => {
        if (domain === 'keyse._domainkey.example.com')
          return Promise.resolve([RULE_DKIM_TARGET]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.checks.dkim.status).toBe('pass');
    });

    it('returns fail when CNAME points elsewhere', async () => {
      mockDns.resolveCname.mockImplementation((domain: string) => {
        if (domain === 'keyse._domainkey.example.com')
          return Promise.resolve(['other.dkim.target.com']);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.checks.dkim.status).toBe('fail');
    });

    it('returns missing when no CNAME found', async () => {
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));

      const result = await checkDns('example.com');
      expect(result.checks.dkim.status).toBe('missing');
    });
  });

  describe('DMARC check', () => {
    beforeEach(() => {
      mockDns.resolveNs.mockResolvedValue(['ns1.dns.com']);
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
    });

    it('returns pass when DMARC record exists', async () => {
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([['v=DMARC1; p=reject']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.checks.dmarc.status).toBe('pass');
    });

    it('returns missing when no DMARC record found', async () => {
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));

      const result = await checkDns('example.com');
      expect(result.checks.dmarc.status).toBe('missing');
    });

    it('returns missing when TXT exists but no DMARC', async () => {
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([['some-other-txt-record']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.checks.dmarc.status).toBe('missing');
    });
  });

  it('allPassed is false when any check fails', async () => {
    mockDns.resolveNs.mockResolvedValue(['ns1.dns.com']);
    mockDns.resolveMx.mockResolvedValue([
      { exchange: RULE_MX_HOST, priority: 10 },
    ]);
    mockDns.resolveCname.mockImplementation((domain: string) => {
      if (domain === 'rm.example.com')
        return Promise.resolve([RULE_CNAME_TARGET]);
      // DKIM missing
      return Promise.reject(new Error('ENOTFOUND'));
    });
    mockDns.resolveTxt.mockImplementation((domain: string) => {
      if (domain === '_dmarc.example.com')
        return Promise.resolve([['v=DMARC1; p=none']]);
      return Promise.reject(new Error('ENOTFOUND'));
    });

    const result = await checkDns('example.com');
    expect(result.allPassed).toBe(false);
    expect(result.checks.dkim.status).toBe('missing');
  });

  describe('CNAME conflict detection', () => {
    beforeEach(() => {
      mockDns.resolveNs.mockResolvedValue(['ns1.dns.com']);
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
    });

    it('warns when A records exist at rm.{domain} without CNAME', async () => {
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolve4.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve(['1.2.3.4']);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          code: 'CNAME_CONFLICT_MX_SPF',
          severity: 'error',
        })
      );
    });

    it('warns when MX records exist at rm.{domain} without CNAME', async () => {
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveMx.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve([{ exchange: 'mail.other.com', priority: 10 }]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          code: 'CNAME_CONFLICT_MX_SPF',
          severity: 'error',
        })
      );
    });

    it('warns when TXT records exist at rm.{domain} without CNAME', async () => {
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve([['v=spf1 include:other.com ~all']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          code: 'CNAME_CONFLICT_MX_SPF',
          severity: 'error',
        })
      );
    });

    it('does not warn when CNAME exists at rm.{domain}', async () => {
      mockDns.resolveCname.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve([RULE_CNAME_TARGET]);
        return Promise.reject(new Error('ENOTFOUND'));
      });
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));

      const result = await checkDns('example.com');
      const conflictWarning = result.warnings.find(
        (w) => w.code === 'CNAME_CONFLICT_MX_SPF'
      );
      expect(conflictWarning).toBeUndefined();
    });
  });

  describe('DKIM conflict detection', () => {
    beforeEach(() => {
      mockDns.resolveNs.mockResolvedValue(['ns1.dns.com']);
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
    });

    it('warns when TXT records exist at DKIM domain without CNAME', async () => {
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === 'keyse._domainkey.example.com')
          return Promise.resolve([['v=DKIM1; k=rsa; p=MIGf...']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          code: 'CNAME_CONFLICT_DKIM',
          severity: 'error',
        })
      );
    });

    it('does not warn when CNAME exists at DKIM domain', async () => {
      mockDns.resolveCname.mockImplementation((domain: string) => {
        if (domain === 'keyse._domainkey.example.com')
          return Promise.resolve([RULE_DKIM_TARGET]);
        return Promise.reject(new Error('ENOTFOUND'));
      });
      mockDns.resolveTxt.mockRejectedValue(new Error('ENOTFOUND'));

      const result = await checkDns('example.com');
      const conflictWarning = result.warnings.find(
        (w) => w.code === 'CNAME_CONFLICT_DKIM'
      );
      expect(conflictWarning).toBeUndefined();
    });
  });

  describe('DMARC analysis warnings', () => {
    beforeEach(() => {
      mockDns.resolveNs.mockResolvedValue(['ns1.dns.com']);
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
    });

    it('stores raw existing DMARC record', async () => {
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([['v=DMARC1; p=none']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.checks.dmarc.existing).toBe('v=DMARC1; p=none');
    });

    it('warns on strict SPF alignment (aspf=s)', async () => {
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([['v=DMARC1; p=none; aspf=s']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          code: 'STRICT_SPF_ALIGNMENT',
          severity: 'warning',
        })
      );
    });

    it('warns on strict DKIM alignment (adkim=s)', async () => {
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([['v=DMARC1; p=none; adkim=s']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          code: 'STRICT_DKIM_ALIGNMENT',
          severity: 'info',
        })
      );
    });

    it('warns on p=reject policy', async () => {
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([['v=DMARC1; p=reject']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          code: 'EXISTING_DMARC_POLICY',
          severity: 'info',
          message: expect.stringContaining('p=reject'),
        })
      );
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          message: expect.stringContaining('rejected'),
        })
      );
    });

    it('warns on p=quarantine policy', async () => {
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([['v=DMARC1; p=quarantine']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          code: 'EXISTING_DMARC_POLICY',
          message: expect.stringContaining('quarantined'),
        })
      );
    });

    it('does not warn on p=none policy', async () => {
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([['v=DMARC1; p=none']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      const policyWarning = result.warnings.find(
        (w) => w.code === 'EXISTING_DMARC_POLICY'
      );
      expect(policyWarning).toBeUndefined();
    });

    it('collects multiple DMARC warnings', async () => {
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([
            ['v=DMARC1; p=reject; aspf=s; adkim=s'],
          ]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      const codes = result.warnings.map((w) => w.code);
      expect(codes).toContain('STRICT_SPF_ALIGNMENT');
      expect(codes).toContain('STRICT_DKIM_ALIGNMENT');
      expect(codes).toContain('EXISTING_DMARC_POLICY');
    });
  });

  describe('warnings array', () => {
    it('returns empty warnings when no issues found', async () => {
      mockDns.resolveNs.mockResolvedValue(['ns1.example.com']);
      mockDns.resolveMx.mockResolvedValue([
        { exchange: RULE_MX_HOST, priority: 10 },
      ]);
      mockDns.resolveCname.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve([RULE_CNAME_TARGET]);
        if (domain === 'keyse._domainkey.example.com')
          return Promise.resolve([RULE_DKIM_TARGET]);
        return Promise.reject(new Error('ENOTFOUND'));
      });
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([
            ['v=DMARC1; p=none; rua=mailto:dmarc@rule.se'],
          ]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.warnings).toEqual([]);
    });

    it('includes warnings in result', async () => {
      mockDns.resolveNs.mockResolvedValue(['ns1.dns.com']);
      mockDns.resolveMx.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolveCname.mockRejectedValue(new Error('ENOTFOUND'));
      mockDns.resolve4.mockImplementation((domain: string) => {
        if (domain === 'rm.example.com')
          return Promise.resolve(['1.2.3.4']);
        return Promise.reject(new Error('ENOTFOUND'));
      });
      mockDns.resolveTxt.mockImplementation((domain: string) => {
        if (domain === '_dmarc.example.com')
          return Promise.resolve([['v=DMARC1; p=reject; aspf=s']]);
        return Promise.reject(new Error('ENOTFOUND'));
      });

      const result = await checkDns('example.com');
      expect(result.warnings.length).toBeGreaterThanOrEqual(2);
      expect(result.warnings.every((w) => w.code && w.severity && w.message)).toBe(true);
    });
  });
});
