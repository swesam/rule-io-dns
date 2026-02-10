import dns from 'node:dns';
import {
  RULE_CNAME_TARGET,
  RULE_DKIM_SELECTOR,
  RULE_DKIM_TARGET,
  RULE_MX_HOST,
  RULE_SENDING_SUBDOMAIN,
} from './constants.js';
import { cleanDomain } from './domain.js';
import type { DnsCheckResult, DnsRecordCheck } from './types.js';

const resolver = dns.promises;

/**
 * Check whether a domain has the required DNS records for Rule.io email sending.
 *
 * Uses Node.js `dns.promises` for all lookups — no external service dependencies.
 *
 * Rule.io requires:
 * - `CNAME rm.{domain} → to.rulemailer.se` (covers MX + SPF)
 * - `CNAME keyse._domainkey.{domain} → keyse._domainkey.rulemailer.se` (DKIM)
 * - `TXT _dmarc.{domain} → v=DMARC1; ...` (DMARC)
 */
export async function checkDns(input: string): Promise<DnsCheckResult> {
  const domain = cleanDomain(input);
  const sendingDomain = `${RULE_SENDING_SUBDOMAIN}.${domain}`;
  const dkimDomain = `${RULE_DKIM_SELECTOR}._domainkey.${domain}`;
  const dmarcDomain = `_dmarc.${domain}`;

  const [ns, mx, spf, dkim, dmarc] = await Promise.all([
    checkNs(domain),
    checkMx(sendingDomain),
    checkSpf(sendingDomain),
    checkDkim(dkimDomain),
    checkDmarc(dmarcDomain),
  ]);

  const allPassed =
    mx.status === 'pass' &&
    spf.status === 'pass' &&
    dkim.status === 'pass' &&
    dmarc.status === 'pass';

  return {
    domain,
    allPassed,
    checks: { ns, mx, spf, dkim, dmarc },
  };
}

async function checkNs(domain: string): Promise<DnsRecordCheck> {
  try {
    const records = await resolver.resolveNs(domain);
    if (records.length === 0) {
      return { status: 'missing' };
    }
    return { status: 'pass', actual: records };
  } catch {
    return { status: 'missing' };
  }
}

async function checkMx(sendingDomain: string): Promise<DnsRecordCheck> {
  try {
    const records = await resolver.resolveMx(sendingDomain);
    const hosts = records.map((r) => r.exchange.toLowerCase());
    if (hosts.some((h) => h === RULE_MX_HOST || h === `${RULE_MX_HOST}.`)) {
      return { status: 'pass', expected: RULE_MX_HOST, actual: hosts };
    }
    if (hosts.length === 0) {
      return { status: 'missing', expected: RULE_MX_HOST };
    }
    return { status: 'fail', expected: RULE_MX_HOST, actual: hosts };
  } catch {
    // MX might not exist directly if using CNAME — check CNAME fallback
    try {
      const cnames = await resolver.resolveCname(sendingDomain);
      const targets = cnames.map((c) => c.toLowerCase());
      if (
        targets.some(
          (t) => t === RULE_CNAME_TARGET || t === `${RULE_CNAME_TARGET}.`
        )
      ) {
        return { status: 'pass', expected: RULE_MX_HOST, actual: targets };
      }
      return { status: 'fail', expected: RULE_MX_HOST, actual: targets };
    } catch {
      return { status: 'missing', expected: RULE_MX_HOST };
    }
  }
}

async function checkSpf(sendingDomain: string): Promise<DnsRecordCheck> {
  try {
    // If rm.{domain} is a CNAME to to.rulemailer.se, SPF is covered
    const cnames = await resolver.resolveCname(sendingDomain);
    const targets = cnames.map((c) => c.toLowerCase());
    if (
      targets.some(
        (t) => t === RULE_CNAME_TARGET || t === `${RULE_CNAME_TARGET}.`
      )
    ) {
      return {
        status: 'pass',
        expected: `CNAME → ${RULE_CNAME_TARGET}`,
        actual: targets,
      };
    }
  } catch {
    // No CNAME — check TXT records for SPF
  }

  try {
    const txtRecords = await resolver.resolveTxt(sendingDomain);
    const flat = txtRecords.map((chunks) => chunks.join(''));
    const spfRecord = flat.find((r) => r.startsWith('v=spf1'));
    if (spfRecord && spfRecord.includes('rulemailer')) {
      return {
        status: 'pass',
        expected: `SPF including rulemailer`,
        actual: spfRecord,
      };
    }
    if (spfRecord) {
      return {
        status: 'fail',
        expected: `SPF including rulemailer`,
        actual: spfRecord,
      };
    }
    return { status: 'missing', expected: `CNAME → ${RULE_CNAME_TARGET}` };
  } catch {
    return { status: 'missing', expected: `CNAME → ${RULE_CNAME_TARGET}` };
  }
}

async function checkDkim(dkimDomain: string): Promise<DnsRecordCheck> {
  try {
    const cnames = await resolver.resolveCname(dkimDomain);
    const targets = cnames.map((c) => c.toLowerCase());
    if (
      targets.some(
        (t) => t === RULE_DKIM_TARGET || t === `${RULE_DKIM_TARGET}.`
      )
    ) {
      return { status: 'pass', expected: RULE_DKIM_TARGET, actual: targets };
    }
    return { status: 'fail', expected: RULE_DKIM_TARGET, actual: targets };
  } catch {
    return { status: 'missing', expected: RULE_DKIM_TARGET };
  }
}

async function checkDmarc(dmarcDomain: string): Promise<DnsRecordCheck> {
  try {
    const txtRecords = await resolver.resolveTxt(dmarcDomain);
    const flat = txtRecords.map((chunks) => chunks.join(''));
    const dmarcRecord = flat.find((r) => r.startsWith('v=DMARC1'));
    if (dmarcRecord) {
      return { status: 'pass', expected: 'v=DMARC1', actual: dmarcRecord };
    }
    return { status: 'missing', expected: 'v=DMARC1' };
  } catch {
    return { status: 'missing', expected: 'v=DMARC1' };
  }
}
