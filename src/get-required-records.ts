import {
  RULE_CNAME_TARGET,
  RULE_DKIM_SELECTOR,
  RULE_DKIM_TARGET,
  RULE_DMARC_POLICY,
  RULE_SENDING_SUBDOMAIN,
} from './constants.js';
import { cleanDomain } from './domain.js';
import type { DnsCheckResult, DnsRecord } from './types.js';

/**
 * Get the DNS records required for Rule.io email sending.
 *
 * Returns all 3 required records by default. If `checkResult` is provided,
 * only returns records for checks that are `fail` or `missing`.
 *
 * This is a pure function — no DNS lookups or I/O.
 */
export function getRequiredDnsRecords(
  input: string,
  checkResult?: DnsCheckResult
): DnsRecord[] {
  const domain = cleanDomain(input);

  const allRecords: DnsRecord[] = [
    {
      type: 'CNAME',
      name: `${RULE_SENDING_SUBDOMAIN}.${domain}`,
      value: RULE_CNAME_TARGET,
      purpose: 'mx-spf',
    },
    {
      type: 'CNAME',
      name: `${RULE_DKIM_SELECTOR}._domainkey.${domain}`,
      value: RULE_DKIM_TARGET,
      purpose: 'dkim',
    },
    {
      type: 'TXT',
      name: `_dmarc.${domain}`,
      value: RULE_DMARC_POLICY,
      purpose: 'dmarc',
    },
  ];

  if (!checkResult) {
    return allRecords;
  }

  return allRecords.filter((record) => {
    switch (record.purpose) {
      case 'mx-spf':
        return (
          checkResult.checks.mx.status !== 'pass' ||
          checkResult.checks.spf.status !== 'pass'
        );
      case 'dkim':
        return checkResult.checks.dkim.status !== 'pass';
      case 'dmarc':
        return checkResult.checks.dmarc.status !== 'pass';
    }
  });
}
