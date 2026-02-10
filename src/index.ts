export { checkDns } from './check-dns.js';
export { getRequiredDnsRecords } from './get-required-records.js';
export { cleanDomain } from './domain.js';
export {
  RULE_SENDING_SUBDOMAIN,
  RULE_CNAME_TARGET,
  RULE_MX_HOST,
  RULE_DKIM_SELECTOR,
  RULE_DKIM_TARGET,
  RULE_DMARC_POLICY,
} from './constants.js';
export type {
  DnsCheckResult,
  DnsRecordCheck,
  DnsRecordStatus,
  DnsRecord,
} from './types.js';
