/** Status of a single DNS record check */
export type DnsRecordStatus = 'pass' | 'fail' | 'missing';

/** Result of checking a single DNS record */
export interface DnsRecordCheck {
  status: DnsRecordStatus;
  /** What we expected to find */
  expected?: string;
  /** What was actually found */
  actual?: string | string[];
}

/** Full result of checking all required DNS records for a domain */
export interface DnsCheckResult {
  /** The cleaned domain that was checked */
  domain: string;
  /** True if all required checks passed */
  allPassed: boolean;
  checks: {
    /** Nameserver lookup (informational — identifies DNS provider) */
    ns: DnsRecordCheck;
    /** MX record for rm.{domain} */
    mx: DnsRecordCheck;
    /** SPF check via CNAME/TXT on rm.{domain} */
    spf: DnsRecordCheck;
    /** DKIM CNAME for keyse._domainkey.{domain} */
    dkim: DnsRecordCheck;
    /** DMARC TXT record on _dmarc.{domain} */
    dmarc: DnsRecordCheck;
  };
}

/** A DNS record that needs to be configured */
export interface DnsRecord {
  type: 'CNAME' | 'TXT';
  /** The DNS record name (e.g., rm.example.com) */
  name: string;
  /** The DNS record value (e.g., to.rulemailer.se) */
  value: string;
  /** What this record is for */
  purpose: 'mx-spf' | 'dkim' | 'dmarc';
}
