/** Rule.io sending subdomain prefix (e.g., rm.example.com) */
export const RULE_SENDING_SUBDOMAIN = 'rm';

/** CNAME target for MX + SPF (rm.{domain} → to.rulemailer.se) */
export const RULE_CNAME_TARGET = 'to.rulemailer.se';

/** Expected MX host for rm.{domain} */
export const RULE_MX_HOST = 'mail.rulemailer.se';

/** DKIM selector used by Rule.io */
export const RULE_DKIM_SELECTOR = 'keyse';

/** CNAME target for DKIM (keyse._domainkey.{domain} → keyse._domainkey.rulemailer.se) */
export const RULE_DKIM_TARGET = 'keyse._domainkey.rulemailer.se';

/** DMARC policy record value */
export const RULE_DMARC_POLICY =
  'v=DMARC1; p=none; rua=mailto:dmarc@rule.se; ruf=mailto:authfail@rule.se';
