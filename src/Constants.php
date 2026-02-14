<?php

declare(strict_types=1);

namespace RuleIo\Dns;

class Constants
{
    public const RULE_SENDING_SUBDOMAIN = 'rm';
    public const RULE_CNAME_TARGET = 'to.rulemailer.se';
    public const RULE_MX_HOST = 'mail.rulemailer.se';
    public const RULE_DKIM_SELECTOR = 'keyse';
    public const RULE_DKIM_TARGET = 'keyse._domainkey.rulemailer.se';
    public const RULE_DMARC_POLICY = 'v=DMARC1; p=none; rua=mailto:dmarc@rule.se; ruf=mailto:authfail@rule.se';
}
