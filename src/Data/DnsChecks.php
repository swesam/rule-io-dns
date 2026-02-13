<?php

namespace RuleIo\Dns\Data;

readonly class DnsChecks
{
    public function __construct(
        public DnsRecordCheck $ns,
        public DnsRecordCheck $mx,
        public DnsRecordCheck $spf,
        public DnsRecordCheck $dkim,
        public DnsRecordCheck $dmarc,
    ) {}
}
