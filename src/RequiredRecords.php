<?php

namespace RuleIo\Dns;

use RuleIo\Dns\Data\DnsCheckResult;
use RuleIo\Dns\Data\DnsRecord;
use RuleIo\Dns\Data\DnsRecordStatus;

class RequiredRecords
{
    /**
     * Get the DNS records required for Rule.io email sending.
     *
     * Returns all 3 required records by default. If $checkResult is provided,
     * only returns records for checks that are fail or missing.
     *
     * @return DnsRecord[]
     */
    public static function get(string $input, ?DnsCheckResult $checkResult = null): array
    {
        $domain = Domain::clean($input);

        $allRecords = [
            new DnsRecord(
                type: 'CNAME',
                name: Constants::RULE_SENDING_SUBDOMAIN . '.' . $domain,
                value: Constants::RULE_CNAME_TARGET,
                purpose: 'mx-spf',
            ),
            new DnsRecord(
                type: 'CNAME',
                name: Constants::RULE_DKIM_SELECTOR . '._domainkey.' . $domain,
                value: Constants::RULE_DKIM_TARGET,
                purpose: 'dkim',
            ),
            new DnsRecord(
                type: 'TXT',
                name: '_dmarc.' . $domain,
                value: Constants::RULE_DMARC_POLICY,
                purpose: 'dmarc',
            ),
        ];

        if ($checkResult === null) {
            return $allRecords;
        }

        return array_values(array_filter($allRecords, function (DnsRecord $record) use ($checkResult) {
            return match ($record->purpose) {
                'mx-spf' => $checkResult->checks->mx->status !== DnsRecordStatus::Pass
                    || $checkResult->checks->spf->status !== DnsRecordStatus::Pass,
                'dkim' => $checkResult->checks->dkim->status !== DnsRecordStatus::Pass,
                'dmarc' => $checkResult->checks->dmarc->status !== DnsRecordStatus::Pass,
                default => false,
            };
        }));
    }
}
