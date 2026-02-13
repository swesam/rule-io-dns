<?php

namespace RuleIo\Dns\Data;

readonly class ProvisionResult
{
    /**
     * @param DnsRecord[] $created
     * @param ProviderRecord[] $deleted
     * @param DnsRecord[] $skipped
     * @param DnsWarning[] $warnings
     */
    public function __construct(
        public string $domain,
        public array $created,
        public array $deleted,
        public array $skipped,
        public array $warnings,
    ) {}
}
