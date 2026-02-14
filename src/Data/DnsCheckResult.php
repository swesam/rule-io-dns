<?php

declare(strict_types=1);

namespace RuleIo\Dns\Data;

readonly class DnsCheckResult
{
    /**
     * @param DnsWarning[] $warnings
     */
    public function __construct(
        public string $domain,
        public bool $allPassed,
        public array $warnings,
        public DnsChecks $checks,
    ) {}
}
