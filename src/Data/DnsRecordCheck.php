<?php

declare(strict_types=1);

namespace RuleIo\Dns\Data;

readonly class DnsRecordCheck
{
    /**
     * @param string|string[]|null $actual
     */
    public function __construct(
        public DnsRecordStatus $status,
        public ?string $expected = null,
        public string|array|null $actual = null,
        public ?string $existing = null,
    ) {}
}
