<?php

declare(strict_types=1);

namespace RuleIo\Dns\Data;

readonly class DnsRecord
{
    public function __construct(
        public string $type,
        public string $name,
        public string $value,
        public string $purpose,
    ) {}
}
