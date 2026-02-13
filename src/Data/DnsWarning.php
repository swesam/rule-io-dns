<?php

namespace RuleIo\Dns\Data;

readonly class DnsWarning
{
    public function __construct(
        public string $code,
        public Severity $severity,
        public string $message,
    ) {}
}
