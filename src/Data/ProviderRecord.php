<?php

namespace RuleIo\Dns\Data;

readonly class ProviderRecord
{
    public function __construct(
        public string $id,
        public string $type,
        public string $name,
        public string $value,
        public ?bool $proxied = null,
    ) {}
}
