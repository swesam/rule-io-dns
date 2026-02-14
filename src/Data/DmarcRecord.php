<?php

declare(strict_types=1);

namespace RuleIo\Dns\Data;

readonly class DmarcRecord
{
    /**
     * @param string[]|null $rua
     * @param string[]|null $ruf
     */
    public function __construct(
        public string $p,
        public ?string $sp = null,
        public ?string $aspf = null,
        public ?string $adkim = null,
        public ?array $rua = null,
        public ?array $ruf = null,
        public ?int $pct = null,
    ) {}
}
