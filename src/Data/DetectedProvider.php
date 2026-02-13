<?php

namespace RuleIo\Dns\Data;

readonly class DetectedProvider
{
    /**
     * @param string[] $nameservers
     */
    public function __construct(
        public ProviderSlug $slug,
        public array $nameservers,
    ) {}
}
