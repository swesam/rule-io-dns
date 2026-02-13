<?php

namespace RuleIo\Dns\Contracts;

interface DnsResolver
{
    /**
     * @return array<int, array<string, mixed>>|false
     */
    public function getRecord(string $hostname, int $type): array|false;
}
