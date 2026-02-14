<?php

declare(strict_types=1);

namespace RuleIo\Dns;

use RuleIo\Dns\Contracts\DnsResolver;

class NativeDnsResolver implements DnsResolver
{
    public function getRecord(string $hostname, int $type): array|false
    {
        return @dns_get_record($hostname, $type);
    }
}
