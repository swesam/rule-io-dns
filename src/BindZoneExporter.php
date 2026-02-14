<?php

namespace RuleIo\Dns;

use RuleIo\Dns\Data\DnsRecord;

class BindZoneExporter
{
    /**
     * Export DNS records as a BIND zone file string.
     *
     * Compatible with Cloudflare, Hetzner, OVH, IONOS, and any provider
     * that supports standard BIND/RFC 1035 zone file imports.
     *
     * @param DnsRecord[] $records
     */
    public static function export(array $records, int $ttl = 3600): string
    {
        $lines = [];

        foreach ($records as $record) {
            $name = str_ends_with($record->name, '.') ? $record->name : $record->name . '.';
            $value = match ($record->type) {
                'CNAME', 'MX', 'NS', 'PTR', 'SRV' => str_ends_with($record->value, '.') ? $record->value : $record->value . '.',
                'TXT' => '"' . $record->value . '"',
                default => $record->value,
            };

            $lines[] = "{$name}\t{$ttl}\tIN\t{$record->type}\t{$value}";
        }

        return implode("\n", $lines) . "\n";
    }
}
