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
        if ($records === []) {
            return '';
        }

        $lines = [];

        foreach ($records as $record) {
            $name = str_ends_with($record->name, '.') ? $record->name : $record->name . '.';
            $type = strtoupper($record->type);
            $value = match ($type) {
                'CNAME', 'NS', 'PTR' => str_ends_with($record->value, '.') ? $record->value : $record->value . '.',
                'MX', 'SRV' => self::ensureTrailingDotOnLastToken($record->value),
                'TXT' => '"' . addcslashes($record->value, '"\\') . '"',
                default => $record->value,
            };

            $lines[] = "{$name}\t{$ttl}\tIN\t{$type}\t{$value}";
        }

        return implode("\n", $lines) . "\n";
    }

    private static function ensureTrailingDotOnLastToken(string $value): string
    {
        $pos = strrpos($value, ' ');

        if ($pos === false) {
            return str_ends_with($value, '.') ? $value : $value . '.';
        }

        $prefix = substr($value, 0, $pos + 1);
        $hostname = substr($value, $pos + 1);

        return $prefix . (str_ends_with($hostname, '.') ? $hostname : $hostname . '.');
    }
}
