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
            $name = self::sanitize($record->name);
            $name = str_ends_with($name, '.') ? $name : $name . '.';
            $type = strtoupper($record->type);
            $sanitizedValue = self::sanitize($record->value);
            $value = match ($type) {
                'CNAME', 'NS', 'PTR' => str_ends_with($sanitizedValue, '.') ? $sanitizedValue : $sanitizedValue . '.',
                'MX', 'SRV' => self::ensureTrailingDotOnLastToken($sanitizedValue),
                'TXT' => '"' . addcslashes($sanitizedValue, '"\\') . '"',
                default => $sanitizedValue,
            };

            $lines[] = "{$name}\t{$ttl}\tIN\t{$type}\t{$value}";
        }

        return implode("\n", $lines) . "\n";
    }

    private static function sanitize(string $value): string
    {
        return trim(preg_replace('/[\r\n\t]/', '', $value));
    }

    private static function ensureTrailingDotOnLastToken(string $value): string
    {
        $value = rtrim($value);
        $pos = strrpos($value, ' ');

        if ($pos === false) {
            return str_ends_with($value, '.') ? $value : $value . '.';
        }

        $prefix = substr($value, 0, $pos + 1);
        $hostname = substr($value, $pos + 1);

        return $prefix . (str_ends_with($hostname, '.') ? $hostname : $hostname . '.');
    }
}
