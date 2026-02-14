<?php

declare(strict_types=1);

namespace RuleIo\Dns;

use RuleIo\Dns\Contracts\DnsResolver;

/**
 * DNS resolver using `dig` with short timeouts.
 *
 * PHP's dns_get_record() on macOS can block 5-10s per query for
 * non-existent records. This resolver uses `dig` which returns
 * NXDOMAIN in ~30ms.
 *
 * Requires the `dig` CLI tool (available by default on macOS and most Linux
 * distributions; not available on Windows without manual installation).
 */
class DigDnsResolver implements DnsResolver
{
    private const TYPE_MAP = [
        DNS_A => 'A',
        DNS_AAAA => 'AAAA',
        DNS_CNAME => 'CNAME',
        DNS_MX => 'MX',
        DNS_NS => 'NS',
        DNS_TXT => 'TXT',
    ];

    public function __construct(
        private readonly string $nameserver = '1.1.1.1',
    ) {}

    public function getRecord(string $hostname, int $type): array|false
    {
        $typeStr = self::TYPE_MAP[$type] ?? null;
        if ($typeStr === null) {
            return false;
        }

        $escaped = escapeshellarg($hostname);
        $ns = escapeshellarg($this->nameserver);
        $output = shell_exec("dig +short +time=3 +tries=1 @{$ns} {$escaped} {$typeStr} 2>/dev/null");

        if ($output === null) {
            return false;
        }

        if (trim($output) === '') {
            return [];
        }

        $lines = array_filter(array_map('trim', explode("\n", trim($output))));
        $records = [];

        foreach ($lines as $line) {
            if (str_starts_with($line, ';')) {
                continue;
            }

            if ($type === DNS_NS) {
                $records[] = ['target' => rtrim($line, '.'), 'type' => 'NS'];
            } elseif ($type === DNS_MX) {
                $parts = preg_split('/\s+/', $line, 2);
                if (count($parts) === 2) {
                    $records[] = ['pri' => (int) $parts[0], 'target' => rtrim($parts[1], '.'), 'type' => 'MX'];
                }
            } elseif ($type === DNS_CNAME) {
                $records[] = ['target' => rtrim($line, '.'), 'type' => 'CNAME'];
            } elseif ($type === DNS_TXT) {
                if (preg_match_all('/"([^"]*)"/', $line, $matches)) {
                    $records[] = ['txt' => implode('', $matches[1]), 'type' => 'TXT'];
                } else {
                    $records[] = ['txt' => $line, 'type' => 'TXT'];
                }
            } elseif ($type === DNS_A) {
                $records[] = ['ip' => $line, 'type' => 'A'];
            } elseif ($type === DNS_AAAA) {
                $records[] = ['ipv6' => $line, 'type' => 'AAAA'];
            }
        }

        return $records;
    }
}
