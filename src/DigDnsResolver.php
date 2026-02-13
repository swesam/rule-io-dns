<?php

namespace RuleIo\Dns;

use RuleIo\Dns\Contracts\DnsResolver;

/**
 * DNS resolver using `dig` with short timeouts and result caching.
 *
 * PHP's dns_get_record() on macOS can block 5-10s per query for
 * non-existent records. This resolver uses `dig` which returns
 * NXDOMAIN in ~30ms, and caches results to eliminate duplicate queries.
 *
 * Queries 1.1.1.1 directly to bypass local DNS caching (important
 * after provisioning — the local resolver may have stale negative cache).
 */
class DigDnsResolver implements DnsResolver
{
    private array $cache = [];

    private const TYPE_MAP = [
        DNS_A => 'A',
        DNS_AAAA => 'AAAA',
        DNS_CNAME => 'CNAME',
        DNS_MX => 'MX',
        DNS_NS => 'NS',
        DNS_TXT => 'TXT',
    ];

    public function getRecord(string $hostname, int $type): array|false
    {
        $key = $hostname . ':' . $type;
        if (array_key_exists($key, $this->cache)) {
            return $this->cache[$key];
        }

        $typeStr = self::TYPE_MAP[$type] ?? null;
        if ($typeStr === null) {
            return $this->cache[$key] = false;
        }

        $escaped = escapeshellarg($hostname);
        $output = shell_exec("dig +short +time=3 +tries=1 @1.1.1.1 {$escaped} {$typeStr} 2>/dev/null");

        if ($output === null || trim($output) === '') {
            return $this->cache[$key] = [];
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

        return $this->cache[$key] = $records;
    }
}
