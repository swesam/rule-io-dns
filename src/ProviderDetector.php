<?php

declare(strict_types=1);

namespace RuleIo\Dns;

use RuleIo\Dns\Data\DetectedProvider;
use RuleIo\Dns\Data\ProviderSlug;

class ProviderDetector
{
    private const PATTERNS = [
        'cloudflare' => '/\.ns\.cloudflare\.com$/i',
        'hetzner' => '/\.ns\.hetzner\.(com|de)$/i',
        'loopia' => '/\.loopia\.se$/i',
        'gandi' => '/\.gandi\.net$/i',
        'domeneshop' => '/\.hyp\.net$/i',
        'ionos' => '/\.ui-dns\.(com|org|de|biz)$/i',
        'ovh' => '/\.ovh\.net$/i',
    ];

    /**
     * Detect which DNS provider hosts a domain based on its nameservers.
     *
     * @param string[] $nameservers List of nameserver hostnames (e.g. from NS lookup)
     * @return DetectedProvider|null Matched provider, or null if unrecognized
     */
    public static function detect(array $nameservers): ?DetectedProvider
    {
        $normalized = array_map(
            fn (string $ns) => rtrim(strtolower($ns), '.'),
            $nameservers,
        );

        foreach (self::PATTERNS as $slug => $pattern) {
            $matched = array_values(array_filter(
                $normalized,
                fn (string $ns) => preg_match($pattern, $ns) === 1,
            ));

            if (count($matched) > 0) {
                return new DetectedProvider(
                    slug: ProviderSlug::from($slug),
                    nameservers: $matched,
                );
            }
        }

        return null;
    }
}
