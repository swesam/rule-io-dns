<?php

namespace RuleIo\Dns;

class Domain
{
    public static function clean(string $input): string
    {
        $domain = strtolower(trim($input));

        // Extract domain from email
        if (str_contains($domain, '@')) {
            $parts = explode('@', $domain);
            $domain = end($parts);
        }

        // Extract hostname from URL
        if (str_contains($domain, '://')) {
            $parsed = parse_url($domain, PHP_URL_HOST);
            if ($parsed) {
                $domain = $parsed;
            } else {
                // If URL parsing fails, strip protocol manually
                $afterProtocol = explode('://', $domain, 2)[1] ?? $domain;
                $domain = explode('/', $afterProtocol, 2)[0];
            }
        }

        // Remove path, query, fragment if present
        $domain = explode('/', $domain, 2)[0];

        // Remove trailing dot (FQDN notation)
        $domain = rtrim($domain, '.');

        // Remove www prefix
        if (str_starts_with($domain, 'www.')) {
            $domain = substr($domain, 4);
        }

        return $domain;
    }
}
