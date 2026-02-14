<?php

declare(strict_types=1);

namespace RuleIo\Dns;

use RuleIo\Dns\Data\DmarcRecord;

class DmarcParser
{
    /**
     * Parse a raw DMARC TXT record string into a structured DmarcRecord.
     *
     * @param string $raw The raw DMARC TXT record value (e.g. "v=DMARC1; p=reject; ...")
     * @return DmarcRecord|null Parsed record, or null if invalid
     */
    public static function parse(string $raw): ?DmarcRecord
    {
        $trimmed = trim($raw);
        if (!str_starts_with($trimmed, 'v=DMARC1')) {
            return null;
        }

        $tags = [];
        $parts = explode(';', $trimmed);
        foreach ($parts as $part) {
            $eq = strpos($part, '=');
            if ($eq === false) {
                continue;
            }
            $key = strtolower(trim(substr($part, 0, $eq)));
            $value = trim(substr($part, $eq + 1));
            $tags[$key] = $value;
        }

        $p = strtolower($tags['p'] ?? '');
        if (!in_array($p, ['none', 'quarantine', 'reject'], true)) {
            return null;
        }

        $sp = isset($tags['sp']) ? strtolower($tags['sp']) : null;
        if ($sp !== null && !in_array($sp, ['none', 'quarantine', 'reject'], true)) {
            $sp = null;
        }

        $aspf = isset($tags['aspf']) ? strtolower($tags['aspf']) : null;
        if ($aspf !== null && !in_array($aspf, ['r', 's'], true)) {
            $aspf = null;
        }

        $adkim = isset($tags['adkim']) ? strtolower($tags['adkim']) : null;
        if ($adkim !== null && !in_array($adkim, ['r', 's'], true)) {
            $adkim = null;
        }

        $rua = null;
        if (isset($tags['rua'])) {
            $list = self::parseMailtoList($tags['rua']);
            if (count($list) > 0) {
                $rua = $list;
            }
        }

        $ruf = null;
        if (isset($tags['ruf'])) {
            $list = self::parseMailtoList($tags['ruf']);
            if (count($list) > 0) {
                $ruf = $list;
            }
        }

        $pct = null;
        if (isset($tags['pct'])) {
            if (ctype_digit($tags['pct'])) {
                $num = (int) $tags['pct'];
                if ($num >= 0 && $num <= 100) {
                    $pct = $num;
                }
            }
        }

        return new DmarcRecord(
            p: $p,
            sp: $sp,
            aspf: $aspf,
            adkim: $adkim,
            rua: $rua,
            ruf: $ruf,
            pct: $pct,
        );
    }

    /**
     * @return string[]
     */
    private static function parseMailtoList(string $value): array
    {
        $uris = array_map('trim', explode(',', $value));
        $result = [];
        foreach ($uris as $uri) {
            if (str_starts_with($uri, 'mailto:')) {
                $result[] = substr($uri, 7);
            }
        }
        return $result;
    }
}
