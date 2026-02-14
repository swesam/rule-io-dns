<?php

namespace RuleIo\Dns;

use RuleIo\Dns\Contracts\DnsResolver;
use RuleIo\Dns\Data\DnsCheckResult;
use RuleIo\Dns\Data\DnsChecks;
use RuleIo\Dns\Data\DnsRecordCheck;
use RuleIo\Dns\Data\DnsRecordStatus;
use RuleIo\Dns\Data\DnsWarning;
use RuleIo\Dns\Data\Severity;

class DnsChecker
{
    public static function check(string $input, ?DnsResolver $resolver = null): DnsCheckResult
    {
        $resolver ??= new NativeDnsResolver();

        $domain = Domain::clean($input);
        $sendingDomain = Constants::RULE_SENDING_SUBDOMAIN . '.' . $domain;
        $dkimDomain = Constants::RULE_DKIM_SELECTOR . '._domainkey.' . $domain;
        $dmarcDomain = '_dmarc.' . $domain;

        $warnings = [];

        $ns = self::checkNs($resolver, $domain);
        $mx = self::checkMx($resolver, $sendingDomain);
        $spf = self::checkSpf($resolver, $sendingDomain);
        $dkim = self::checkDkim($resolver, $dkimDomain);
        $dmarc = self::checkDmarc($resolver, $dmarcDomain);

        self::detectCnameConflict($resolver, $sendingDomain, $warnings);
        self::detectDkimConflict($resolver, $dkimDomain, $warnings);
        self::detectCloudflareProxy($ns, $resolver, $sendingDomain, $dkimDomain, $mx, $spf, $dkim, $warnings);
        self::analyzeDmarc($dmarc, $sendingDomain, $warnings);

        $allPassed = $mx->status === DnsRecordStatus::Pass
            && $spf->status === DnsRecordStatus::Pass
            && $dkim->status === DnsRecordStatus::Pass
            && $dmarc->status === DnsRecordStatus::Pass;

        return new DnsCheckResult(
            domain: $domain,
            allPassed: $allPassed,
            warnings: $warnings,
            checks: new DnsChecks(
                ns: $ns,
                mx: $mx,
                spf: $spf,
                dkim: $dkim,
                dmarc: $dmarc,
            ),
        );
    }

    private static function checkNs(DnsResolver $resolver, string $domain): DnsRecordCheck
    {
        $records = $resolver->getRecord($domain, DNS_NS);
        if ($records === false || count($records) === 0) {
            return new DnsRecordCheck(status: DnsRecordStatus::Missing);
        }
        $targets = array_map(fn ($r) => $r['target'], $records);
        return new DnsRecordCheck(status: DnsRecordStatus::Pass, actual: $targets);
    }

    private static function checkMx(DnsResolver $resolver, string $sendingDomain): DnsRecordCheck
    {
        $records = $resolver->getRecord($sendingDomain, DNS_MX);
        if ($records !== false && count($records) > 0) {
            $hosts = array_map(fn ($r) => strtolower($r['target']), $records);
            $ruleHost = Constants::RULE_MX_HOST;
            foreach ($hosts as $h) {
                if ($h === $ruleHost || $h === $ruleHost . '.') {
                    return new DnsRecordCheck(
                        status: DnsRecordStatus::Pass,
                        expected: $ruleHost,
                        actual: $hosts,
                    );
                }
            }
            return new DnsRecordCheck(
                status: DnsRecordStatus::Fail,
                expected: $ruleHost,
                actual: $hosts,
            );
        }

        // MX might not exist directly if using CNAME — check CNAME fallback
        $cnames = $resolver->getRecord($sendingDomain, DNS_CNAME);
        if ($cnames !== false && count($cnames) > 0) {
            $targets = array_map(fn ($r) => strtolower($r['target']), $cnames);
            $cnameTarget = Constants::RULE_CNAME_TARGET;
            foreach ($targets as $t) {
                if ($t === $cnameTarget || $t === $cnameTarget . '.') {
                    return new DnsRecordCheck(
                        status: DnsRecordStatus::Pass,
                        expected: Constants::RULE_MX_HOST,
                        actual: $targets,
                    );
                }
            }
            return new DnsRecordCheck(
                status: DnsRecordStatus::Fail,
                expected: Constants::RULE_MX_HOST,
                actual: $targets,
            );
        }

        return new DnsRecordCheck(
            status: DnsRecordStatus::Missing,
            expected: Constants::RULE_MX_HOST,
        );
    }

    private static function checkSpf(DnsResolver $resolver, string $sendingDomain): DnsRecordCheck
    {
        // If rm.{domain} is a CNAME to to.rulemailer.se, SPF is covered
        $cnames = $resolver->getRecord($sendingDomain, DNS_CNAME);
        if ($cnames !== false && count($cnames) > 0) {
            $targets = array_map(fn ($r) => strtolower($r['target']), $cnames);
            $cnameTarget = Constants::RULE_CNAME_TARGET;
            foreach ($targets as $t) {
                if ($t === $cnameTarget || $t === $cnameTarget . '.') {
                    return new DnsRecordCheck(
                        status: DnsRecordStatus::Pass,
                        expected: 'CNAME → ' . $cnameTarget,
                        actual: $targets,
                    );
                }
            }
        }

        // No CNAME — check TXT records for SPF
        $txtRecords = $resolver->getRecord($sendingDomain, DNS_TXT);
        if ($txtRecords !== false && count($txtRecords) > 0) {
            $flat = array_map(fn ($r) => $r['txt'], $txtRecords);
            $spfRecord = null;
            foreach ($flat as $r) {
                if (str_starts_with($r, 'v=spf1')) {
                    $spfRecord = $r;
                    break;
                }
            }
            if ($spfRecord !== null && str_contains($spfRecord, 'rulemailer')) {
                return new DnsRecordCheck(
                    status: DnsRecordStatus::Pass,
                    expected: 'SPF including rulemailer',
                    actual: $spfRecord,
                );
            }
            if ($spfRecord !== null) {
                return new DnsRecordCheck(
                    status: DnsRecordStatus::Fail,
                    expected: 'SPF including rulemailer',
                    actual: $spfRecord,
                );
            }
        }

        return new DnsRecordCheck(
            status: DnsRecordStatus::Missing,
            expected: 'CNAME → ' . Constants::RULE_CNAME_TARGET,
        );
    }

    private static function checkDkim(DnsResolver $resolver, string $dkimDomain): DnsRecordCheck
    {
        $cnames = $resolver->getRecord($dkimDomain, DNS_CNAME);
        if ($cnames !== false && count($cnames) > 0) {
            $targets = array_map(fn ($r) => strtolower($r['target']), $cnames);
            $dkimTarget = Constants::RULE_DKIM_TARGET;
            foreach ($targets as $t) {
                if ($t === $dkimTarget || $t === $dkimTarget . '.') {
                    return new DnsRecordCheck(
                        status: DnsRecordStatus::Pass,
                        expected: $dkimTarget,
                        actual: $targets,
                    );
                }
            }
            return new DnsRecordCheck(
                status: DnsRecordStatus::Fail,
                expected: $dkimTarget,
                actual: $targets,
            );
        }

        return new DnsRecordCheck(
            status: DnsRecordStatus::Missing,
            expected: Constants::RULE_DKIM_TARGET,
        );
    }

    private static function checkDmarc(DnsResolver $resolver, string $dmarcDomain): DnsRecordCheck
    {
        $txtRecords = $resolver->getRecord($dmarcDomain, DNS_TXT);
        if ($txtRecords !== false && count($txtRecords) > 0) {
            $flat = array_map(fn ($r) => $r['txt'], $txtRecords);
            foreach ($flat as $r) {
                if (str_starts_with($r, 'v=DMARC1')) {
                    return new DnsRecordCheck(
                        status: DnsRecordStatus::Pass,
                        expected: 'v=DMARC1',
                        actual: $r,
                        existing: $r,
                    );
                }
            }
        }

        return new DnsRecordCheck(
            status: DnsRecordStatus::Missing,
            expected: 'v=DMARC1',
        );
    }

    /**
     * @param DnsWarning[] $warnings
     */
    private static function detectCnameConflict(DnsResolver $resolver, string $sendingDomain, array &$warnings): void
    {
        $cnames = $resolver->getRecord($sendingDomain, DNS_CNAME);
        if ($cnames !== false && count($cnames) > 0) {
            return; // CNAME already exists — no conflict
        }

        $hasA = self::safeHasRecords($resolver, $sendingDomain, DNS_A);
        $hasAAAA = self::safeHasRecords($resolver, $sendingDomain, DNS_AAAA);
        $hasTxt = self::safeHasRecords($resolver, $sendingDomain, DNS_TXT);
        $hasMx = self::safeHasRecords($resolver, $sendingDomain, DNS_MX);

        if ($hasA || $hasAAAA || $hasTxt || $hasMx) {
            $warnings[] = new DnsWarning(
                code: 'CNAME_CONFLICT_MX_SPF',
                severity: Severity::Error,
                message: "Existing records at {$sendingDomain} must be removed before adding the CNAME. A CNAME cannot coexist with other record types (RFC 1034).",
            );
        }
    }

    /**
     * @param DnsWarning[] $warnings
     */
    private static function detectDkimConflict(DnsResolver $resolver, string $dkimDomain, array &$warnings): void
    {
        $cnames = $resolver->getRecord($dkimDomain, DNS_CNAME);
        if ($cnames !== false && count($cnames) > 0) {
            return; // CNAME already exists — no conflict
        }

        if (self::safeHasRecords($resolver, $dkimDomain, DNS_TXT)) {
            $warnings[] = new DnsWarning(
                code: 'CNAME_CONFLICT_DKIM',
                severity: Severity::Error,
                message: "Existing TXT records at {$dkimDomain} must be removed before adding the CNAME.",
            );
        }
    }

    /**
     * @param DnsWarning[] $warnings
     */
    private static function detectCloudflareProxy(
        DnsRecordCheck $ns,
        DnsResolver $resolver,
        string $sendingDomain,
        string $dkimDomain,
        DnsRecordCheck $mx,
        DnsRecordCheck $spf,
        DnsRecordCheck $dkim,
        array &$warnings,
    ): void {
        if ($ns->status !== DnsRecordStatus::Pass || !is_array($ns->actual)) {
            return;
        }

        $isCloudflare = false;
        foreach ($ns->actual as $nameserver) {
            if (preg_match('/\.ns\.cloudflare\.com$/i', rtrim(strtolower($nameserver), '.')) === 1) {
                $isCloudflare = true;
                break;
            }
        }

        if (!$isCloudflare) {
            return;
        }

        $cnameSubdomains = [];
        if ($mx->status !== DnsRecordStatus::Pass || $spf->status !== DnsRecordStatus::Pass) {
            $cnameSubdomains[] = $sendingDomain;
        }
        if ($dkim->status !== DnsRecordStatus::Pass) {
            $cnameSubdomains[] = $dkimDomain;
        }

        foreach ($cnameSubdomains as $subdomain) {
            if (self::safeHasRecords($resolver, $subdomain, DNS_A)) {
                $warnings[] = new DnsWarning(
                    code: 'CLOUDFLARE_PROXY_ENABLED',
                    severity: Severity::Error,
                    message: "A records found at {$subdomain} but no CNAME. If you've added a CNAME in Cloudflare, ensure the proxy is disabled (orange cloud → grey cloud) so the CNAME is visible to DNS lookups.",
                );
            }
        }
    }

    private static function safeHasRecords(DnsResolver $resolver, string $domain, int $type): bool
    {
        $records = $resolver->getRecord($domain, $type);
        return $records !== false && count($records) > 0;
    }

    /**
     * @param DnsWarning[] $warnings
     */
    private static function analyzeDmarc(DnsRecordCheck $dmarcCheck, string $sendingDomain, array &$warnings): void
    {
        if ($dmarcCheck->existing === null) {
            return;
        }

        $parsed = DmarcParser::parse($dmarcCheck->existing);
        if ($parsed === null) {
            return;
        }

        if ($parsed->aspf === 's') {
            $warnings[] = new DnsWarning(
                code: 'STRICT_SPF_ALIGNMENT',
                severity: Severity::Warning,
                message: "Existing DMARC policy uses strict SPF alignment (aspf=s). SPF alignment will fail for subdomain sending from {$sendingDomain}. DKIM alignment must pass for emails to be delivered.",
            );
        }

        if ($parsed->adkim === 's') {
            $warnings[] = new DnsWarning(
                code: 'STRICT_DKIM_ALIGNMENT',
                severity: Severity::Info,
                message: 'Existing DMARC policy uses strict DKIM alignment (adkim=s). Ensure the DKIM signing domain exactly matches the From header domain.',
            );
        }

        if ($parsed->p === 'reject' || $parsed->p === 'quarantine') {
            $action = $parsed->p === 'reject' ? 'rejected' : 'quarantined';
            $warnings[] = new DnsWarning(
                code: 'EXISTING_DMARC_POLICY',
                severity: Severity::Info,
                message: "Domain has an existing DMARC policy of p={$parsed->p}. Ensure SPF and DKIM are correctly configured before sending, or emails may be {$action}.",
            );
        }
    }
}
