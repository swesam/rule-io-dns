<?php

declare(strict_types=1);

use RuleIo\Dns\Constants;
use RuleIo\Dns\Contracts\DnsResolver;
use RuleIo\Dns\DnsChecker;

function mockResolver(array $records = []): DnsResolver
{
    return new class($records) implements DnsResolver {
        public function __construct(private readonly array $records) {}

        public function getRecord(string $hostname, int $type): array|false
        {
            return $this->records[$hostname][$type] ?? false;
        }
    };
}

it('returns allPassed: true when all records are correct', function () {
    $resolver = mockResolver([
        'example.com' => [
            DNS_NS => [['target' => 'ns1.example.com'], ['target' => 'ns2.example.com']],
        ],
        'rm.example.com' => [
            DNS_MX => [['target' => Constants::RULE_MX_HOST, 'pri' => 10]],
            DNS_CNAME => [['target' => Constants::RULE_CNAME_TARGET]],
        ],
        'keyse._domainkey.example.com' => [
            DNS_CNAME => [['target' => Constants::RULE_DKIM_TARGET]],
        ],
        '_dmarc.example.com' => [
            DNS_TXT => [['txt' => 'v=DMARC1; p=none; rua=mailto:dmarc@rule.se; ruf=mailto:authfail@rule.se']],
        ],
    ]);

    $result = DnsChecker::check('example.com', $resolver);
    expect($result->domain)->toBe('example.com')
        ->and($result->allPassed)->toBeTrue()
        ->and($result->checks->ns->status->value)->toBe('pass')
        ->and($result->checks->mx->status->value)->toBe('pass')
        ->and($result->checks->spf->status->value)->toBe('pass')
        ->and($result->checks->dkim->status->value)->toBe('pass')
        ->and($result->checks->dmarc->status->value)->toBe('pass');
});

it('cleans domain from email input', function () {
    $resolver = mockResolver();
    $result = DnsChecker::check('user@example.com', $resolver);
    expect($result->domain)->toBe('example.com');
});

describe('NS check', function () {
    it('returns pass when nameservers exist', function () {
        $resolver = mockResolver([
            'example.com' => [
                DNS_NS => [['target' => 'ns1.dns.com']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->ns->status->value)->toBe('pass')
            ->and($result->checks->ns->actual)->toBe(['ns1.dns.com']);
    });

    it('returns missing when no nameservers found', function () {
        $resolver = mockResolver();
        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->ns->status->value)->toBe('missing');
    });
});

describe('MX check', function () {
    it('returns pass when MX points to rule host', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_MX => [['target' => Constants::RULE_MX_HOST, 'pri' => 10]],
                DNS_CNAME => [['target' => Constants::RULE_CNAME_TARGET]],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->mx->status->value)->toBe('pass');
    });

    it('returns fail when MX points elsewhere', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_MX => [['target' => 'mail.other.com', 'pri' => 10]],
                DNS_CNAME => [['target' => Constants::RULE_CNAME_TARGET]],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->mx->status->value)->toBe('fail');
    });

    it('falls back to CNAME check when MX lookup fails', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_CNAME => [['target' => Constants::RULE_CNAME_TARGET]],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->mx->status->value)->toBe('pass');
    });

    it('returns missing when both MX and CNAME fail', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->mx->status->value)->toBe('missing');
    });
});

describe('SPF check', function () {
    it('returns pass when CNAME points to rule target', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_CNAME => [['target' => Constants::RULE_CNAME_TARGET]],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->spf->status->value)->toBe('pass');
    });

    it('returns pass when TXT includes rulemailer SPF', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_TXT => [['txt' => 'v=spf1 include:spf.rulemailer.se ~all']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->spf->status->value)->toBe('pass');
    });

    it('returns fail when SPF exists but without rulemailer', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_TXT => [['txt' => 'v=spf1 include:other.com ~all']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->spf->status->value)->toBe('fail');
    });

    it('returns missing when no CNAME or TXT found', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->spf->status->value)->toBe('missing');
    });
});

describe('DKIM check', function () {
    it('returns pass when CNAME points to rule DKIM target', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'keyse._domainkey.example.com' => [
                DNS_CNAME => [['target' => Constants::RULE_DKIM_TARGET]],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->dkim->status->value)->toBe('pass');
    });

    it('returns fail when CNAME points elsewhere', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'keyse._domainkey.example.com' => [
                DNS_CNAME => [['target' => 'other.dkim.target.com']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->dkim->status->value)->toBe('fail');
    });

    it('returns missing when no CNAME found', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->dkim->status->value)->toBe('missing');
    });
});

describe('DMARC check', function () {
    it('returns pass when DMARC record exists at org domain', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=reject']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->dmarc->status->value)->toBe('pass');
    });

    it('returns missing when no DMARC record found', function () {
        $resolver = mockResolver();
        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->dmarc->status->value)->toBe('missing');
    });

    it('returns missing when TXT exists but no DMARC', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'some-other-txt-record']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->dmarc->status->value)->toBe('missing');
    });
});

it('allPassed is false when any check fails', function () {
    $resolver = mockResolver([
        'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
        'rm.example.com' => [
            DNS_MX => [['target' => Constants::RULE_MX_HOST, 'pri' => 10]],
            DNS_CNAME => [['target' => Constants::RULE_CNAME_TARGET]],
        ],
        '_dmarc.example.com' => [
            DNS_TXT => [['txt' => 'v=DMARC1; p=none']],
        ],
        // DKIM missing
    ]);

    $result = DnsChecker::check('example.com', $resolver);
    expect($result->allPassed)->toBeFalse()
        ->and($result->checks->dkim->status->value)->toBe('missing');
});

describe('CNAME conflict detection', function () {
    it('warns when A records exist at rm.{domain} without CNAME', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_A => [['ip' => '1.2.3.4']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->toContain('CNAME_CONFLICT_MX_SPF');
    });

    it('warns when MX records exist at rm.{domain} without CNAME', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_MX => [['target' => 'mail.other.com', 'pri' => 10]],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->toContain('CNAME_CONFLICT_MX_SPF');
    });

    it('warns when TXT records exist at rm.{domain} without CNAME', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_TXT => [['txt' => 'v=spf1 include:other.com ~all']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->toContain('CNAME_CONFLICT_MX_SPF');
    });

    it('warns when AAAA records exist at rm.{domain} without CNAME', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_AAAA => [['ipv6' => '2001:db8::1']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->toContain('CNAME_CONFLICT_MX_SPF');
    });

    it('does not warn when CNAME exists at rm.{domain}', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_CNAME => [['target' => Constants::RULE_CNAME_TARGET]],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->not->toContain('CNAME_CONFLICT_MX_SPF');
    });
});

describe('DKIM conflict detection', function () {
    it('warns when TXT records exist at DKIM domain without CNAME', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'keyse._domainkey.example.com' => [
                DNS_TXT => [['txt' => 'v=DKIM1; k=rsa; p=MIGf...']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->toContain('CNAME_CONFLICT_DKIM');
    });

    it('does not warn when CNAME exists at DKIM domain', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'keyse._domainkey.example.com' => [
                DNS_CNAME => [['target' => Constants::RULE_DKIM_TARGET]],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->not->toContain('CNAME_CONFLICT_DKIM');
    });
});

describe('DMARC analysis warnings', function () {
    it('stores raw existing DMARC record from org domain', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=none']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->checks->dmarc->existing)->toBe('v=DMARC1; p=none');
    });

    it('warns on strict SPF alignment (aspf=s) from org DMARC', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=none; aspf=s']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->toContain('STRICT_SPF_ALIGNMENT');
    });

    it('warns on strict DKIM alignment (adkim=s) from org DMARC', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=none; adkim=s']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->toContain('STRICT_DKIM_ALIGNMENT');
    });

    it('warns on p=reject policy from org DMARC', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=reject']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        $messages = array_map(fn ($w) => $w->message, $result->warnings);
        expect($codes)->toContain('EXISTING_DMARC_POLICY');

        $policyWarning = null;
        foreach ($result->warnings as $w) {
            if ($w->code === 'EXISTING_DMARC_POLICY') {
                $policyWarning = $w;
            }
        }
        expect($policyWarning->message)->toContain('p=reject')
            ->and($policyWarning->message)->toContain('rejected');
    });

    it('warns on p=quarantine policy from org DMARC', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=quarantine']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $policyWarning = null;
        foreach ($result->warnings as $w) {
            if ($w->code === 'EXISTING_DMARC_POLICY') {
                $policyWarning = $w;
            }
        }
        expect($policyWarning->message)->toContain('quarantined');
    });

    it('does not warn on p=none policy from org DMARC', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=none']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->not->toContain('EXISTING_DMARC_POLICY');
    });

    it('collects multiple DMARC warnings from org DMARC', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=reject; aspf=s; adkim=s']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->toContain('STRICT_SPF_ALIGNMENT')
            ->and($codes)->toContain('STRICT_DKIM_ALIGNMENT')
            ->and($codes)->toContain('EXISTING_DMARC_POLICY');
    });
});

describe('Cloudflare proxy detection', function () {
    it('warns when Cloudflare NS + missing CNAME + A records exist at sending domain', function () {
        $resolver = mockResolver([
            'example.com' => [
                DNS_NS => [['target' => 'ada.ns.cloudflare.com'], ['target' => 'bob.ns.cloudflare.com']],
            ],
            'rm.example.com' => [
                DNS_A => [['ip' => '104.21.0.1']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->toContain('CLOUDFLARE_PROXY_ENABLED');

        $warning = null;
        foreach ($result->warnings as $w) {
            if ($w->code === 'CLOUDFLARE_PROXY_ENABLED') {
                $warning = $w;
                break;
            }
        }
        expect($warning->message)->toContain('rm.example.com')
            ->and($warning->message)->toContain('Cloudflare proxy')
            ->and($warning->message)->toContain('orange cloud');
    });

    it('warns for DKIM domain when Cloudflare NS + missing CNAME + A records exist', function () {
        $resolver = mockResolver([
            'example.com' => [
                DNS_NS => [['target' => 'ada.ns.cloudflare.com']],
            ],
            'keyse._domainkey.example.com' => [
                DNS_A => [['ip' => '104.21.0.1']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $proxyWarnings = array_values(array_filter($result->warnings, fn ($w) => $w->code === 'CLOUDFLARE_PROXY_ENABLED'));
        expect($proxyWarnings)->not->toBeEmpty();

        $hasDkim = false;
        foreach ($proxyWarnings as $w) {
            if (str_contains($w->message, 'keyse._domainkey.example.com')) {
                $hasDkim = true;
            }
        }
        expect($hasDkim)->toBeTrue();
    });

    it('emits a single warning mentioning both subdomains when both are proxied', function () {
        $resolver = mockResolver([
            'example.com' => [
                DNS_NS => [['target' => 'ada.ns.cloudflare.com']],
            ],
            'rm.example.com' => [
                DNS_A => [['ip' => '104.21.0.1']],
            ],
            'keyse._domainkey.example.com' => [
                DNS_A => [['ip' => '104.21.0.2']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $proxyWarnings = array_values(array_filter($result->warnings, fn ($w) => $w->code === 'CLOUDFLARE_PROXY_ENABLED'));
        expect($proxyWarnings)->toHaveCount(1)
            ->and($proxyWarnings[0]->message)->toContain('rm.example.com')
            ->and($proxyWarnings[0]->message)->toContain('keyse._domainkey.example.com');
    });

    it('does not warn for non-Cloudflare nameservers', function () {
        $resolver = mockResolver([
            'example.com' => [
                DNS_NS => [['target' => 'ns1.hetzner.com'], ['target' => 'ns2.hetzner.com']],
            ],
            'rm.example.com' => [
                DNS_A => [['ip' => '1.2.3.4']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->not->toContain('CLOUDFLARE_PROXY_ENABLED');
    });

    it('warns even when wildcard DNS record exists on Cloudflare', function () {
        $resolver = mockResolver([
            'example.com' => [
                DNS_NS => [['target' => 'ada.ns.cloudflare.com']],
            ],
            'rm.example.com' => [
                DNS_A => [['ip' => '104.21.0.1']],
            ],
            'keyse._domainkey.example.com' => [
                DNS_A => [['ip' => '104.21.0.1']],
            ],
            '_cf-proxy-check.example.com' => [
                DNS_A => [['ip' => '104.21.0.1']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->toContain('CLOUDFLARE_PROXY_ENABLED');
    });

    it('does not warn when CNAME checks pass (proxy not an issue)', function () {
        $resolver = mockResolver([
            'example.com' => [
                DNS_NS => [['target' => 'ada.ns.cloudflare.com']],
            ],
            'rm.example.com' => [
                DNS_CNAME => [['target' => Constants::RULE_CNAME_TARGET]],
            ],
            'keyse._domainkey.example.com' => [
                DNS_CNAME => [['target' => Constants::RULE_DKIM_TARGET]],
            ],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=none']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        $codes = array_map(fn ($w) => $w->code, $result->warnings);
        expect($codes)->not->toContain('CLOUDFLARE_PROXY_ENABLED');
    });
});

describe('warnings array', function () {
    it('returns empty warnings when no issues found', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.example.com']]],
            'rm.example.com' => [
                DNS_MX => [['target' => Constants::RULE_MX_HOST, 'pri' => 10]],
                DNS_CNAME => [['target' => Constants::RULE_CNAME_TARGET]],
            ],
            'keyse._domainkey.example.com' => [
                DNS_CNAME => [['target' => Constants::RULE_DKIM_TARGET]],
            ],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=none; rua=mailto:dmarc@rule.se']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect($result->warnings)->toBe([]);
    });

    it('includes warnings in result', function () {
        $resolver = mockResolver([
            'example.com' => [DNS_NS => [['target' => 'ns1.dns.com']]],
            'rm.example.com' => [
                DNS_A => [['ip' => '1.2.3.4']],
            ],
            '_dmarc.example.com' => [
                DNS_TXT => [['txt' => 'v=DMARC1; p=reject; aspf=s']],
            ],
        ]);

        $result = DnsChecker::check('example.com', $resolver);
        expect(count($result->warnings))->toBeGreaterThanOrEqual(2);
        foreach ($result->warnings as $w) {
            expect($w->code)->not->toBeEmpty()
                ->and($w->severity)->not->toBeNull()
                ->and($w->message)->not->toBeEmpty();
        }
    });
});
