<?php

use RuleIo\Dns\Constants;
use RuleIo\Dns\Contracts\DnsProvider;
use RuleIo\Dns\Contracts\DnsResolver;
use RuleIo\Dns\Data\ProviderRecord;
use RuleIo\Dns\DnsProvisioner;

function allMissingResolver(): DnsResolver
{
    return new class implements DnsResolver {
        public function getRecord(string $hostname, int $type): array|false
        {
            return false;
        }
    };
}

function allPassingResolver(): DnsResolver
{
    return new class implements DnsResolver {
        public function getRecord(string $hostname, int $type): array|false
        {
            return match (true) {
                str_ends_with($hostname, '.com') && $type === DNS_NS => [['target' => 'ns1.dns.com']],
                $hostname === 'rm.example.com' && $type === DNS_MX => [['target' => Constants::RULE_MX_HOST, 'pri' => 10]],
                $hostname === 'rm.example.com' && $type === DNS_CNAME => [['target' => Constants::RULE_CNAME_TARGET]],
                $hostname === 'keyse._domainkey.example.com' && $type === DNS_CNAME => [['target' => Constants::RULE_DKIM_TARGET]],
                $hostname === '_dmarc.example.com' && $type === DNS_TXT => [['txt' => 'v=DMARC1; p=none; rua=mailto:dmarc@rule.se; ruf=mailto:authfail@rule.se']],
                default => false,
            };
        }
    };
}

function createMockProvider(array $existing = []): DnsProvider
{
    return new class($existing) implements DnsProvider {
        public array $created = [];
        public array $deletedIds = [];
        private int $nextId = 1;

        public function __construct(private readonly array $existing) {}

        public function getRecords(string $name): array
        {
            return $this->existing[$name] ?? [];
        }

        public function createRecord(array $record): ProviderRecord
        {
            $this->created[] = $record;
            return new ProviderRecord(
                id: 'new-' . $this->nextId++,
                type: $record['type'],
                name: $record['name'],
                value: $record['value'],
            );
        }

        public function deleteRecord(string $id): void
        {
            $this->deletedIds[] = $id;
        }
    };
}

it('creates all 3 records when everything is missing', function () {
    $provider = createMockProvider();
    $result = DnsProvisioner::provision('example.com', $provider, allMissingResolver());

    expect($result->domain)->toBe('example.com')
        ->and($result->created)->toHaveCount(3)
        ->and($result->deleted)->toHaveCount(0)
        ->and($result->skipped)->toHaveCount(0);

    expect($provider->created)->toHaveCount(3)
        ->and($provider->created[0])->toBe(['type' => 'CNAME', 'name' => 'rm.example.com', 'value' => Constants::RULE_CNAME_TARGET])
        ->and($provider->created[1])->toBe(['type' => 'CNAME', 'name' => 'keyse._domainkey.example.com', 'value' => Constants::RULE_DKIM_TARGET])
        ->and($provider->created[2])->toBe(['type' => 'TXT', 'name' => '_dmarc.example.com', 'value' => Constants::RULE_DMARC_POLICY]);
});

it('skips all records when everything passes', function () {
    $provider = createMockProvider();
    $result = DnsProvisioner::provision('example.com', $provider, allPassingResolver());

    expect($result->created)->toHaveCount(0)
        ->and($result->deleted)->toHaveCount(0)
        ->and($result->skipped)->toHaveCount(3);
    expect($provider->created)->toHaveCount(0);
});

it('deletes conflicting records before creating', function () {
    $provider = createMockProvider([
        'rm.example.com' => [
            new ProviderRecord(id: 'old-1', type: 'A', name: 'rm.example.com', value: '1.2.3.4'),
        ],
    ]);
    $result = DnsProvisioner::provision('example.com', $provider, allMissingResolver());

    expect($result->deleted)->toHaveCount(1)
        ->and($result->deleted[0]->id)->toBe('old-1')
        ->and($provider->deletedIds)->toBe(['old-1'])
        ->and($result->created)->toHaveCount(3);
});

it('skips record if provider already has the correct one', function () {
    $provider = createMockProvider([
        'rm.example.com' => [
            new ProviderRecord(
                id: 'existing-cname',
                type: 'CNAME',
                name: 'rm.example.com',
                value: Constants::RULE_CNAME_TARGET,
            ),
        ],
    ]);
    $result = DnsProvisioner::provision('example.com', $provider, allMissingResolver());

    // MX/SPF record already exists at provider → skipped (even though checkDns said missing)
    expect($result->created)->toHaveCount(2)
        ->and($result->skipped)->toHaveCount(1)
        ->and($result->skipped[0]->name)->toBe('rm.example.com')
        ->and($provider->deletedIds)->toHaveCount(0);
});

it('passes through warnings from checkDns', function () {
    // Use a resolver that returns org DMARC with aspf=s to trigger a warning
    $resolver = new class implements DnsResolver {
        public function getRecord(string $hostname, int $type): array|false
        {
            if ($hostname === '_dmarc.example.com' && $type === DNS_TXT) {
                return [['txt' => 'v=DMARC1; p=none; aspf=s']];
            }
            return false;
        }
    };

    $provider = createMockProvider();
    $result = DnsProvisioner::provision('example.com', $provider, $resolver);

    $codes = array_map(fn ($w) => $w->code, $result->warnings);
    expect($codes)->toContain('STRICT_SPF_ALIGNMENT');
});

it('deletes multiple conflicting records at the same name', function () {
    $provider = createMockProvider([
        'rm.example.com' => [
            new ProviderRecord(id: 'old-a', type: 'A', name: 'rm.example.com', value: '1.2.3.4'),
            new ProviderRecord(id: 'old-txt', type: 'TXT', name: 'rm.example.com', value: 'v=spf1 -all'),
        ],
    ]);
    $result = DnsProvisioner::provision('example.com', $provider, allMissingResolver());

    expect($result->deleted)->toHaveCount(2)
        ->and($provider->deletedIds)->toContain('old-a')
        ->and($provider->deletedIds)->toContain('old-txt');
});

it('treats trailing-dot FQDN values as equivalent', function () {
    $provider = createMockProvider([
        'rm.example.com' => [
            new ProviderRecord(
                id: 'existing-cname',
                type: 'CNAME',
                name: 'rm.example.com',
                value: Constants::RULE_CNAME_TARGET . '.',
            ),
        ],
    ]);
    $result = DnsProvisioner::provision('example.com', $provider, allMissingResolver());

    // Trailing-dot value should match → no delete, no re-create for this record
    expect($provider->deletedIds)->toHaveCount(0)
        ->and($result->created)->toHaveCount(2)
        ->and($result->skipped[0]->name)->toBe('rm.example.com');
});
