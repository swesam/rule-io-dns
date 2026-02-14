<?php

declare(strict_types=1);

namespace RuleIo\Dns\Providers;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use RuleIo\Dns\Contracts\DnsProvider;
use RuleIo\Dns\Data\ProviderRecord;
use RuleIo\Dns\Domain;

class HetznerProvider implements DnsProvider
{
    private const API = 'https://dns.hetzner.com/api/v1';

    private ?string $resolvedZoneId;

    private ClientInterface $client;

    public function __construct(
        private readonly string $apiToken,
        ?string $zoneId = null,
        private readonly ?string $domain = null,
        ?ClientInterface $client = null,
    ) {
        if ($apiToken === '') {
            throw new \InvalidArgumentException('Hetzner: apiToken is required');
        }
        if ($zoneId === null && $domain === null) {
            throw new \InvalidArgumentException('Hetzner: either zoneId or domain is required');
        }
        $this->resolvedZoneId = $zoneId;
        $this->client = $client ?? new Client();
    }

    public function getRecords(string $name): array
    {
        $zoneId = $this->resolveZoneId();
        $data = $this->request('GET', "/records?zone_id=" . urlencode($zoneId));

        $records = [];
        foreach ($data['records'] as $r) {
            if ($r['name'] === $name) {
                $records[] = new ProviderRecord(
                    id: $r['id'],
                    type: $r['type'],
                    name: $r['name'],
                    value: $r['value'],
                );
            }
        }
        return $records;
    }

    public function createRecord(array $record): ProviderRecord
    {
        $zoneId = $this->resolveZoneId();
        $data = $this->request('POST', '/records', [
            'zone_id' => $zoneId,
            'type' => $record['type'],
            'name' => $record['name'],
            'value' => $record['value'],
            'ttl' => 300,
        ]);

        return new ProviderRecord(
            id: $data['record']['id'],
            type: $data['record']['type'],
            name: $data['record']['name'],
            value: $data['record']['value'],
        );
    }

    public function deleteRecord(string $id): void
    {
        $this->request('DELETE', "/records/{$id}");
    }

    /**
     * @return array{id: string, name: string}[]
     */
    public static function listZones(string $apiToken, ?ClientInterface $client = null): array
    {
        if ($apiToken === '') {
            throw new \InvalidArgumentException('Hetzner: apiToken is required');
        }

        $client ??= new Client();
        $response = $client->request('GET', self::API . '/zones', [
            'headers' => [
                'Auth-API-Token' => $apiToken,
                'Content-Type' => 'application/json',
            ],
        ]);

        $data = json_decode((string) $response->getBody(), true);
        return array_map(fn ($z) => ['id' => $z['id'], 'name' => $z['name']], $data['zones']);
    }

    private function resolveZoneId(): string
    {
        if ($this->resolvedZoneId !== null) {
            return $this->resolvedZoneId;
        }

        $domain = Domain::clean($this->domain);
        $data = $this->request('GET', '/zones?name=' . urlencode($domain));

        if (count($data['zones']) === 0) {
            throw new \RuntimeException("Hetzner: no zone found for domain \"{$domain}\"");
        }

        $this->resolvedZoneId = $data['zones'][0]['id'];
        return $this->resolvedZoneId;
    }

    private function request(string $method, string $path, ?array $body = null): array
    {
        $options = [
            'headers' => [
                'Auth-API-Token' => $this->apiToken,
                'Content-Type' => 'application/json',
            ],
        ];

        if ($body !== null) {
            $options['json'] = $body;
        }

        $response = $this->client->request($method, self::API . $path, $options);
        return json_decode((string) $response->getBody(), true) ?? [];
    }
}
