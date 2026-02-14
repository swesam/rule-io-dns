<?php

declare(strict_types=1);

namespace RuleIo\Dns\Providers;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use RuleIo\Dns\Contracts\DnsProvider;
use RuleIo\Dns\Data\ProviderRecord;
use RuleIo\Dns\Domain;

class IonosProvider implements DnsProvider
{
    private const API = 'https://dns.de.api.ionos.com/v1';

    private ?string $resolvedZoneId;

    private ClientInterface $client;

    public function __construct(
        private readonly string $apiKey,
        ?string $zoneId = null,
        private readonly ?string $domain = null,
        ?ClientInterface $client = null,
    ) {
        if ($apiKey === '') {
            throw new \InvalidArgumentException('IONOS: apiKey is required');
        }
        if ($zoneId === null && $domain === null) {
            throw new \InvalidArgumentException('IONOS: either zoneId or domain is required');
        }
        $this->resolvedZoneId = $zoneId;
        $this->client = $client ?? new Client();
    }

    public function getRecords(string $name): array
    {
        $zoneId = $this->resolveZoneId();
        $data = $this->request('GET', "/zones/{$zoneId}?recordName=" . urlencode($name) . '&recordType=');

        return array_map(fn (array $r) => new ProviderRecord(
            id: $r['id'],
            type: $r['type'],
            name: $r['name'],
            value: $r['content'],
        ), $data['records']);
    }

    public function createRecord(array $record): ProviderRecord
    {
        $zoneId = $this->resolveZoneId();
        $data = $this->requestRaw('POST', "/zones/{$zoneId}/records", [[
            'name' => $record['name'],
            'type' => $record['type'],
            'content' => $record['value'],
            'ttl' => 3600,
            'prio' => 0,
        ]]);

        if (!is_array($data) || count($data) === 0) {
            throw new \RuntimeException('IONOS: createRecord returned empty response');
        }

        $r = $data[0];
        return new ProviderRecord(
            id: $r['id'],
            type: $r['type'],
            name: $r['name'],
            value: $r['content'],
        );
    }

    public function deleteRecord(string $id): void
    {
        $zoneId = $this->resolveZoneId();
        $this->client->request('DELETE', self::API . "/zones/{$zoneId}/records/{$id}", [
            'headers' => [
                'X-API-Key' => $this->apiKey,
                'Content-Type' => 'application/json',
            ],
        ]);
    }

    /**
     * @return array{id: string, name: string, type: string}[]
     */
    public static function listZones(string $apiKey, ?ClientInterface $client = null): array
    {
        if ($apiKey === '') {
            throw new \InvalidArgumentException('IONOS: apiKey is required');
        }

        $client ??= new Client();
        $response = $client->request('GET', self::API . '/zones', [
            'headers' => [
                'X-API-Key' => $apiKey,
                'Content-Type' => 'application/json',
            ],
        ]);

        $data = json_decode((string) $response->getBody(), true);
        return array_map(fn ($z) => ['id' => $z['id'], 'name' => $z['name'], 'type' => $z['type']], $data);
    }

    private function resolveZoneId(): string
    {
        if ($this->resolvedZoneId !== null) {
            return $this->resolvedZoneId;
        }

        $domain = Domain::clean($this->domain);
        $response = $this->client->request('GET', self::API . '/zones', [
            'headers' => [
                'X-API-Key' => $this->apiKey,
                'Content-Type' => 'application/json',
            ],
        ]);

        $zones = json_decode((string) $response->getBody(), true);
        foreach ($zones as $z) {
            if ($z['name'] === $domain) {
                $this->resolvedZoneId = $z['id'];
                return $this->resolvedZoneId;
            }
        }

        throw new \RuntimeException("IONOS: no zone found for domain \"{$domain}\"");
    }

    private function request(string $method, string $path): array
    {
        $response = $this->client->request($method, self::API . $path, [
            'headers' => [
                'X-API-Key' => $this->apiKey,
                'Content-Type' => 'application/json',
            ],
        ]);
        return json_decode((string) $response->getBody(), true);
    }

    private function requestRaw(string $method, string $path, array $body): array
    {
        $response = $this->client->request($method, self::API . $path, [
            'headers' => [
                'X-API-Key' => $this->apiKey,
                'Content-Type' => 'application/json',
            ],
            'json' => $body,
        ]);
        return json_decode((string) $response->getBody(), true);
    }
}
