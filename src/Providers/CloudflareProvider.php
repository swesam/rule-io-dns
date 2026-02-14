<?php

declare(strict_types=1);

namespace RuleIo\Dns\Providers;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use RuleIo\Dns\Contracts\DnsProvider;
use RuleIo\Dns\Contracts\UpdatableDnsProvider;
use RuleIo\Dns\Data\ProviderRecord;
use RuleIo\Dns\Domain;

class CloudflareProvider implements DnsProvider, UpdatableDnsProvider
{
    private const API = 'https://api.cloudflare.com/client/v4';

    private ?string $resolvedZoneId;

    private ClientInterface $client;

    public function __construct(
        private readonly string $apiToken,
        ?string $zoneId = null,
        private readonly ?string $domain = null,
        ?ClientInterface $client = null,
    ) {
        if ($apiToken === '') {
            throw new \InvalidArgumentException('Cloudflare: apiToken is required');
        }
        if ($zoneId === null && $domain === null) {
            throw new \InvalidArgumentException('Cloudflare: either zoneId or domain is required');
        }
        $this->resolvedZoneId = $zoneId;
        $this->client = $client ?? new Client();
    }

    public function getRecords(string $name): array
    {
        $zoneId = $this->resolveZoneId();
        $data = $this->request('GET', "/zones/{$zoneId}/dns_records?name=" . urlencode($name));

        return array_map(fn (array $r) => new ProviderRecord(
            id: $r['id'],
            type: $r['type'],
            name: $r['name'],
            value: $r['content'],
            proxied: $r['proxied'] ?? null,
        ), $data['result']);
    }

    public function createRecord(array $record): ProviderRecord
    {
        $zoneId = $this->resolveZoneId();
        $data = $this->request('POST', "/zones/{$zoneId}/dns_records", [
            'type' => $record['type'],
            'name' => $record['name'],
            'content' => $record['value'],
            'proxied' => false,
        ]);

        return new ProviderRecord(
            id: $data['result']['id'],
            type: $data['result']['type'],
            name: $data['result']['name'],
            value: $data['result']['content'],
            proxied: $data['result']['proxied'] ?? null,
        );
    }

    public function updateRecord(string $id, array $data): ProviderRecord
    {
        $zoneId = $this->resolveZoneId();
        $response = $this->request('PATCH', "/zones/{$zoneId}/dns_records/{$id}", $data);

        return new ProviderRecord(
            id: $response['result']['id'],
            type: $response['result']['type'],
            name: $response['result']['name'],
            value: $response['result']['content'],
            proxied: $response['result']['proxied'] ?? null,
        );
    }

    public function deleteRecord(string $id): void
    {
        $zoneId = $this->resolveZoneId();
        $this->request('DELETE', "/zones/{$zoneId}/dns_records/{$id}");
    }

    /**
     * @return array{id: string, name: string}[]
     */
    public static function listZones(string $apiToken, ?ClientInterface $client = null): array
    {
        if ($apiToken === '') {
            throw new \InvalidArgumentException('Cloudflare: apiToken is required');
        }

        $client ??= new Client();
        $zones = [];
        $page = 1;

        while (true) {
            $response = $client->request('GET', self::API . "/zones?page={$page}&per_page=50", [
                'headers' => [
                    'Authorization' => "Bearer {$apiToken}",
                    'Content-Type' => 'application/json',
                ],
            ]);

            $data = json_decode((string) $response->getBody(), true);
            if (!$data['success']) {
                $errors = array_map(fn ($e) => "{$e['code']}: {$e['message']}", $data['errors'] ?? []);
                throw new \RuntimeException('Cloudflare API error: ' . (implode(', ', $errors) ?: 'unknown error'));
            }

            foreach ($data['result'] as $z) {
                $zones[] = ['id' => $z['id'], 'name' => $z['name']];
            }

            $info = $data['result_info'] ?? null;
            if (!$info || $page >= $info['total_pages']) {
                break;
            }
            $page++;
        }

        return $zones;
    }

    private function resolveZoneId(): string
    {
        if ($this->resolvedZoneId !== null) {
            return $this->resolvedZoneId;
        }

        $domain = Domain::clean($this->domain);
        $data = $this->request('GET', '/zones?name=' . urlencode($domain));

        if (count($data['result']) === 0) {
            throw new \RuntimeException("Cloudflare: no zone found for domain \"{$domain}\"");
        }

        $this->resolvedZoneId = $data['result'][0]['id'];
        return $this->resolvedZoneId;
    }

    private function request(string $method, string $path, ?array $body = null): array
    {
        $options = [
            'headers' => [
                'Authorization' => "Bearer {$this->apiToken}",
                'Content-Type' => 'application/json',
            ],
        ];

        if ($body !== null) {
            $options['json'] = $body;
        }

        $response = $this->client->request($method, self::API . $path, $options);
        $data = json_decode((string) $response->getBody(), true);

        if (!($data['success'] ?? false)) {
            $errors = array_map(fn ($e) => "{$e['code']}: {$e['message']}", $data['errors'] ?? []);
            throw new \RuntimeException('Cloudflare API error: ' . (implode(', ', $errors) ?: 'unknown error'));
        }

        return $data;
    }
}
