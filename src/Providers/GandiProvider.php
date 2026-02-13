<?php

namespace RuleIo\Dns\Providers;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;
use RuleIo\Dns\Contracts\DnsProvider;
use RuleIo\Dns\Data\ProviderRecord;

class GandiProvider implements DnsProvider
{
    private const API = 'https://api.gandi.net/v5';

    private ClientInterface $client;

    public function __construct(
        private readonly string $apiToken,
        private readonly string $domain,
        ?ClientInterface $client = null,
    ) {
        if ($apiToken === '') {
            throw new \InvalidArgumentException('Gandi: apiToken is required');
        }
        if ($domain === '') {
            throw new \InvalidArgumentException('Gandi: domain is required');
        }
        $this->client = $client ?? new Client();
    }

    public function getRecords(string $name): array
    {
        $relative = $this->toRelativeName($name);

        try {
            $data = $this->request('GET', '/livedns/domains/' . urlencode($this->domain) . '/records/' . urlencode($relative));
        } catch (ClientException $e) {
            if ($e->getResponse()->getStatusCode() === 404) {
                return [];
            }
            throw $e;
        }

        $records = [];
        foreach ($data as $rrset) {
            foreach ($rrset['rrset_values'] as $value) {
                $records[] = new ProviderRecord(
                    id: $rrset['rrset_name'] . '/' . $rrset['rrset_type'],
                    type: $rrset['rrset_type'],
                    name: $this->toFqdn($rrset['rrset_name']),
                    value: $value,
                );
            }
        }
        return $records;
    }

    public function createRecord(array $record): ProviderRecord
    {
        $relative = $this->toRelativeName($record['name']);

        $this->request('POST', '/livedns/domains/' . urlencode($this->domain) . '/records', [
            'rrset_name' => $relative,
            'rrset_type' => $record['type'],
            'rrset_ttl' => 300,
            'rrset_values' => [$record['value']],
        ]);

        return new ProviderRecord(
            id: $relative . '/' . $record['type'],
            type: $record['type'],
            name: $this->toFqdn($relative),
            value: $record['value'],
        );
    }

    public function deleteRecord(string $id): void
    {
        $parts = explode('/', $id, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new \InvalidArgumentException("Gandi: invalid record id \"{$id}\"");
        }
        [$name, $type] = $parts;

        $this->request(
            'DELETE',
            '/livedns/domains/' . urlencode($this->domain) . '/records/' . urlencode($name) . '/' . urlencode($type),
        );
    }

    /**
     * @return array{fqdn: string}[]
     */
    public static function listDomains(string $apiToken, ?ClientInterface $client = null): array
    {
        if ($apiToken === '') {
            throw new \InvalidArgumentException('Gandi: apiToken is required');
        }

        $client ??= new Client();
        $response = $client->request('GET', self::API . '/livedns/domains', [
            'headers' => [
                'Authorization' => "Bearer {$apiToken}",
                'Content-Type' => 'application/json',
            ],
        ]);

        $data = json_decode((string) $response->getBody(), true);
        return array_map(fn ($d) => ['fqdn' => $d['fqdn']], $data);
    }

    private function toRelativeName(string $fqdn): string
    {
        $lower = strtolower($fqdn);
        $zoneLower = strtolower($this->domain);

        if ($lower === $zoneLower) {
            return '@';
        }

        $suffix = '.' . $zoneLower;
        if (str_ends_with($lower, $suffix)) {
            return substr($lower, 0, -strlen($suffix));
        }

        return $lower;
    }

    private function toFqdn(string $relativeName): string
    {
        if ($relativeName === '@') {
            return $this->domain;
        }
        return $relativeName . '.' . $this->domain;
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
        return json_decode((string) $response->getBody(), true) ?? [];
    }
}
