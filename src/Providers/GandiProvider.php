<?php

namespace RuleIo\Dns\Providers;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;
use RuleIo\Dns\Contracts\DnsProvider;
use RuleIo\Dns\Data\ProviderRecord;
use RuleIo\Dns\Domain;

class GandiProvider implements DnsProvider
{
    private const API = 'https://api.gandi.net/v5';

    private ClientInterface $client;

    private string $domain;

    public function __construct(
        private readonly string $apiToken,
        string $domain,
        ?ClientInterface $client = null,
    ) {
        if ($apiToken === '') {
            throw new \InvalidArgumentException('Gandi: apiToken is required');
        }
        if ($domain === '') {
            throw new \InvalidArgumentException('Gandi: domain is required');
        }
        $this->domain = Domain::clean($domain);
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
                    id: $rrset['rrset_name'] . '/' . $rrset['rrset_type'] . '/' . $value,
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
            id: $relative . '/' . $record['type'] . '/' . $record['value'],
            type: $record['type'],
            name: $this->toFqdn($relative),
            value: $record['value'],
        );
    }

    public function deleteRecord(string $id): void
    {
        $firstSlash = strpos($id, '/');
        $secondSlash = $firstSlash !== false ? strpos($id, '/', $firstSlash + 1) : false;
        if ($firstSlash === false || $secondSlash === false) {
            throw new \InvalidArgumentException("Gandi: invalid record id \"{$id}\"");
        }

        $name = substr($id, 0, $firstSlash);
        $type = substr($id, $firstSlash + 1, $secondSlash - $firstSlash - 1);
        $value = substr($id, $secondSlash + 1);

        if ($name === '' || $type === '' || $value === '') {
            throw new \InvalidArgumentException("Gandi: invalid record id \"{$id}\"");
        }

        $rrsetPath = '/livedns/domains/' . urlencode($this->domain) . '/records/' . urlencode($name) . '/' . urlencode($type);

        // Fetch current rrset to check for other values
        try {
            $rrset = $this->request('GET', $rrsetPath);
        } catch (ClientException $e) {
            if ($e->getResponse()->getStatusCode() === 404) {
                return; // Already gone
            }
            throw $e;
        }

        $domainLikeTypes = ['CNAME', 'NS', 'PTR', 'MX', 'SRV'];
        $isDomainLike = in_array($type, $domainLikeTypes, true);

        $normalizeValue = function (string $v) use ($isDomainLike): string {
            if (! $isDomainLike) {
                return $v;
            }
            return rtrim(strtolower($v), '.');
        };

        $normalizedValue = $normalizeValue($value);
        $remaining = array_values(array_filter(
            $rrset['rrset_values'],
            fn (string $v) => $normalizeValue($v) !== $normalizedValue,
        ));

        if (count($remaining) === 0) {
            $this->request('DELETE', $rrsetPath);
        } else {
            $this->request('PUT', $rrsetPath, [
                'rrset_ttl' => $rrset['rrset_ttl'],
                'rrset_values' => $remaining,
            ]);
        }
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
