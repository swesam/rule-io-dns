<?php

declare(strict_types=1);

namespace RuleIo\Dns\Providers;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use RuleIo\Dns\Contracts\DnsProvider;
use RuleIo\Dns\Data\ProviderRecord;
use RuleIo\Dns\Domain;

class DomeneshopProvider implements DnsProvider
{
    private const API = 'https://api.domeneshop.no/v0';

    private ?int $resolvedDomainId;

    private ?string $resolvedDomainName = null;

    private ClientInterface $client;

    public function __construct(
        private readonly string $token,
        private readonly string $secret,
        ?int $domainId = null,
        private readonly ?string $domain = null,
        ?ClientInterface $client = null,
    ) {
        if ($token === '') {
            throw new \InvalidArgumentException('Domeneshop: token is required');
        }
        if ($secret === '') {
            throw new \InvalidArgumentException('Domeneshop: secret is required');
        }
        if ($domainId === null && $domain === null) {
            throw new \InvalidArgumentException('Domeneshop: either domainId or domain is required');
        }
        $this->resolvedDomainId = $domainId;
        if ($domain !== null) {
            $this->resolvedDomainName = Domain::clean($domain);
        }
        $this->client = $client ?? new Client();
    }

    public function getRecords(string $name): array
    {
        $this->ensureDomainResolved();
        $host = $this->toRelativeHost($name);

        $data = $this->request('GET', "/domains/{$this->resolvedDomainId}/dns?host=" . urlencode($host));

        return array_map(fn (array $r) => new ProviderRecord(
            id: (string) $r['id'],
            type: $r['type'],
            name: $this->toFqdn($r['host']),
            value: $r['data'],
        ), $data);
    }

    public function createRecord(array $record): ProviderRecord
    {
        $this->ensureDomainResolved();
        $host = $this->toRelativeHost($record['name']);

        $data = $this->request('POST', "/domains/{$this->resolvedDomainId}/dns", [
            'host' => $host,
            'type' => $record['type'],
            'data' => $record['value'],
            'ttl' => 3600,
        ]);

        return new ProviderRecord(
            id: (string) $data['id'],
            type: $data['type'],
            name: $this->toFqdn($data['host']),
            value: $data['data'],
        );
    }

    public function deleteRecord(string $id): void
    {
        $this->ensureDomainResolved();

        $this->client->request('DELETE', self::API . "/domains/{$this->resolvedDomainId}/dns/{$id}", [
            'headers' => [
                'Authorization' => 'Basic ' . base64_encode($this->token . ':' . $this->secret),
                'Content-Type' => 'application/json',
            ],
        ]);
    }

    /**
     * @return array{id: int, domain: string}[]
     */
    public static function listDomains(string $token, string $secret, ?ClientInterface $client = null): array
    {
        if ($token === '' || $secret === '') {
            throw new \InvalidArgumentException('Domeneshop: token and secret are required');
        }

        $client ??= new Client();
        $response = $client->request('GET', self::API . '/domains', [
            'headers' => [
                'Authorization' => 'Basic ' . base64_encode($token . ':' . $secret),
                'Content-Type' => 'application/json',
            ],
        ]);

        $data = json_decode((string) $response->getBody(), true);
        return array_map(fn ($d) => ['id' => $d['id'], 'domain' => $d['domain']], $data);
    }

    private function ensureDomainResolved(): void
    {
        if ($this->resolvedDomainId !== null && $this->resolvedDomainName !== null) {
            return;
        }

        if ($this->resolvedDomainId !== null && $this->resolvedDomainName === null) {
            // domainId was provided but not domain name — look it up
            $domains = $this->request('GET', '/domains');
            foreach ($domains as $d) {
                if ($d['id'] === $this->resolvedDomainId) {
                    $this->resolvedDomainName = $d['domain'];
                    return;
                }
            }
            throw new \RuntimeException("Domeneshop: no domain found for ID {$this->resolvedDomainId}");
        }

        // Look up by domain name
        $domain = Domain::clean($this->domain);
        $domains = $this->request('GET', '/domains');
        foreach ($domains as $d) {
            if (strtolower($d['domain']) === $domain) {
                $this->resolvedDomainId = $d['id'];
                $this->resolvedDomainName = $d['domain'];
                return;
            }
        }

        throw new \RuntimeException("Domeneshop: no domain found for \"{$domain}\"");
    }

    private function toRelativeHost(string $fqdn): string
    {
        $lower = strtolower($fqdn);
        $domainLower = strtolower($this->resolvedDomainName);

        if ($lower === $domainLower) {
            return '@';
        }

        $suffix = '.' . $domainLower;
        if (str_ends_with($lower, $suffix)) {
            return substr($lower, 0, -strlen($suffix));
        }

        return $lower;
    }

    private function toFqdn(string $host): string
    {
        if ($host === '@' || $host === '') {
            return $this->resolvedDomainName;
        }
        return $host . '.' . $this->resolvedDomainName;
    }

    private function request(string $method, string $path, ?array $body = null): array
    {
        $options = [
            'headers' => [
                'Authorization' => 'Basic ' . base64_encode($this->token . ':' . $this->secret),
                'Content-Type' => 'application/json',
            ],
        ];

        if ($body !== null) {
            $options['json'] = $body;
        }

        $response = $this->client->request($method, self::API . $path, $options);

        if ($response->getStatusCode() === 204) {
            return [];
        }

        return json_decode((string) $response->getBody(), true) ?? [];
    }
}
