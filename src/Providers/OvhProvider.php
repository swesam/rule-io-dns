<?php

namespace RuleIo\Dns\Providers;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use RuleIo\Dns\Contracts\DnsProvider;
use RuleIo\Dns\Data\ProviderRecord;

class OvhProvider implements DnsProvider
{
    private const API = 'https://eu.api.ovh.com/1.0';

    private ClientInterface $client;

    public function __construct(
        private readonly string $appKey,
        private readonly string $appSecret,
        private readonly string $consumerKey,
        private readonly string $zoneName,
        ?ClientInterface $client = null,
    ) {
        if ($appKey === '') {
            throw new \InvalidArgumentException('OVH: appKey is required');
        }
        if ($appSecret === '') {
            throw new \InvalidArgumentException('OVH: appSecret is required');
        }
        if ($consumerKey === '') {
            throw new \InvalidArgumentException('OVH: consumerKey is required');
        }
        if ($zoneName === '') {
            throw new \InvalidArgumentException('OVH: zoneName is required');
        }
        $this->client = $client ?? new Client();
    }

    public function getRecords(string $name): array
    {
        $subDomain = $this->toSubDomain($name);
        $ids = $this->ovhRequest(
            'GET',
            '/domain/zone/' . urlencode($this->zoneName) . '/record?subDomain=' . urlencode($subDomain),
        );

        $records = [];
        foreach ($ids as $id) {
            $detail = $this->ovhRequest(
                'GET',
                '/domain/zone/' . urlencode($this->zoneName) . '/record/' . $id,
            );
            $records[] = new ProviderRecord(
                id: (string) $detail['id'],
                type: $detail['fieldType'],
                name: $this->toFqdn($detail['subDomain']),
                value: $detail['target'],
            );
        }

        return $records;
    }

    public function createRecord(array $record): ProviderRecord
    {
        $subDomain = $this->toSubDomain($record['name']);
        $detail = $this->ovhRequest(
            'POST',
            '/domain/zone/' . urlencode($this->zoneName) . '/record',
            [
                'fieldType' => $record['type'],
                'subDomain' => $subDomain,
                'target' => $record['value'],
                'ttl' => 3600,
            ],
        );

        // Refresh the zone to apply changes
        $this->ovhRequest('POST', '/domain/zone/' . urlencode($this->zoneName) . '/refresh');

        return new ProviderRecord(
            id: (string) $detail['id'],
            type: $detail['fieldType'],
            name: $this->toFqdn($detail['subDomain']),
            value: $detail['target'],
        );
    }

    public function deleteRecord(string $id): void
    {
        $this->ovhRequest(
            'DELETE',
            '/domain/zone/' . urlencode($this->zoneName) . '/record/' . $id,
        );

        // Refresh the zone to apply changes
        $this->ovhRequest('POST', '/domain/zone/' . urlencode($this->zoneName) . '/refresh');
    }

    private function toSubDomain(string $fqdn): string
    {
        $suffix = '.' . $this->zoneName;
        if ($fqdn === $this->zoneName) {
            return '';
        }
        if (str_ends_with($fqdn, $suffix)) {
            return substr($fqdn, 0, -strlen($suffix));
        }
        return $fqdn;
    }

    private function toFqdn(string $subDomain): string
    {
        if ($subDomain === '') {
            return $this->zoneName;
        }
        return $subDomain . '.' . $this->zoneName;
    }

    private function getServerTime(): int
    {
        $response = $this->client->request('GET', self::API . '/auth/time');
        return (int) json_decode((string) $response->getBody(), true);
    }

    private static function signature(string $appSecret, string $consumerKey, string $method, string $url, string $body, int $timestamp): string
    {
        $raw = "{$appSecret}+{$consumerKey}+{$method}+{$url}+{$body}+{$timestamp}";
        return '$1$' . sha1($raw);
    }

    private function ovhRequest(string $method, string $path, ?array $body = null): mixed
    {
        $url = self::API . $path;
        $bodyStr = $body !== null ? json_encode($body) : '';
        $timestamp = $this->getServerTime();
        $sig = self::signature($this->appSecret, $this->consumerKey, $method, $url, $bodyStr, $timestamp);

        $options = [
            'headers' => [
                'X-Ovh-Application' => $this->appKey,
                'X-Ovh-Consumer' => $this->consumerKey,
                'X-Ovh-Timestamp' => (string) $timestamp,
                'X-Ovh-Signature' => $sig,
                'Content-Type' => 'application/json',
            ],
        ];

        if ($bodyStr !== '') {
            $options['body'] = $bodyStr;
        }

        $response = $this->client->request($method, $url, $options);
        $text = (string) $response->getBody();
        if ($text === '') {
            return null;
        }
        return json_decode($text, true);
    }
}
