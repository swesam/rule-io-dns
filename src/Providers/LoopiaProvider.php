<?php

namespace RuleIo\Dns\Providers;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use RuleIo\Dns\Contracts\DnsProvider;
use RuleIo\Dns\Data\ProviderRecord;

class LoopiaProvider implements DnsProvider
{
    private const API = 'https://api.loopia.se/RPCSERV';

    private ClientInterface $client;

    public function __construct(
        private readonly string $username,
        private readonly string $password,
        private readonly string $domain,
        ?ClientInterface $client = null,
    ) {
        if ($username === '') {
            throw new \InvalidArgumentException('Loopia: username is required');
        }
        if ($password === '') {
            throw new \InvalidArgumentException('Loopia: password is required');
        }
        if ($domain === '') {
            throw new \InvalidArgumentException('Loopia: domain is required');
        }
        $this->client = $client ?? new Client();
    }

    public function getRecords(string $name): array
    {
        $subdomain = $this->toSubdomain($name);

        // Ensure the subdomain zone exists — without it, records won't resolve.
        // addSubdomain is idempotent (returns OK or DOMAIN_OCCUPIED).
        $this->ensureSubdomain($subdomain);

        $result = $this->call('getZoneRecords', [$this->domain, $subdomain]);

        if (is_string($result)) {
            throw new \RuntimeException("Loopia: getZoneRecords failed: {$result}");
        }

        return array_map(fn (array $r) => new ProviderRecord(
            id: $subdomain . ':' . $r['record_id'],
            type: $r['type'],
            name: $name,
            value: $r['rdata'],
        ), $result);
    }

    public function createRecord(array $record): ProviderRecord
    {
        $subdomain = $this->toSubdomain($record['name']);

        $this->ensureSubdomain($subdomain);

        $loopiaRecord = [
            'type' => $record['type'],
            'ttl' => 300,
            'priority' => 0,
            'rdata' => $record['value'],
        ];

        $result = $this->call('addZoneRecord', [$this->domain, $subdomain, $loopiaRecord]);

        if ($result !== 'OK') {
            throw new \RuntimeException("Loopia: addZoneRecord failed: {$result}");
        }

        // Loopia does not return the created record, so fetch to find it
        $records = $this->call('getZoneRecords', [$this->domain, $subdomain]);

        if (is_string($records)) {
            throw new \RuntimeException("Loopia: getZoneRecords failed: {$records}");
        }

        foreach ($records as $r) {
            if ($r['type'] === $record['type'] && rtrim($r['rdata'], '.') === rtrim($record['value'], '.')) {
                return new ProviderRecord(
                    id: $subdomain . ':' . $r['record_id'],
                    type: $r['type'],
                    name: $record['name'],
                    value: $r['rdata'],
                );
            }
        }

        throw new \RuntimeException('Loopia: record was created but could not be found');
    }

    public function deleteRecord(string $id): void
    {
        $sep = strrpos($id, ':');
        if ($sep === false) {
            throw new \InvalidArgumentException("Loopia: invalid record id \"{$id}\"");
        }
        $subdomain = substr($id, 0, $sep);
        $suffix = substr($id, $sep + 1);
        if (!ctype_digit($suffix)) {
            throw new \InvalidArgumentException("Loopia: invalid record id \"{$id}\"");
        }
        $recordId = (int) $suffix;

        $result = $this->call('removeZoneRecord', [$this->domain, $subdomain, $recordId]);

        if ($result !== 'OK') {
            throw new \RuntimeException("Loopia: removeZoneRecord failed: {$result}");
        }
    }

    private function ensureSubdomain(string $subdomain): void
    {
        $result = $this->call('addSubdomain', [$this->domain, $subdomain]);
        if ($result !== 'OK' && $result !== 'DOMAIN_OCCUPIED') {
            throw new \RuntimeException("Loopia: addSubdomain failed: {$result}");
        }
    }

    private function toSubdomain(string $fqdn): string
    {
        $lower = strtolower($fqdn);
        $domainLower = strtolower($this->domain);
        if ($lower === $domainLower) {
            return '@';
        }
        $suffix = '.' . $domainLower;
        if (str_ends_with($lower, $suffix)) {
            return substr($lower, 0, -strlen($suffix));
        }
        return $lower;
    }

    private function call(string $method, array $extraParams): mixed
    {
        $params = array_merge([$this->username, $this->password], $extraParams);
        $body = self::buildXmlRpcRequest($method, $params);

        $response = $this->client->request('POST', self::API, [
            'headers' => ['Content-Type' => 'text/xml'],
            'body' => $body,
        ]);

        $xml = (string) $response->getBody();
        return self::parseXmlRpcResponse($xml);
    }

    private static function buildXmlRpcRequest(string $method, array $params): string
    {
        $parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<methodCall>',
            "<methodName>{$method}</methodName>",
            '<params>',
        ];

        foreach ($params as $p) {
            $parts[] = '<param>' . self::serializeValue($p) . '</param>';
        }

        $parts[] = '</params>';
        $parts[] = '</methodCall>';

        return implode('', $parts);
    }

    private static function serializeValue(mixed $value): string
    {
        if (is_string($value)) {
            return '<value><string>' . self::escapeXml($value) . '</string></value>';
        }
        if (is_int($value)) {
            return "<value><int>{$value}</int></value>";
        }
        if (is_float($value)) {
            return "<value><double>{$value}</double></value>";
        }
        if (is_bool($value)) {
            $v = $value ? 1 : 0;
            return "<value><boolean>{$v}</boolean></value>";
        }
        if (is_array($value) && self::isAssoc($value)) {
            $members = '';
            foreach ($value as $k => $v) {
                $members .= '<member><name>' . self::escapeXml((string) $k) . '</name>' . self::serializeValue($v) . '</member>';
            }
            return "<value><struct>{$members}</struct></value>";
        }
        if (is_array($value)) {
            $data = '';
            foreach ($value as $v) {
                $data .= self::serializeValue($v);
            }
            return "<value><array><data>{$data}</data></array></value>";
        }
        return '<value><string>' . self::escapeXml((string) $value) . '</string></value>';
    }

    private static function isAssoc(array $arr): bool
    {
        if ($arr === []) {
            return false;
        }
        return array_keys($arr) !== range(0, count($arr) - 1);
    }

    private static function escapeXml(string $s): string
    {
        return htmlspecialchars($s, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }

    private static function extractFault(string $xml): ?string
    {
        if (!preg_match('/<fault>([\s\S]*?)<\/fault>/', $xml, $faultMatch)) {
            return null;
        }
        $code = 'unknown';
        $msg = 'unknown error';
        if (preg_match('/<name>faultCode<\/name>\s*<value><int>(\d+)<\/int><\/value>/', $faultMatch[1], $codeMatch)) {
            $code = $codeMatch[1];
        }
        if (preg_match('/<name>faultString<\/name>\s*<value><string>([\s\S]*?)<\/string><\/value>/', $faultMatch[1], $stringMatch)) {
            $msg = $stringMatch[1];
        }
        return "{$code}: {$msg}";
    }

    private static function parseValue(string $xml): mixed
    {
        $inner = trim(preg_replace('/^\s*<value>\s*/', '', preg_replace('/\s*<\/value>\s*$/', '', $xml)));

        if (str_starts_with($inner, '<array>')) {
            if (!preg_match('/<data>([\s\S]*)<\/data>/', $inner, $dataMatch)) {
                return [];
            }
            $values = [];
            $content = $dataMatch[1];
            $depth = 0;
            $start = -1;
            $len = strlen($content);
            for ($i = 0; $i < $len; $i++) {
                if (substr($content, $i, 7) === '<value>') {
                    if ($depth === 0) {
                        $start = $i;
                    }
                    $depth++;
                } elseif (substr($content, $i, 8) === '</value>') {
                    $depth--;
                    if ($depth === 0 && $start !== -1) {
                        $values[] = self::parseValue(substr($content, $start, $i + 8 - $start));
                        $start = -1;
                    }
                }
            }
            return $values;
        }

        if (str_starts_with($inner, '<struct>')) {
            $obj = [];
            if (preg_match_all('/<member>\s*<name>([\s\S]*?)<\/name>\s*([\s\S]*?)\s*<\/member>/s', $inner, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $m) {
                    $name = $m[1];
                    if (preg_match('/<value>([\s\S]*)<\/value>/', $m[2], $valueMatch)) {
                        $obj[$name] = self::parseValue('<value>' . $valueMatch[1] . '</value>');
                    }
                }
            }
            return $obj;
        }

        if (preg_match('/^<string>([\s\S]*?)<\/string>$/', $inner, $m)) {
            return $m[1];
        }
        if (preg_match('/^<(?:int|i4)>([\s\S]*?)<\/(?:int|i4)>$/', $inner, $m)) {
            return (int) $m[1];
        }
        if (preg_match('/^<double>([\s\S]*?)<\/double>$/', $inner, $m)) {
            return (float) $m[1];
        }
        if (preg_match('/^<boolean>([\s\S]*?)<\/boolean>$/', $inner, $m)) {
            return $m[1] === '1';
        }

        return $inner;
    }

    private static function parseXmlRpcResponse(string $xml): mixed
    {
        $fault = self::extractFault($xml);
        if ($fault !== null) {
            throw new \RuntimeException("Loopia: XML-RPC fault {$fault}");
        }

        if (!preg_match('/<params>([\s\S]*?)<\/params>/', $xml, $paramsMatch)) {
            throw new \RuntimeException('Loopia: invalid XML-RPC response');
        }

        if (!preg_match('/<param>\s*<value>([\s\S]*?)<\/value>\s*<\/param>/', $paramsMatch[1], $paramMatch)) {
            throw new \RuntimeException('Loopia: invalid XML-RPC response');
        }

        return self::parseValue('<value>' . $paramMatch[1] . '</value>');
    }
}
