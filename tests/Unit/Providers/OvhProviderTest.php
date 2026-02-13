<?php

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use RuleIo\Dns\Providers\OvhProvider;

function ovhClient(array &$history, Response ...$responses): Client
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));
    return new Client(['handler' => $stack]);
}

function ovhTime(int $timestamp = 1700000000): Response
{
    return new Response(200, [], json_encode($timestamp));
}

function ovhOk(mixed $data): Response
{
    return new Response(200, [], $data !== null ? json_encode($data) : '');
}

function ovhEmpty(): Response
{
    return new Response(200, [], '');
}

describe('OvhProvider', function () {
    $baseArgs = [
        'appKey' => 'ak-123',
        'appSecret' => 'as-secret',
        'consumerKey' => 'ck-456',
        'zoneName' => 'example.com',
    ];

    describe('validation', function () use ($baseArgs) {
        it('throws if appKey is missing', function () use ($baseArgs) {
            expect(fn () => new OvhProvider(...array_merge($baseArgs, ['appKey' => ''])))->toThrow(
                InvalidArgumentException::class,
                'OVH: appKey is required'
            );
        });

        it('throws if appSecret is missing', function () use ($baseArgs) {
            expect(fn () => new OvhProvider(...array_merge($baseArgs, ['appSecret' => ''])))->toThrow(
                InvalidArgumentException::class,
                'OVH: appSecret is required'
            );
        });

        it('throws if consumerKey is missing', function () use ($baseArgs) {
            expect(fn () => new OvhProvider(...array_merge($baseArgs, ['consumerKey' => ''])))->toThrow(
                InvalidArgumentException::class,
                'OVH: consumerKey is required'
            );
        });

        it('throws if zoneName is missing', function () use ($baseArgs) {
            expect(fn () => new OvhProvider(...array_merge($baseArgs, ['zoneName' => ''])))->toThrow(
                InvalidArgumentException::class,
                'OVH: zoneName is required'
            );
        });
    });

    describe('signature generation', function () use ($baseArgs) {
        it('sends correct OVH authentication headers', function () use ($baseArgs) {
            $timestamp = 1700000000;
            $history = [];
            $client = ovhClient($history, ovhTime($timestamp), ovhOk([]));

            $provider = new OvhProvider(...array_merge($baseArgs, ['client' => $client]));
            $provider->getRecords('rm.example.com');

            $request = $history[1]['request'];
            $headers = [];
            foreach (['X-Ovh-Application', 'X-Ovh-Consumer', 'X-Ovh-Timestamp', 'X-Ovh-Signature'] as $h) {
                $headers[$h] = $request->getHeaderLine($h);
            }

            expect($headers['X-Ovh-Application'])->toBe('ak-123')
                ->and($headers['X-Ovh-Consumer'])->toBe('ck-456')
                ->and($headers['X-Ovh-Timestamp'])->toBe((string) $timestamp);

            $url = (string) $request->getUri();
            $raw = "as-secret+ck-456+GET+{$url}++{$timestamp}";
            $expectedSig = '$1$' . sha1($raw);
            expect($headers['X-Ovh-Signature'])->toBe($expectedSig);
        });
    });

    describe('getRecords', function () use ($baseArgs) {
        it('fetches record IDs then each record detail', function () use ($baseArgs) {
            $history = [];
            $client = ovhClient($history,
                ovhTime(), ovhOk([101, 102]),
                ovhOk(['id' => 101, 'fieldType' => 'CNAME', 'subDomain' => 'rm', 'target' => 'to.rulemailer.se', 'ttl' => 3600, 'zone' => 'example.com']),
                ovhOk(['id' => 102, 'fieldType' => 'A', 'subDomain' => 'rm', 'target' => '1.2.3.4', 'ttl' => 3600, 'zone' => 'example.com']),
            );

            $provider = new OvhProvider(...array_merge($baseArgs, ['client' => $client]));
            $records = $provider->getRecords('rm.example.com');

            expect($records)->toHaveCount(2)
                ->and($records[0]->id)->toBe('101')
                ->and($records[0]->type)->toBe('CNAME')
                ->and($records[0]->name)->toBe('rm.example.com')
                ->and($records[0]->value)->toBe('to.rulemailer.se')
                ->and($records[1]->id)->toBe('102');
        });

        it('returns empty array when no records exist', function () use ($baseArgs) {
            $history = [];
            $client = ovhClient($history, ovhTime(), ovhOk([]));

            $provider = new OvhProvider(...array_merge($baseArgs, ['client' => $client]));
            $records = $provider->getRecords('nonexistent.example.com');
            expect($records)->toBe([]);
        });
    });

    describe('createRecord', function () use ($baseArgs) {
        it('creates a record and refreshes the zone', function () use ($baseArgs) {
            $history = [];
            $client = ovhClient($history,
                ovhTime(), ovhOk(['id' => 201, 'fieldType' => 'CNAME', 'subDomain' => 'rm', 'target' => 'to.rulemailer.se', 'ttl' => 3600, 'zone' => 'example.com']),
                ovhEmpty(),
            );

            $provider = new OvhProvider(...array_merge($baseArgs, ['client' => $client]));
            $result = $provider->createRecord([
                'type' => 'CNAME', 'name' => 'rm.example.com', 'value' => 'to.rulemailer.se',
            ]);

            expect($result->id)->toBe('201')
                ->and($result->type)->toBe('CNAME')
                ->and($result->name)->toBe('rm.example.com');

            // Verify refresh was called (time cached, so: time + create + refresh = 3 requests)
            expect((string) $history[2]['request']->getUri())->toContain('/domain/zone/example.com/refresh');
        });
    });

    describe('deleteRecord', function () use ($baseArgs) {
        it('deletes a record and refreshes the zone', function () use ($baseArgs) {
            $history = [];
            $client = ovhClient($history,
                ovhTime(), ovhEmpty(),
                ovhEmpty(),
            );

            $provider = new OvhProvider(...array_merge($baseArgs, ['client' => $client]));
            $provider->deleteRecord('301');

            expect((string) $history[1]['request']->getUri())->toContain('/domain/zone/example.com/record/301');
        });
    });

    describe('error handling', function () use ($baseArgs) {
        it('throws on API error', function () use ($baseArgs) {
            $history = [];
            $client = ovhClient($history, ovhTime(), new Response(403, [], 'Invalid key'));

            $provider = new OvhProvider(...array_merge($baseArgs, ['client' => $client]));
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(RuntimeException::class);
        });

        it('throws when server time request fails', function () use ($baseArgs) {
            $history = [];
            $client = ovhClient($history, new Response(500, [], 'Internal Server Error'));

            $provider = new OvhProvider(...array_merge($baseArgs, ['client' => $client]));
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(RuntimeException::class);
        });
    });
});
