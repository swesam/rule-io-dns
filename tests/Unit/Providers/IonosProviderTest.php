<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use RuleIo\Dns\Providers\IonosProvider;

function ionosClient(array &$history, Response ...$responses): Client
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));
    return new Client(['handler' => $stack]);
}

function ionosOk(mixed $body): Response
{
    return new Response(200, [], json_encode($body));
}

describe('IonosProvider', function () {
    it('throws if apiKey is missing', function () {
        expect(fn () => new IonosProvider(apiKey: '', zoneId: 'z1'))->toThrow(
            InvalidArgumentException::class,
            'apiKey is required'
        );
    });

    it('throws if neither zoneId nor domain is provided', function () {
        expect(fn () => new IonosProvider(apiKey: 'prefix.secret'))->toThrow(
            InvalidArgumentException::class,
            'either zoneId or domain is required'
        );
    });

    describe('with zoneId', function () {
        it('getRecords fetches zone and returns records', function () {
            $history = [];
            $client = ionosClient($history, ionosOk([
                'id' => 'z1', 'name' => 'example.com', 'type' => 'NATIVE',
                'records' => [
                    ['id' => 'r1', 'name' => 'rm.example.com', 'type' => 'CNAME', 'content' => 'to.rulemailer.se', 'ttl' => 3600, 'prio' => 0],
                    ['id' => 'r2', 'name' => 'rm.example.com', 'type' => 'A', 'content' => '1.2.3.4', 'ttl' => 3600, 'prio' => 0],
                ],
            ]));

            $provider = new IonosProvider(apiKey: 'prefix.secret', zoneId: 'z1', client: $client);
            $records = $provider->getRecords('rm.example.com');

            expect($records)->toHaveCount(2)
                ->and($records[0]->id)->toBe('r1')
                ->and($records[0]->value)->toBe('to.rulemailer.se');

            $request = $history[0]['request'];
            expect($request->getHeaderLine('X-API-Key'))->toBe('prefix.secret')
                ->and((string) $request->getUri())->toContain('/zones/z1?recordName=rm.example.com&recordType=');
        });

        it('createRecord posts a new record array', function () {
            $history = [];
            $client = ionosClient($history, ionosOk([
                ['id' => 'new-1', 'type' => 'CNAME', 'name' => 'rm.example.com', 'content' => 'to.rulemailer.se', 'ttl' => 3600, 'prio' => 0],
            ]));

            $provider = new IonosProvider(apiKey: 'prefix.secret', zoneId: 'z1', client: $client);
            $result = $provider->createRecord([
                'type' => 'CNAME', 'name' => 'rm.example.com', 'value' => 'to.rulemailer.se',
            ]);

            expect($result->id)->toBe('new-1')
                ->and($result->value)->toBe('to.rulemailer.se');

            $body = json_decode((string) $history[0]['request']->getBody(), true);
            expect($body)->toBe([[
                'name' => 'rm.example.com', 'type' => 'CNAME', 'content' => 'to.rulemailer.se', 'ttl' => 3600, 'prio' => 0,
            ]]);
        });

        it('deleteRecord sends DELETE request', function () {
            $history = [];
            $client = ionosClient($history, new Response(200, [], ''));

            $provider = new IonosProvider(apiKey: 'prefix.secret', zoneId: 'z1', client: $client);
            $provider->deleteRecord('r1');

            expect($history[0]['request']->getMethod())->toBe('DELETE')
                ->and((string) $history[0]['request']->getUri())->toContain('/zones/z1/records/r1');
        });

        it('throws on API error', function () {
            $history = [];
            $client = ionosClient($history, new Response(403, [], 'Forbidden'));

            $provider = new IonosProvider(apiKey: 'bad-key', zoneId: 'z1', client: $client);
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(RuntimeException::class);
        });
    });

    describe('with domain (auto-lookup)', function () {
        it('looks up zoneId from domain', function () {
            $history = [];
            $client = ionosClient($history,
                ionosOk([['id' => 'z1', 'name' => 'example.com', 'type' => 'NATIVE']]),
                ionosOk(['id' => 'z1', 'name' => 'example.com', 'type' => 'NATIVE', 'records' => []]),
            );

            $provider = new IonosProvider(apiKey: 'prefix.secret', domain: 'example.com', client: $client);
            $provider->getRecords('rm.example.com');

            expect((string) $history[0]['request']->getUri())->toContain('/zones');
        });

        it('caches zoneId after first lookup', function () {
            $history = [];
            $client = ionosClient($history,
                ionosOk([['id' => 'z1', 'name' => 'example.com', 'type' => 'NATIVE']]),
                ionosOk(['id' => 'z1', 'name' => 'example.com', 'type' => 'NATIVE', 'records' => []]),
                ionosOk(['id' => 'z1', 'name' => 'example.com', 'type' => 'NATIVE', 'records' => []]),
            );

            $provider = new IonosProvider(apiKey: 'prefix.secret', domain: 'example.com', client: $client);
            $provider->getRecords('rm.example.com');
            $provider->getRecords('_dmarc.rm.example.com');

            expect($history)->toHaveCount(3);
        });

        it('throws if no zone found for domain', function () {
            $history = [];
            $client = ionosClient($history,
                ionosOk([['id' => 'z1', 'name' => 'other.com', 'type' => 'NATIVE']]),
            );

            $provider = new IonosProvider(apiKey: 'prefix.secret', domain: 'nonexistent.com', client: $client);
            expect(fn () => $provider->getRecords('rm.nonexistent.com'))->toThrow(
                RuntimeException::class,
                'no zone found for domain "nonexistent.com"'
            );
        });
    });
});

describe('IonosProvider::listZones', function () {
    it('returns all zones', function () {
        $history = [];
        $client = ionosClient($history, ionosOk([
            ['id' => 'z1', 'name' => 'example.com', 'type' => 'NATIVE'],
            ['id' => 'z2', 'name' => 'alright.se', 'type' => 'NATIVE'],
        ]));

        $zones = IonosProvider::listZones('prefix.secret', $client);
        expect($zones)->toBe([
            ['id' => 'z1', 'name' => 'example.com', 'type' => 'NATIVE'],
            ['id' => 'z2', 'name' => 'alright.se', 'type' => 'NATIVE'],
        ]);
    });

    it('throws if apiKey is missing', function () {
        expect(fn () => IonosProvider::listZones(''))->toThrow(
            InvalidArgumentException::class,
            'apiKey is required'
        );
    });
});
