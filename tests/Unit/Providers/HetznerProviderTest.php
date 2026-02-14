<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use RuleIo\Dns\Providers\HetznerProvider;

function hetznerClient(array &$history, Response ...$responses): Client
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));
    return new Client(['handler' => $stack]);
}

function hetznerOk(mixed $body): Response
{
    return new Response(200, [], json_encode($body));
}

describe('HetznerProvider', function () {
    it('throws if apiToken is missing', function () {
        expect(fn () => new HetznerProvider(apiToken: '', zoneId: 'z1'))->toThrow(
            InvalidArgumentException::class,
            'apiToken is required'
        );
    });

    it('throws if neither zoneId nor domain is provided', function () {
        expect(fn () => new HetznerProvider(apiToken: 'tok'))->toThrow(
            InvalidArgumentException::class,
            'either zoneId or domain is required'
        );
    });

    describe('with zoneId', function () {
        it('getRecords fetches and filters records by name', function () {
            $history = [];
            $client = hetznerClient($history, hetznerOk([
                'records' => [
                    ['id' => 'r1', 'type' => 'CNAME', 'name' => 'rm.example.com', 'value' => 'to.rulemailer.se', 'zone_id' => 'z1', 'ttl' => 300],
                    ['id' => 'r2', 'type' => 'A', 'name' => 'rm.example.com', 'value' => '1.2.3.4', 'zone_id' => 'z1', 'ttl' => 300],
                    ['id' => 'r3', 'type' => 'A', 'name' => 'other.example.com', 'value' => '5.6.7.8', 'zone_id' => 'z1', 'ttl' => 300],
                ],
            ]));

            $provider = new HetznerProvider(apiToken: 'tok', zoneId: 'z1', client: $client);
            $records = $provider->getRecords('rm.example.com');

            expect($records)->toHaveCount(2)
                ->and($records[0]->id)->toBe('r1')
                ->and($records[1]->id)->toBe('r2');

            $request = $history[0]['request'];
            expect($request->getHeaderLine('Auth-API-Token'))->toBe('tok')
                ->and((string) $request->getUri())->toContain('/records?zone_id=z1');
        });

        it('createRecord posts a new record', function () {
            $history = [];
            $client = hetznerClient($history, hetznerOk([
                'record' => [
                    'id' => 'new-1', 'type' => 'CNAME', 'name' => 'rm.example.com',
                    'value' => 'to.rulemailer.se', 'zone_id' => 'z1', 'ttl' => 300,
                ],
            ]));

            $provider = new HetznerProvider(apiToken: 'tok', zoneId: 'z1', client: $client);
            $result = $provider->createRecord([
                'type' => 'CNAME', 'name' => 'rm.example.com', 'value' => 'to.rulemailer.se',
            ]);

            expect($result->id)->toBe('new-1')
                ->and($result->value)->toBe('to.rulemailer.se');

            $body = json_decode((string) $history[0]['request']->getBody(), true);
            expect($body)->toBe([
                'zone_id' => 'z1', 'type' => 'CNAME', 'name' => 'rm.example.com',
                'value' => 'to.rulemailer.se', 'ttl' => 300,
            ]);
        });

        it('deleteRecord sends DELETE request', function () {
            $history = [];
            $client = hetznerClient($history, hetznerOk([]));

            $provider = new HetznerProvider(apiToken: 'tok', zoneId: 'z1', client: $client);
            $provider->deleteRecord('r1');

            expect($history[0]['request']->getMethod())->toBe('DELETE')
                ->and((string) $history[0]['request']->getUri())->toContain('/records/r1');
        });

        it('throws on API error', function () {
            $history = [];
            $client = hetznerClient($history, new Response(403, [], 'Forbidden'));

            $provider = new HetznerProvider(apiToken: 'bad-tok', zoneId: 'z1', client: $client);
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(RuntimeException::class);
        });
    });

    describe('with domain (auto-lookup)', function () {
        it('looks up zoneId from domain', function () {
            $history = [];
            $client = hetznerClient($history,
                hetznerOk(['zones' => [['id' => 'auto-zone-1', 'name' => 'example.com']]]),
                hetznerOk(['records' => []]),
            );

            $provider = new HetznerProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $provider->getRecords('rm.example.com');

            expect((string) $history[0]['request']->getUri())->toContain('/zones?name=example.com');
        });

        it('caches zoneId after first lookup', function () {
            $history = [];
            $client = hetznerClient($history,
                hetznerOk(['zones' => [['id' => 'auto-zone-1', 'name' => 'example.com']]]),
                hetznerOk(['records' => []]),
                hetznerOk(['records' => []]),
            );

            $provider = new HetznerProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $provider->getRecords('rm.example.com');
            $provider->getRecords('_dmarc.rm.example.com');

            expect($history)->toHaveCount(3);
        });

        it('throws if no zone found for domain', function () {
            $history = [];
            $client = hetznerClient($history, hetznerOk(['zones' => []]));

            $provider = new HetznerProvider(apiToken: 'tok', domain: 'nonexistent.com', client: $client);
            expect(fn () => $provider->getRecords('rm.nonexistent.com'))->toThrow(
                RuntimeException::class,
                'no zone found for domain "nonexistent.com"'
            );
        });
    });
});

describe('HetznerProvider::listZones', function () {
    it('returns all zones for the token', function () {
        $history = [];
        $client = hetznerClient($history, hetznerOk([
            'zones' => [
                ['id' => 'z1', 'name' => 'example.com'],
                ['id' => 'z2', 'name' => 'alright.se'],
            ],
        ]));

        $zones = HetznerProvider::listZones('tok', $client);
        expect($zones)->toBe([
            ['id' => 'z1', 'name' => 'example.com'],
            ['id' => 'z2', 'name' => 'alright.se'],
        ]);
    });

    it('throws if apiToken is missing', function () {
        expect(fn () => HetznerProvider::listZones(''))->toThrow(
            InvalidArgumentException::class,
            'apiToken is required'
        );
    });
});
