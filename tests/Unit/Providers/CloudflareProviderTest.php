<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use RuleIo\Dns\Providers\CloudflareProvider;

function cfClient(array &$history, Response ...$responses): Client
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));
    return new Client(['handler' => $stack]);
}

function cfResponse(mixed $result, ?array $resultInfo = null): Response
{
    return new Response(200, [], json_encode([
        'success' => true,
        'errors' => [],
        'result' => $result,
        'result_info' => $resultInfo,
    ]));
}

function cfErrorResponse(int $status, string $body): Response
{
    return new Response($status, [], $body);
}

describe('CloudflareProvider', function () {
    it('throws if apiToken is missing', function () {
        expect(fn () => new CloudflareProvider(apiToken: '', zoneId: 'z1'))->toThrow(
            InvalidArgumentException::class,
            'apiToken is required'
        );
    });

    it('throws if neither zoneId nor domain is provided', function () {
        expect(fn () => new CloudflareProvider(apiToken: 'tok'))->toThrow(
            InvalidArgumentException::class,
            'either zoneId or domain is required'
        );
    });

    describe('with zoneId', function () {
        it('getRecords fetches records by name', function () {
            $history = [];
            $client = cfClient($history, cfResponse([
                ['id' => 'r1', 'type' => 'CNAME', 'name' => 'rm.example.com', 'content' => 'to.rulemailer.se'],
                ['id' => 'r2', 'type' => 'A', 'name' => 'rm.example.com', 'content' => '1.2.3.4'],
            ]));

            $provider = new CloudflareProvider(apiToken: 'tok', zoneId: 'z1', client: $client);
            $records = $provider->getRecords('rm.example.com');

            expect($records)->toHaveCount(2)
                ->and($records[0]->id)->toBe('r1')
                ->and($records[0]->value)->toBe('to.rulemailer.se')
                ->and($records[1]->id)->toBe('r2')
                ->and($records[1]->value)->toBe('1.2.3.4');

            $request = $history[0]['request'];
            expect((string) $request->getUri())->toContain('/zones/z1/dns_records?name=rm.example.com')
                ->and($request->getHeaderLine('Authorization'))->toBe('Bearer tok');
        });

        it('createRecord posts a new record', function () {
            $history = [];
            $client = cfClient($history, cfResponse([
                'id' => 'new-1',
                'type' => 'CNAME',
                'name' => 'rm.example.com',
                'content' => 'to.rulemailer.se',
                'proxied' => false,
            ]));

            $provider = new CloudflareProvider(apiToken: 'tok', zoneId: 'z1', client: $client);
            $result = $provider->createRecord([
                'type' => 'CNAME',
                'name' => 'rm.example.com',
                'value' => 'to.rulemailer.se',
            ]);

            expect($result->id)->toBe('new-1')
                ->and($result->value)->toBe('to.rulemailer.se')
                ->and($result->proxied)->toBeFalse();

            $request = $history[0]['request'];
            expect($request->getMethod())->toBe('POST')
                ->and((string) $request->getUri())->toContain('/zones/z1/dns_records');
            $body = json_decode((string) $request->getBody(), true);
            expect($body)->toBe([
                'type' => 'CNAME',
                'name' => 'rm.example.com',
                'content' => 'to.rulemailer.se',
                'proxied' => false,
            ]);
        });

        it('getRecords returns proxied field', function () {
            $history = [];
            $client = cfClient($history, cfResponse([
                ['id' => 'r1', 'type' => 'CNAME', 'name' => 'rm.example.com', 'content' => 'to.rulemailer.se', 'proxied' => true],
                ['id' => 'r2', 'type' => 'A', 'name' => 'rm.example.com', 'content' => '1.2.3.4', 'proxied' => false],
            ]));

            $provider = new CloudflareProvider(apiToken: 'tok', zoneId: 'z1', client: $client);
            $records = $provider->getRecords('rm.example.com');

            expect($records[0]->proxied)->toBeTrue()
                ->and($records[1]->proxied)->toBeFalse();
        });

        it('updateRecord sends PATCH request', function () {
            $history = [];
            $client = cfClient($history, cfResponse([
                'id' => 'r1',
                'type' => 'CNAME',
                'name' => 'rm.example.com',
                'content' => 'to.rulemailer.se',
                'proxied' => false,
            ]));

            $provider = new CloudflareProvider(apiToken: 'tok', zoneId: 'z1', client: $client);
            $result = $provider->updateRecord('r1', ['proxied' => false]);

            expect($result->id)->toBe('r1')
                ->and($result->proxied)->toBeFalse();

            $request = $history[0]['request'];
            expect($request->getMethod())->toBe('PATCH')
                ->and((string) $request->getUri())->toContain('/zones/z1/dns_records/r1');
            $body = json_decode((string) $request->getBody(), true);
            expect($body)->toBe(['proxied' => false]);
        });

        it('deleteRecord sends DELETE request', function () {
            $history = [];
            $client = cfClient($history, cfResponse(['id' => 'r1']));

            $provider = new CloudflareProvider(apiToken: 'tok', zoneId: 'z1', client: $client);
            $provider->deleteRecord('r1');

            $request = $history[0]['request'];
            expect($request->getMethod())->toBe('DELETE')
                ->and((string) $request->getUri())->toContain('/zones/z1/dns_records/r1');
        });

        it('throws on API error', function () {
            $history = [];
            $client = cfClient($history, cfErrorResponse(403, 'Forbidden'));

            $provider = new CloudflareProvider(apiToken: 'bad-tok', zoneId: 'z1', client: $client);
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(RuntimeException::class);
        });

        it('throws on success: false with error details', function () {
            $history = [];
            $client = cfClient($history, new Response(200, [], json_encode([
                'success' => false,
                'errors' => [['code' => 1001, 'message' => 'Invalid zone']],
                'result' => null,
            ])));

            $provider = new CloudflareProvider(apiToken: 'tok', zoneId: 'z1', client: $client);
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(
                RuntimeException::class,
                '1001: Invalid zone'
            );
        });
    });

    describe('with domain (auto-lookup)', function () {
        it('looks up zoneId from domain', function () {
            $history = [];
            $client = cfClient($history,
                cfResponse([['id' => 'auto-zone-1']]),
                cfResponse([]),
            );

            $provider = new CloudflareProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $provider->getRecords('rm.example.com');

            expect((string) $history[0]['request']->getUri())->toContain('/zones?name=example.com')
                ->and((string) $history[1]['request']->getUri())->toContain('/zones/auto-zone-1/dns_records');
        });

        it('caches zoneId after first lookup', function () {
            $history = [];
            $client = cfClient($history,
                cfResponse([['id' => 'auto-zone-1']]),
                cfResponse([]),
                cfResponse([]),
            );

            $provider = new CloudflareProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $provider->getRecords('rm.example.com');
            $provider->getRecords('_dmarc.rm.example.com');

            // Zone lookup should happen only once (3 total calls, not 4)
            expect($history)->toHaveCount(3);
        });

        it('throws if no zone found for domain', function () {
            $history = [];
            $client = cfClient($history, cfResponse([]));

            $provider = new CloudflareProvider(apiToken: 'tok', domain: 'nonexistent.com', client: $client);
            expect(fn () => $provider->getRecords('rm.nonexistent.com'))->toThrow(
                RuntimeException::class,
                'no zone found for domain "nonexistent.com"'
            );
        });

        it('normalizes domain input via cleanDomain', function () {
            $history = [];
            $client = cfClient($history,
                cfResponse([['id' => 'z1']]),
                cfResponse([]),
            );

            $provider = new CloudflareProvider(apiToken: 'tok', domain: 'https://www.example.com/', client: $client);
            $provider->getRecords('rm.example.com');

            expect((string) $history[0]['request']->getUri())->toContain('/zones?name=example.com');
        });
    });
});

describe('CloudflareProvider::listZones', function () {
    it('returns all zones for the token', function () {
        $history = [];
        $client = cfClient($history, cfResponse([
            ['id' => 'z1', 'name' => 'example.com'],
            ['id' => 'z2', 'name' => 'alright.se'],
        ]));

        $zones = CloudflareProvider::listZones('tok', $client);

        expect($zones)->toBe([
            ['id' => 'z1', 'name' => 'example.com'],
            ['id' => 'z2', 'name' => 'alright.se'],
        ]);
        expect((string) $history[0]['request']->getUri())->toContain('/zones?page=1&per_page=50');
    });

    it('paginates when there are more than 50 zones', function () {
        $page1 = array_map(fn ($i) => ['id' => "z{$i}", 'name' => "domain{$i}.com"], range(0, 49));
        $page2 = [['id' => 'z50', 'name' => 'last.com']];

        $history = [];
        $client = cfClient($history,
            cfResponse($page1, ['page' => 1, 'total_pages' => 2]),
            cfResponse($page2, ['page' => 2, 'total_pages' => 2]),
        );

        $zones = CloudflareProvider::listZones('tok', $client);

        expect($zones)->toHaveCount(51)
            ->and($history)->toHaveCount(2);
        expect((string) $history[1]['request']->getUri())->toContain('page=2');
    });

    it('returns empty array when no zones exist', function () {
        $history = [];
        $client = cfClient($history, cfResponse([]));
        $zones = CloudflareProvider::listZones('tok', $client);
        expect($zones)->toBe([]);
    });
});
