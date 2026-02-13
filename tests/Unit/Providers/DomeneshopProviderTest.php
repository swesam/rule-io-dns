<?php

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use RuleIo\Dns\Providers\DomeneshopProvider;

function dsClient(array &$history, Response ...$responses): Client
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));
    return new Client(['handler' => $stack]);
}

function dsOk(mixed $body): Response
{
    return new Response(200, [], json_encode($body));
}

function dsNoContent(): Response
{
    return new Response(204, [], '');
}

describe('DomeneshopProvider', function () {
    it('throws if token is missing', function () {
        expect(fn () => new DomeneshopProvider(token: '', secret: 's', domainId: 1))
            ->toThrow(InvalidArgumentException::class, 'token is required');
    });

    it('throws if secret is missing', function () {
        expect(fn () => new DomeneshopProvider(token: 't', secret: '', domainId: 1))
            ->toThrow(InvalidArgumentException::class, 'secret is required');
    });

    it('throws if neither domainId nor domain is provided', function () {
        expect(fn () => new DomeneshopProvider(token: 't', secret: 's'))
            ->toThrow(InvalidArgumentException::class, 'either domainId or domain is required');
    });

    describe('with domainId and domain', function () {
        it('getRecords fetches records by relative host', function () {
            $history = [];
            $client = dsClient($history, dsOk([
                ['id' => 1, 'host' => 'rm', 'type' => 'CNAME', 'data' => 'to.rulemailer.se', 'ttl' => 3600],
                ['id' => 2, 'host' => 'rm', 'type' => 'A', 'data' => '1.2.3.4', 'ttl' => 3600],
            ]));

            $provider = new DomeneshopProvider(token: 't', secret: 's', domainId: 123, domain: 'example.com', client: $client);
            $records = $provider->getRecords('rm.example.com');

            expect($records)->toHaveCount(2)
                ->and($records[0]->id)->toBe('1')
                ->and($records[0]->value)->toBe('to.rulemailer.se');

            $request = $history[0]['request'];
            expect($request->getHeaderLine('Authorization'))->toStartWith('Basic ')
                ->and((string) $request->getUri())->toContain('/domains/123/dns?host=rm');
        });

        it('createRecord posts a new record', function () {
            $history = [];
            $client = dsClient($history, dsOk([
                'id' => 99, 'host' => 'rm', 'type' => 'CNAME', 'data' => 'to.rulemailer.se', 'ttl' => 3600,
            ]));

            $provider = new DomeneshopProvider(token: 't', secret: 's', domainId: 123, domain: 'example.com', client: $client);
            $result = $provider->createRecord([
                'type' => 'CNAME', 'name' => 'rm.example.com', 'value' => 'to.rulemailer.se',
            ]);

            expect($result->id)->toBe('99')
                ->and($result->value)->toBe('to.rulemailer.se');
        });

        it('deleteRecord sends DELETE request', function () {
            $history = [];
            $client = dsClient($history, dsNoContent());

            $provider = new DomeneshopProvider(token: 't', secret: 's', domainId: 123, domain: 'example.com', client: $client);
            $provider->deleteRecord('42');

            expect($history[0]['request']->getMethod())->toBe('DELETE')
                ->and((string) $history[0]['request']->getUri())->toContain('/domains/123/dns/42');
        });

        it('throws on API error', function () {
            $history = [];
            $client = dsClient($history, new Response(403, [], 'Forbidden'));

            $provider = new DomeneshopProvider(token: 't', secret: 's', domainId: 123, domain: 'example.com', client: $client);
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(RuntimeException::class);
        });
    });

    describe('with domain auto-lookup', function () {
        it('looks up domainId from domain name', function () {
            $history = [];
            $client = dsClient($history,
                dsOk([['id' => 100, 'domain' => 'example.com'], ['id' => 200, 'domain' => 'other.com']]),
                dsOk([]),
            );

            $provider = new DomeneshopProvider(token: 't', secret: 's', domain: 'example.com', client: $client);
            $provider->getRecords('rm.example.com');

            expect((string) $history[0]['request']->getUri())->toContain('/domains')
                ->and((string) $history[1]['request']->getUri())->toContain('/domains/100/dns?host=rm');
        });

        it('caches domainId after first lookup', function () {
            $history = [];
            $client = dsClient($history,
                dsOk([['id' => 100, 'domain' => 'example.com']]),
                dsOk([]),
                dsOk([]),
            );

            $provider = new DomeneshopProvider(token: 't', secret: 's', domain: 'example.com', client: $client);
            $provider->getRecords('rm.example.com');
            $provider->getRecords('_dmarc.rm.example.com');

            expect($history)->toHaveCount(3);
        });

        it('throws if no domain found', function () {
            $history = [];
            $client = dsClient($history, dsOk([]));

            $provider = new DomeneshopProvider(token: 't', secret: 's', domain: 'nonexistent.com', client: $client);
            expect(fn () => $provider->getRecords('rm.nonexistent.com'))->toThrow(
                RuntimeException::class,
                'no domain found for "nonexistent.com"'
            );
        });
    });
});

describe('DomeneshopProvider::listDomains', function () {
    it('returns all domains', function () {
        $history = [];
        $client = dsClient($history, dsOk([
            ['id' => 1, 'domain' => 'example.com'],
            ['id' => 2, 'domain' => 'alright.se'],
        ]));

        $domains = DomeneshopProvider::listDomains('t', 's', $client);
        expect($domains)->toBe([
            ['id' => 1, 'domain' => 'example.com'],
            ['id' => 2, 'domain' => 'alright.se'],
        ]);
    });

    it('throws if token/secret missing', function () {
        expect(fn () => DomeneshopProvider::listDomains('', 's'))->toThrow(
            InvalidArgumentException::class,
            'token and secret are required'
        );
    });
});
