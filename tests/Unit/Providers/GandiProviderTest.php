<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use RuleIo\Dns\Providers\GandiProvider;

function gandiClient(array &$history, Response ...$responses): Client
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));
    return new Client(['handler' => $stack]);
}

function gandiOk(mixed $body): Response
{
    return new Response(200, [], json_encode($body));
}

describe('GandiProvider', function () {
    it('throws if apiToken is missing', function () {
        expect(fn () => new GandiProvider(apiToken: '', domain: 'example.com'))->toThrow(
            InvalidArgumentException::class,
            'Gandi: apiToken is required'
        );
    });

    it('throws if domain is missing', function () {
        expect(fn () => new GandiProvider(apiToken: 'tok', domain: ''))->toThrow(
            InvalidArgumentException::class,
            'Gandi: domain is required'
        );
    });

    describe('getRecords', function () {
        it('fetches records by relative name', function () {
            $history = [];
            $client = gandiClient($history, gandiOk([
                ['rrset_name' => 'rm', 'rrset_type' => 'CNAME', 'rrset_ttl' => 300, 'rrset_values' => ['to.rulemailer.se.']],
            ]));

            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $records = $provider->getRecords('rm.example.com');

            expect($records)->toHaveCount(1)
                ->and($records[0]->id)->toBe('rm/CNAME/to.rulemailer.se.')
                ->and($records[0]->value)->toBe('to.rulemailer.se.');

            expect((string) $history[0]['request']->getUri())->toContain('/livedns/domains/example.com/records/rm')
                ->and($history[0]['request']->getHeaderLine('Authorization'))->toBe('Bearer tok');
        });

        it('converts apex domain to @ relative name', function () {
            $history = [];
            $client = gandiClient($history, gandiOk([
                ['rrset_name' => '@', 'rrset_type' => 'MX', 'rrset_ttl' => 300, 'rrset_values' => ['10 mail.example.com.']],
            ]));

            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $records = $provider->getRecords('example.com');

            expect($records[0]->name)->toBe('example.com');
            expect((string) $history[0]['request']->getUri())->toContain('/records/%40');
        });

        it('flattens rrsets with multiple values', function () {
            $history = [];
            $client = gandiClient($history, gandiOk([
                ['rrset_name' => '@', 'rrset_type' => 'TXT', 'rrset_ttl' => 300, 'rrset_values' => ['"v=spf1 ~all"', '"verification=abc"']],
            ]));

            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $records = $provider->getRecords('example.com');
            expect($records)->toHaveCount(2);
        });

        it('returns empty array on 404', function () {
            $history = [];
            $client = gandiClient($history, new Response(404, [], 'Not Found'));

            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $records = $provider->getRecords('nonexistent.example.com');
            expect($records)->toBe([]);
        });

        it('throws on non-404 API error', function () {
            $history = [];
            $client = gandiClient($history, new Response(403, [], 'Forbidden'));

            $provider = new GandiProvider(apiToken: 'bad-tok', domain: 'example.com', client: $client);
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(RuntimeException::class);
        });
    });

    describe('createRecord', function () {
        it('posts a new rrset', function () {
            $history = [];
            $client = gandiClient($history, gandiOk(['message' => 'DNS Record Created']));

            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $result = $provider->createRecord([
                'type' => 'CNAME', 'name' => 'rm.example.com', 'value' => 'to.rulemailer.se.',
            ]);

            expect($result->id)->toBe('rm/CNAME/to.rulemailer.se.')
                ->and($result->name)->toBe('rm.example.com')
                ->and($result->value)->toBe('to.rulemailer.se.');

            $body = json_decode((string) $history[0]['request']->getBody(), true);
            expect($body)->toBe([
                'rrset_name' => 'rm', 'rrset_type' => 'CNAME', 'rrset_ttl' => 300, 'rrset_values' => ['to.rulemailer.se.'],
            ]);
        });
    });

    describe('deleteRecord', function () {
        it('deletes entire rrset when it is the last value', function () {
            $history = [];
            $client = gandiClient($history,
                gandiOk(['rrset_name' => 'rm', 'rrset_type' => 'CNAME', 'rrset_ttl' => 300, 'rrset_values' => ['to.rulemailer.se.']]),
                gandiOk(null),
            );

            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $provider->deleteRecord('rm/CNAME/to.rulemailer.se.');

            expect($history[0]['request']->getMethod())->toBe('GET')
                ->and((string) $history[0]['request']->getUri())->toContain('/records/rm/CNAME');
            expect($history[1]['request']->getMethod())->toBe('DELETE')
                ->and((string) $history[1]['request']->getUri())->toContain('/records/rm/CNAME');
        });

        it('updates rrset with remaining values when multi-value', function () {
            $history = [];
            $client = gandiClient($history,
                gandiOk(['rrset_name' => '@', 'rrset_type' => 'TXT', 'rrset_ttl' => 300, 'rrset_values' => ['"v=spf1 ~all"', '"verification=abc"']]),
                gandiOk(null),
            );

            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $provider->deleteRecord('@/TXT/"v=spf1 ~all"');

            expect($history[1]['request']->getMethod())->toBe('PUT');
            $body = json_decode((string) $history[1]['request']->getBody(), true);
            expect($body['rrset_values'])->toBe(['"verification=abc"']);
        });

        it('normalizes trailing dots for domain-like types', function () {
            $history = [];
            $client = gandiClient($history,
                gandiOk(['rrset_name' => 'rm', 'rrset_type' => 'CNAME', 'rrset_ttl' => 300, 'rrset_values' => ['to.rulemailer.se.']]),
                gandiOk(null),
            );

            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $provider->deleteRecord('rm/CNAME/to.rulemailer.se');

            expect($history[1]['request']->getMethod())->toBe('DELETE');
        });

        it('returns silently when rrset is already gone (404)', function () {
            $history = [];
            $client = gandiClient($history, new Response(404, [], 'Not Found'));

            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com', client: $client);
            $provider->deleteRecord('rm/CNAME/to.rulemailer.se.');

            expect($history)->toHaveCount(1);
        });

        it('throws on invalid record id', function () {
            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com');
            expect(fn () => $provider->deleteRecord('invalid'))->toThrow(
                InvalidArgumentException::class,
                'Gandi: invalid record id "invalid"'
            );
        });

        it('throws on id with only two parts', function () {
            $provider = new GandiProvider(apiToken: 'tok', domain: 'example.com');
            expect(fn () => $provider->deleteRecord('rm/CNAME'))->toThrow(
                InvalidArgumentException::class,
                'Gandi: invalid record id "rm/CNAME"'
            );
        });
    });
});

describe('GandiProvider::listDomains', function () {
    it('returns all domains', function () {
        $history = [];
        $client = gandiClient($history, gandiOk([
            ['fqdn' => 'example.com'],
            ['fqdn' => 'alright.se'],
        ]));

        $domains = GandiProvider::listDomains('tok', $client);
        expect($domains)->toBe([
            ['fqdn' => 'example.com'],
            ['fqdn' => 'alright.se'],
        ]);
    });

    it('throws if apiToken is missing', function () {
        expect(fn () => GandiProvider::listDomains(''))->toThrow(
            InvalidArgumentException::class,
            'Gandi: apiToken is required'
        );
    });
});
