<?php

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use RuleIo\Dns\Providers\LoopiaProvider;

function loopiaClient(array &$history, Response ...$responses): Client
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));
    return new Client(['handler' => $stack]);
}

function xmlRpcOk(string $value): Response
{
    return new Response(200, [], '<?xml version="1.0"?><methodResponse><params><param><value><string>' . $value . '</string></value></param></params></methodResponse>');
}

function xmlRpcArray(array $records): Response
{
    $structs = '';
    foreach ($records as $r) {
        $structs .= '<value><struct>'
            . '<member><name>type</name><value><string>' . $r['type'] . '</string></value></member>'
            . '<member><name>ttl</name><value><int>' . $r['ttl'] . '</int></value></member>'
            . '<member><name>priority</name><value><int>' . $r['priority'] . '</int></value></member>'
            . '<member><name>rdata</name><value><string>' . $r['rdata'] . '</string></value></member>'
            . '<member><name>record_id</name><value><int>' . $r['record_id'] . '</int></value></member>'
            . '</struct></value>';
    }
    return new Response(200, [], '<?xml version="1.0"?><methodResponse><params><param><value><array><data>' . $structs . '</data></array></value></param></params></methodResponse>');
}

function xmlRpcFault(int $code, string $message): Response
{
    return new Response(200, [],
        '<?xml version="1.0"?><methodResponse><fault><value><struct>'
        . '<member><name>faultCode</name><value><int>' . $code . '</int></value></member>'
        . '<member><name>faultString</name><value><string>' . $message . '</string></value></member>'
        . '</struct></value></fault></methodResponse>'
    );
}

describe('LoopiaProvider', function () {
    it('throws if username is missing', function () {
        expect(fn () => new LoopiaProvider(username: '', password: 'pass', domain: 'example.com'))
            ->toThrow(InvalidArgumentException::class, 'Loopia: username is required');
    });

    it('throws if password is missing', function () {
        expect(fn () => new LoopiaProvider(username: 'user', password: '', domain: 'example.com'))
            ->toThrow(InvalidArgumentException::class, 'Loopia: password is required');
    });

    it('throws if domain is missing', function () {
        expect(fn () => new LoopiaProvider(username: 'user', password: 'pass', domain: ''))
            ->toThrow(InvalidArgumentException::class, 'Loopia: domain is required');
    });

    describe('getRecords', function () {
        it('fetches records for a subdomain', function () {
            $history = [];
            $client = loopiaClient($history, xmlRpcArray([
                ['type' => 'CNAME', 'ttl' => 300, 'priority' => 0, 'rdata' => 'to.rulemailer.se', 'record_id' => 101],
                ['type' => 'A', 'ttl' => 300, 'priority' => 0, 'rdata' => '1.2.3.4', 'record_id' => 102],
            ]));

            $provider = new LoopiaProvider(username: 'user', password: 'pass', domain: 'example.com', client: $client);
            $records = $provider->getRecords('rm.example.com');

            expect($records)->toHaveCount(2)
                ->and($records[0]->id)->toBe('rm:101')
                ->and($records[0]->value)->toBe('to.rulemailer.se')
                ->and($records[1]->id)->toBe('rm:102');

            $body = (string) $history[0]['request']->getBody();
            expect($body)->toContain('<methodName>getZoneRecords</methodName>')
                ->and($body)->toContain('<string>user</string>')
                ->and($body)->toContain('<string>pass</string>');
        });

        it('throws on error string response', function () {
            $history = [];
            $client = loopiaClient($history, xmlRpcOk('UNKNOWN_ERROR'));

            $provider = new LoopiaProvider(username: 'user', password: 'pass', domain: 'example.com', client: $client);
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(
                RuntimeException::class,
                'Loopia: getZoneRecords failed: UNKNOWN_ERROR'
            );
        });

        it('throws on HTTP error', function () {
            $history = [];
            $client = loopiaClient($history, new Response(500, [], 'Internal Server Error'));

            $provider = new LoopiaProvider(username: 'user', password: 'pass', domain: 'example.com', client: $client);
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(RuntimeException::class);
        });

        it('throws on XML-RPC fault', function () {
            $history = [];
            $client = loopiaClient($history, xmlRpcFault(403, 'AUTH_ERROR'));

            $provider = new LoopiaProvider(username: 'user', password: 'pass', domain: 'example.com', client: $client);
            expect(fn () => $provider->getRecords('rm.example.com'))->toThrow(
                RuntimeException::class,
                'Loopia: XML-RPC fault 403: AUTH_ERROR'
            );
        });
    });

    describe('createRecord', function () {
        it('creates a record and returns the result', function () {
            $history = [];
            $client = loopiaClient($history,
                xmlRpcOk('OK'),
                xmlRpcArray([
                    ['type' => 'CNAME', 'ttl' => 300, 'priority' => 0, 'rdata' => 'to.rulemailer.se', 'record_id' => 201],
                ]),
            );

            $provider = new LoopiaProvider(username: 'user', password: 'pass', domain: 'example.com', client: $client);
            $result = $provider->createRecord([
                'type' => 'CNAME', 'name' => 'rm.example.com', 'value' => 'to.rulemailer.se',
            ]);

            expect($result->id)->toBe('rm:201')
                ->and($result->value)->toBe('to.rulemailer.se');
            expect($history)->toHaveCount(2);
        });

        it('throws when addZoneRecord returns non-OK', function () {
            $history = [];
            $client = loopiaClient($history, xmlRpcOk('AUTH_ERROR'));

            $provider = new LoopiaProvider(username: 'user', password: 'pass', domain: 'example.com', client: $client);
            expect(fn () => $provider->createRecord([
                'type' => 'CNAME', 'name' => 'rm.example.com', 'value' => 'to.rulemailer.se',
            ]))->toThrow(RuntimeException::class, 'Loopia: addZoneRecord failed: AUTH_ERROR');
        });
    });

    describe('deleteRecord', function () {
        it('deletes a record by encoded id', function () {
            $history = [];
            $client = loopiaClient($history, xmlRpcOk('OK'));

            $provider = new LoopiaProvider(username: 'user', password: 'pass', domain: 'example.com', client: $client);
            $provider->deleteRecord('rm:101');

            $body = (string) $history[0]['request']->getBody();
            expect($body)->toContain('<methodName>removeZoneRecord</methodName>')
                ->and($body)->toContain('<int>101</int>');
        });

        it('throws on invalid id format', function () {
            $provider = new LoopiaProvider(username: 'user', password: 'pass', domain: 'example.com');
            expect(fn () => $provider->deleteRecord('invalid'))->toThrow(
                InvalidArgumentException::class,
                'Loopia: invalid record id "invalid"'
            );
        });
    });
});
