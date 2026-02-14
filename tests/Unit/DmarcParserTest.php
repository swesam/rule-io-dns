<?php

declare(strict_types=1);

use RuleIo\Dns\DmarcParser;

it('parses a minimal record', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none');
    expect($result->p)->toBe('none');
});

it('parses a full record with all tags', function () {
    $raw = 'v=DMARC1; p=reject; sp=quarantine; aspf=s; adkim=s; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; pct=50';
    $result = DmarcParser::parse($raw);
    expect($result->p)->toBe('reject')
        ->and($result->sp)->toBe('quarantine')
        ->and($result->aspf)->toBe('s')
        ->and($result->adkim)->toBe('s')
        ->and($result->rua)->toBe(['dmarc@example.com'])
        ->and($result->ruf)->toBe(['forensics@example.com'])
        ->and($result->pct)->toBe(50);
});

it('returns null for non-DMARC records', function () {
    expect(DmarcParser::parse('v=spf1 include:example.com ~all'))->toBeNull()
        ->and(DmarcParser::parse('some random text'))->toBeNull()
        ->and(DmarcParser::parse(''))->toBeNull();
});

it('handles p=reject', function () {
    expect(DmarcParser::parse('v=DMARC1; p=reject')->p)->toBe('reject');
});

it('handles p=quarantine', function () {
    expect(DmarcParser::parse('v=DMARC1; p=quarantine')->p)->toBe('quarantine');
});

it('handles p=none', function () {
    expect(DmarcParser::parse('v=DMARC1; p=none')->p)->toBe('none');
});

it('returns null when p tag is missing', function () {
    expect(DmarcParser::parse('v=DMARC1; rua=mailto:a@b.com'))->toBeNull();
});

it('parses rua with multiple mailto URIs', function () {
    $raw = 'v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com';
    $result = DmarcParser::parse($raw);
    expect($result->rua)->toBe(['a@example.com', 'b@example.com']);
});

it('parses ruf with multiple mailto URIs', function () {
    $raw = 'v=DMARC1; p=none; ruf=mailto:x@example.com,mailto:y@example.com';
    $result = DmarcParser::parse($raw);
    expect($result->ruf)->toBe(['x@example.com', 'y@example.com']);
});

it('handles whitespace variations', function () {
    $raw = 'v=DMARC1;p=reject;  sp=none ;aspf=r';
    $result = DmarcParser::parse($raw);
    expect($result->p)->toBe('reject')
        ->and($result->sp)->toBe('none')
        ->and($result->aspf)->toBe('r');
});

it('handles leading/trailing whitespace in the record', function () {
    $result = DmarcParser::parse('  v=DMARC1; p=none  ');
    expect($result->p)->toBe('none');
});

it('parses aspf=s and adkim=s', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; aspf=s; adkim=s');
    expect($result->aspf)->toBe('s')
        ->and($result->adkim)->toBe('s');
});

it('parses aspf=r and adkim=r', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; aspf=r; adkim=r');
    expect($result->aspf)->toBe('r')
        ->and($result->adkim)->toBe('r');
});

it('parses pct=50', function () {
    $result = DmarcParser::parse('v=DMARC1; p=quarantine; pct=50');
    expect($result->pct)->toBe(50);
});

it('parses pct=100', function () {
    $result = DmarcParser::parse('v=DMARC1; p=reject; pct=100');
    expect($result->pct)->toBe(100);
});

it('parses the Rule.io default DMARC record', function () {
    $raw = 'v=DMARC1; p=none; rua=mailto:dmarc@rule.se; ruf=mailto:authfail@rule.se';
    $result = DmarcParser::parse($raw);
    expect($result->p)->toBe('none')
        ->and($result->rua)->toBe(['dmarc@rule.se'])
        ->and($result->ruf)->toBe(['authfail@rule.se']);
});

it('handles case-insensitive policy values', function () {
    expect(DmarcParser::parse('v=DMARC1; p=REJECT')->p)->toBe('reject')
        ->and(DmarcParser::parse('v=DMARC1; p=Quarantine')->p)->toBe('quarantine')
        ->and(DmarcParser::parse('v=DMARC1; p=NONE')->p)->toBe('none');
});

it('handles case-insensitive sp values', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; sp=REJECT');
    expect($result->sp)->toBe('reject');
});

it('handles case-insensitive alignment modes', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; aspf=S; adkim=R');
    expect($result->aspf)->toBe('s')
        ->and($result->adkim)->toBe('r');
});

it('ignores non-mailto URIs in rua', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; rua=http://example.com');
    expect($result->rua)->toBeNull();
});

it('ignores non-mailto URIs in ruf', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; ruf=https://example.com');
    expect($result->ruf)->toBeNull();
});

it('filters non-mailto URIs but keeps valid ones', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; rua=http://bad.com,mailto:good@example.com');
    expect($result->rua)->toBe(['good@example.com']);
});

it('ignores invalid pct values (non-numeric)', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; pct=abc');
    expect($result->pct)->toBeNull();
});

it('ignores pct values below 0', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; pct=-10');
    expect($result->pct)->toBeNull();
});

it('ignores pct values above 100', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; pct=150');
    expect($result->pct)->toBeNull();
});

it('accepts pct=0', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; pct=0');
    expect($result->pct)->toBe(0);
});

it('uses last value when duplicate tags exist', function () {
    $result = DmarcParser::parse('v=DMARC1; p=none; p=reject');
    expect($result->p)->toBe('reject');
});
