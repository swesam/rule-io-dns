<?php

use RuleIo\Dns\Domain;

it('returns bare domain as-is', function () {
    expect(Domain::clean('example.com'))->toBe('example.com');
});

it('extracts domain from email address', function () {
    expect(Domain::clean('user@example.com'))->toBe('example.com');
});

it('extracts domain from HTTPS URL', function () {
    expect(Domain::clean('https://www.example.com/path?q=1'))->toBe('example.com');
});

it('extracts domain from HTTP URL', function () {
    expect(Domain::clean('http://example.com/page'))->toBe('example.com');
});

it('strips www prefix', function () {
    expect(Domain::clean('www.example.com'))->toBe('example.com');
});

it('lowercases domain', function () {
    expect(Domain::clean('EXAMPLE.COM'))->toBe('example.com');
});

it('removes trailing dot (FQDN)', function () {
    expect(Domain::clean('example.com.'))->toBe('example.com');
});

it('trims whitespace', function () {
    expect(Domain::clean('  example.com  '))->toBe('example.com');
});

it('preserves subdomains (not www)', function () {
    expect(Domain::clean('sub.example.com'))->toBe('sub.example.com');
});

it('handles email with uppercase and spaces', function () {
    expect(Domain::clean(' User@EXAMPLE.COM '))->toBe('example.com');
});

it('handles URL without path', function () {
    expect(Domain::clean('https://example.com'))->toBe('example.com');
});

it('handles input with path but no protocol', function () {
    expect(Domain::clean('example.com/page'))->toBe('example.com');
});
