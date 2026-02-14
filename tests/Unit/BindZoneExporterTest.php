<?php

use RuleIo\Dns\BindZoneExporter;
use RuleIo\Dns\Data\DnsRecord;

it('exports CNAME records with trailing dots', function () {
    $records = [
        new DnsRecord(type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se', purpose: 'mx-spf'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->toBe("rm.example.com.\t3600\tIN\tCNAME\tto.rulemailer.se.\n");
});

it('exports TXT records with quoted values', function () {
    $records = [
        new DnsRecord(type: 'TXT', name: '_dmarc.example.com', value: 'v=DMARC1; p=none; rua=mailto:dmarc@rule.se', purpose: 'dmarc'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->toBe("_dmarc.example.com.\t3600\tIN\tTXT\t\"v=DMARC1; p=none; rua=mailto:dmarc@rule.se\"\n");
});

it('escapes quotes and backslashes in TXT values', function () {
    $records = [
        new DnsRecord(type: 'TXT', name: 'test.example.com', value: 'v=spf1 "include:example.com" \\all', purpose: 'spf'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->toBe("test.example.com.\t3600\tIN\tTXT\t\"v=spf1 \\\"include:example.com\\\" \\\\all\"\n");
});

it('exports MX records with trailing dots', function () {
    $records = [
        new DnsRecord(type: 'MX', name: 'example.com', value: '10 mail.example.com', purpose: 'mx'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->toContain("MX\t10 mail.example.com.");
});

it('exports MX records with tab-separated values', function () {
    $records = [
        new DnsRecord(type: 'MX', name: 'example.com', value: "10\tmail.example.com", purpose: 'mx'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->toContain("MX\t10 mail.example.com.");
});

it('exports NS records with trailing dots', function () {
    $records = [
        new DnsRecord(type: 'NS', name: 'example.com', value: 'ns1.cloudflare.com', purpose: 'ns'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->toContain("NS\tns1.cloudflare.com.");
});

it('exports multiple records', function () {
    $records = [
        new DnsRecord(type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se', purpose: 'mx-spf'),
        new DnsRecord(type: 'CNAME', name: 'rule1._domainkey.example.com', value: 'rule1.domainkey.rulemailer.se', purpose: 'dkim'),
        new DnsRecord(type: 'TXT', name: '_dmarc.example.com', value: 'v=DMARC1; p=none; rua=mailto:dmarc@rule.se', purpose: 'dmarc'),
    ];

    $output = BindZoneExporter::export($records);
    $lines = explode("\n", trim($output));

    expect($lines)->toHaveCount(3);
    expect($lines[0])->toContain('CNAME');
    expect($lines[1])->toContain('_domainkey');
    expect($lines[2])->toContain('TXT');
});

it('respects custom TTL', function () {
    $records = [
        new DnsRecord(type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se', purpose: 'mx-spf'),
    ];

    $output = BindZoneExporter::export($records, ttl: 300);

    expect($output)->toContain("\t300\t");
});

it('normalizes lowercase record types', function () {
    $records = [
        new DnsRecord(type: 'cname', name: 'rm.example.com', value: 'to.rulemailer.se', purpose: 'mx-spf'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->toContain('CNAME');
    expect($output)->toContain('to.rulemailer.se.');
});

it('does not double trailing dots', function () {
    $records = [
        new DnsRecord(type: 'CNAME', name: 'rm.example.com.', value: 'to.rulemailer.se.', purpose: 'mx-spf'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->not->toContain('..');
    expect($output)->toBe("rm.example.com.\t3600\tIN\tCNAME\tto.rulemailer.se.\n");
});

it('strips control characters from values', function () {
    $records = [
        new DnsRecord(type: 'TXT', name: "test.example.com", value: "v=spf1\r\ninclude:evil.com", purpose: 'spf'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->not->toContain("\r");
    expect($output)->not->toContain("\n\n");
    expect($output)->toContain('v=spf1include:evil.com');
});

it('strips control characters from names', function () {
    $records = [
        new DnsRecord(type: 'CNAME', name: "evil\n.example.com", value: 'to.rulemailer.se', purpose: 'mx-spf'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->not->toContain("\n\n");
    expect($output)->toContain('evil.example.com.');
});

it('handles trailing whitespace in MX values', function () {
    $records = [
        new DnsRecord(type: 'MX', name: 'example.com', value: '10 mail.example.com  ', purpose: 'mx'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->toContain("MX\t10 mail.example.com.");
});

it('normalizes tab-separated MX values to spaces', function () {
    $records = [
        new DnsRecord(type: 'MX', name: 'example.com', value: "10\tmail.example.com", purpose: 'mx'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->toContain("MX\t10 mail.example.com.");
});

it('skips records with invalid type', function () {
    $records = [
        new DnsRecord(type: 'CNAME', name: 'rm.example.com', value: 'to.rulemailer.se', purpose: 'mx-spf'),
        new DnsRecord(type: 'BAD TYPE!', name: 'evil.example.com', value: 'x', purpose: 'test'),
    ];

    $output = BindZoneExporter::export($records);
    $lines = explode("\n", trim($output));

    expect($lines)->toHaveCount(1);
    expect($output)->toContain('CNAME');
    expect($output)->not->toContain('evil');
});

it('returns empty string for empty records', function () {
    expect(BindZoneExporter::export([]))->toBe('');
});
