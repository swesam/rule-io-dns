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

it('does not double trailing dots', function () {
    $records = [
        new DnsRecord(type: 'CNAME', name: 'rm.example.com.', value: 'to.rulemailer.se.', purpose: 'mx-spf'),
    ];

    $output = BindZoneExporter::export($records);

    expect($output)->not->toContain('..');
    expect($output)->toBe("rm.example.com.\t3600\tIN\tCNAME\tto.rulemailer.se.\n");
});

it('returns empty string for empty records', function () {
    expect(BindZoneExporter::export([]))->toBe("\n");
});
