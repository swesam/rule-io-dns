<?php

use RuleIo\Dns\Constants;
use RuleIo\Dns\Data\DnsCheckResult;
use RuleIo\Dns\Data\DnsChecks;
use RuleIo\Dns\Data\DnsRecordCheck;
use RuleIo\Dns\Data\DnsRecordStatus;
use RuleIo\Dns\RequiredRecords;

it('returns all 3 records when no checkResult provided', function () {
    $records = RequiredRecords::get('example.com');
    expect($records)->toHaveCount(3)
        ->and($records[0]->type)->toBe('CNAME')
        ->and($records[0]->name)->toBe('rm.example.com')
        ->and($records[0]->value)->toBe(Constants::RULE_CNAME_TARGET)
        ->and($records[0]->purpose)->toBe('mx-spf')
        ->and($records[1]->type)->toBe('CNAME')
        ->and($records[1]->name)->toBe('keyse._domainkey.example.com')
        ->and($records[1]->value)->toBe(Constants::RULE_DKIM_TARGET)
        ->and($records[1]->purpose)->toBe('dkim')
        ->and($records[2]->type)->toBe('TXT')
        ->and($records[2]->name)->toBe('_dmarc.rm.example.com')
        ->and($records[2]->value)->toBe(Constants::RULE_DMARC_POLICY)
        ->and($records[2]->purpose)->toBe('dmarc');
});

it('cleans domain from input', function () {
    $records = RequiredRecords::get('user@EXAMPLE.COM');
    expect($records[0]->name)->toBe('rm.example.com');
});

it('returns empty array when all checks pass', function () {
    $checkResult = new DnsCheckResult(
        domain: 'example.com',
        allPassed: true,
        warnings: [],
        checks: new DnsChecks(
            ns: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            mx: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            spf: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            dkim: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            dmarc: new DnsRecordCheck(status: DnsRecordStatus::Pass),
        ),
    );

    $records = RequiredRecords::get('example.com', $checkResult);
    expect($records)->toHaveCount(0);
});

it('returns only DKIM record when only DKIM fails', function () {
    $checkResult = new DnsCheckResult(
        domain: 'example.com',
        allPassed: false,
        warnings: [],
        checks: new DnsChecks(
            ns: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            mx: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            spf: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            dkim: new DnsRecordCheck(status: DnsRecordStatus::Fail, expected: Constants::RULE_DKIM_TARGET),
            dmarc: new DnsRecordCheck(status: DnsRecordStatus::Pass),
        ),
    );

    $records = RequiredRecords::get('example.com', $checkResult);
    expect($records)->toHaveCount(1)
        ->and($records[0]->purpose)->toBe('dkim');
});

it('returns CNAME record when MX is missing (even if SPF passes)', function () {
    $checkResult = new DnsCheckResult(
        domain: 'example.com',
        allPassed: false,
        warnings: [],
        checks: new DnsChecks(
            ns: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            mx: new DnsRecordCheck(status: DnsRecordStatus::Missing),
            spf: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            dkim: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            dmarc: new DnsRecordCheck(status: DnsRecordStatus::Pass),
        ),
    );

    $records = RequiredRecords::get('example.com', $checkResult);
    expect($records)->toHaveCount(1)
        ->and($records[0]->purpose)->toBe('mx-spf');
});

it('returns all records when everything is missing', function () {
    $checkResult = new DnsCheckResult(
        domain: 'example.com',
        allPassed: false,
        warnings: [],
        checks: new DnsChecks(
            ns: new DnsRecordCheck(status: DnsRecordStatus::Missing),
            mx: new DnsRecordCheck(status: DnsRecordStatus::Missing),
            spf: new DnsRecordCheck(status: DnsRecordStatus::Missing),
            dkim: new DnsRecordCheck(status: DnsRecordStatus::Missing),
            dmarc: new DnsRecordCheck(status: DnsRecordStatus::Missing),
        ),
    );

    $records = RequiredRecords::get('example.com', $checkResult);
    expect($records)->toHaveCount(3);
});

it('returns DMARC record when DMARC is missing', function () {
    $checkResult = new DnsCheckResult(
        domain: 'example.com',
        allPassed: false,
        warnings: [],
        checks: new DnsChecks(
            ns: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            mx: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            spf: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            dkim: new DnsRecordCheck(status: DnsRecordStatus::Pass),
            dmarc: new DnsRecordCheck(status: DnsRecordStatus::Missing),
        ),
    );

    $records = RequiredRecords::get('example.com', $checkResult);
    expect($records)->toHaveCount(1)
        ->and($records[0]->purpose)->toBe('dmarc');
});
