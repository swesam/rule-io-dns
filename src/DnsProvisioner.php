<?php

namespace RuleIo\Dns;

use RuleIo\Dns\Contracts\DnsProvider;
use RuleIo\Dns\Contracts\DnsResolver;
use RuleIo\Dns\Contracts\UpdatableDnsProvider;
use RuleIo\Dns\Data\DnsRecord;
use RuleIo\Dns\Data\ProvisionResult;

class DnsProvisioner
{
    public static function provision(string $input, DnsProvider $provider, ?DnsResolver $resolver = null): ProvisionResult
    {
        $checkResult = DnsChecker::check($input, $resolver);
        $required = RequiredRecords::get($input, $checkResult);

        $created = [];
        $deleted = [];
        $skipped = [];
        $updated = [];

        // All 3 required records (if all pass, $required is empty → everything is skipped)
        $allRecords = RequiredRecords::get($input);
        foreach ($allRecords as $record) {
            $isRequired = false;
            foreach ($required as $r) {
                if ($r->name === $record->name && $r->type === $record->type) {
                    $isRequired = true;
                    break;
                }
            }
            if (!$isRequired) {
                $skipped[] = $record;
            }
        }

        foreach ($required as $record) {
            $existing = $provider->getRecords($record->name);

            // Delete conflicting records (wrong type or wrong value at the same name)
            foreach ($existing as $ex) {
                $sameType = strtoupper($ex->type) === $record->type;
                $sameValue = self::normalizeDnsValue($ex->value) === self::normalizeDnsValue($record->value);
                if (!$sameType || !$sameValue) {
                    $provider->deleteRecord($ex->id);
                    $deleted[] = $ex;
                }
            }

            // Check if the correct record already exists from the provider's perspective
            $matchingRecord = null;
            foreach ($existing as $ex) {
                if (strtoupper($ex->type) === $record->type
                    && self::normalizeDnsValue($ex->value) === self::normalizeDnsValue($record->value)) {
                    $matchingRecord = $ex;
                    break;
                }
            }

            if ($matchingRecord === null) {
                $provider->createRecord([
                    'type' => $record->type,
                    'name' => $record->name,
                    'value' => $record->value,
                ]);
                $created[] = $record;
            } else {
                if ($matchingRecord->proxied === true && $provider instanceof UpdatableDnsProvider) {
                    $updated[] = $provider->updateRecord($matchingRecord->id, ['proxied' => false]);
                }
                $skipped[] = $record;
            }
        }

        return new ProvisionResult(
            domain: $checkResult->domain,
            created: $created,
            deleted: $deleted,
            skipped: $skipped,
            warnings: $checkResult->warnings,
            updated: $updated,
        );
    }

    private static function normalizeDnsValue(string $value): string
    {
        return rtrim(strtolower($value), '.');
    }
}
