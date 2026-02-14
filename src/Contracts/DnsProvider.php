<?php

declare(strict_types=1);

namespace RuleIo\Dns\Contracts;

use RuleIo\Dns\Data\ProviderRecord;

interface DnsProvider
{
    /**
     * Get all DNS records at a specific name.
     *
     * @return ProviderRecord[]
     */
    public function getRecords(string $name): array;

    /**
     * Create a DNS record.
     *
     * @param array{type: string, name: string, value: string} $record
     */
    public function createRecord(array $record): ProviderRecord;

    /**
     * Delete a DNS record by provider ID.
     */
    public function deleteRecord(string $id): void;
}
