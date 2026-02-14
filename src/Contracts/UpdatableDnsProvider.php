<?php

namespace RuleIo\Dns\Contracts;

use RuleIo\Dns\Data\ProviderRecord;

interface UpdatableDnsProvider
{
    /**
     * Update an existing DNS record by provider ID.
     *
     * @param array<string, mixed> $data Fields to update (e.g. ['proxied' => false])
     */
    public function updateRecord(string $id, array $data): ProviderRecord;
}
