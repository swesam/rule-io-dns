<?php

namespace RuleIo\Dns\Contracts;

use RuleIo\Dns\Data\ProviderRecord;

interface UpdatableDnsProvider
{
    public function updateRecord(string $id, array $data): ProviderRecord;
}
