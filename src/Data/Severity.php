<?php

declare(strict_types=1);

namespace RuleIo\Dns\Data;

enum Severity: string
{
    case Error = 'error';
    case Warning = 'warning';
    case Info = 'info';
}
