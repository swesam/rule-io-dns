<?php

namespace RuleIo\Dns\Data;

enum DnsRecordStatus: string
{
    case Pass = 'pass';
    case Fail = 'fail';
    case Missing = 'missing';
}
