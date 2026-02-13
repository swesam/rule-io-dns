<?php

namespace RuleIo\Dns\Data;

enum ProviderSlug: string
{
    case Cloudflare = 'cloudflare';
    case Hetzner = 'hetzner';
    case Loopia = 'loopia';
    case Gandi = 'gandi';
    case Domeneshop = 'domeneshop';
    case Ionos = 'ionos';
    case Ovh = 'ovh';
}
