<?php

use RuleIo\Dns\Data\ProviderSlug;
use RuleIo\Dns\ProviderDetector;

it('detects Cloudflare', function () {
    $result = ProviderDetector::detect(['arya.ns.cloudflare.com', 'bob.ns.cloudflare.com']);
    expect($result->slug)->toBe(ProviderSlug::Cloudflare)
        ->and($result->nameservers)->toBe(['arya.ns.cloudflare.com', 'bob.ns.cloudflare.com']);
});

it('detects Hetzner (.com)', function () {
    $result = ProviderDetector::detect(['helium.ns.hetzner.com', 'hydrogen.ns.hetzner.com']);
    expect($result->slug)->toBe(ProviderSlug::Hetzner)
        ->and($result->nameservers)->toBe(['helium.ns.hetzner.com', 'hydrogen.ns.hetzner.com']);
});

it('detects Hetzner (.de)', function () {
    $result = ProviderDetector::detect(['ns1.ns.hetzner.de']);
    expect($result->slug)->toBe(ProviderSlug::Hetzner)
        ->and($result->nameservers)->toBe(['ns1.ns.hetzner.de']);
});

it('detects Loopia', function () {
    $result = ProviderDetector::detect(['ns1.loopia.se', 'ns2.loopia.se']);
    expect($result->slug)->toBe(ProviderSlug::Loopia)
        ->and($result->nameservers)->toBe(['ns1.loopia.se', 'ns2.loopia.se']);
});

it('detects Gandi', function () {
    $result = ProviderDetector::detect(['ns-123-a.gandi.net', 'ns-456-b.gandi.net']);
    expect($result->slug)->toBe(ProviderSlug::Gandi)
        ->and($result->nameservers)->toBe(['ns-123-a.gandi.net', 'ns-456-b.gandi.net']);
});

it('detects Domeneshop', function () {
    $result = ProviderDetector::detect(['dns1.hyp.net', 'dns2.hyp.net']);
    expect($result->slug)->toBe(ProviderSlug::Domeneshop)
        ->and($result->nameservers)->toBe(['dns1.hyp.net', 'dns2.hyp.net']);
});

it('detects IONOS (.com)', function () {
    $result = ProviderDetector::detect(['ns1.ui-dns.com', 'ns2.ui-dns.com']);
    expect($result->slug)->toBe(ProviderSlug::Ionos)
        ->and($result->nameservers)->toBe(['ns1.ui-dns.com', 'ns2.ui-dns.com']);
});

it('detects IONOS (.org)', function () {
    $result = ProviderDetector::detect(['ns1.ui-dns.org']);
    expect($result->slug)->toBe(ProviderSlug::Ionos)
        ->and($result->nameservers)->toBe(['ns1.ui-dns.org']);
});

it('detects IONOS (.de)', function () {
    $result = ProviderDetector::detect(['ns1.ui-dns.de']);
    expect($result->slug)->toBe(ProviderSlug::Ionos)
        ->and($result->nameservers)->toBe(['ns1.ui-dns.de']);
});

it('detects IONOS (.biz)', function () {
    $result = ProviderDetector::detect(['ns1.ui-dns.biz']);
    expect($result->slug)->toBe(ProviderSlug::Ionos)
        ->and($result->nameservers)->toBe(['ns1.ui-dns.biz']);
});

it('detects OVH', function () {
    $result = ProviderDetector::detect(['dns1.ovh.net', 'ns1.ovh.net']);
    expect($result->slug)->toBe(ProviderSlug::Ovh)
        ->and($result->nameservers)->toBe(['dns1.ovh.net', 'ns1.ovh.net']);
});

it('handles mixed-case nameservers', function () {
    $result = ProviderDetector::detect(['Arya.NS.Cloudflare.COM']);
    expect($result->slug)->toBe(ProviderSlug::Cloudflare)
        ->and($result->nameservers)->toBe(['arya.ns.cloudflare.com']);
});

it('handles trailing dots', function () {
    $result = ProviderDetector::detect(['ns1.loopia.se.', 'ns2.loopia.se.']);
    expect($result->slug)->toBe(ProviderSlug::Loopia)
        ->and($result->nameservers)->toBe(['ns1.loopia.se', 'ns2.loopia.se']);
});

it('returns null for unknown providers', function () {
    $result = ProviderDetector::detect(['ns1.example.com', 'ns2.example.com']);
    expect($result)->toBeNull();
});

it('returns null for empty array', function () {
    $result = ProviderDetector::detect([]);
    expect($result)->toBeNull();
});

it('only includes matching nameservers when mixed', function () {
    $result = ProviderDetector::detect(['arya.ns.cloudflare.com', 'ns1.example.com']);
    expect($result->slug)->toBe(ProviderSlug::Cloudflare)
        ->and($result->nameservers)->toBe(['arya.ns.cloudflare.com']);
});
