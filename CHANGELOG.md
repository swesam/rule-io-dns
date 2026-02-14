# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-02-14

### Added

- **DNS checking** — validate MX, SPF, DKIM, and DMARC records against Rule.io's required configuration
- **Required records** — generate the 3 DNS records needed for Rule.io email sending
- **Auto-provisioning** — create, delete, and update DNS records through provider APIs
- **Provider detection** — identify DNS provider from nameserver hostnames
- **DMARC parsing** — parse raw DMARC TXT records into structured data
- **BIND zone export** — export DNS records as standard BIND zone file format
- **DNS resolvers** — `NativeDnsResolver` (php built-in) and `DigDnsResolver` (dig CLI)
- **7 DNS providers** — Cloudflare, Hetzner, Loopia, Gandi, Domeneshop, IONOS, OVH
- **Cloudflare proxy detection** — warn when orange-cloud proxy hides CNAME records
- **Wildcard DNS awareness** — skip false-positive proxy warnings when wildcard records exist
- **DMARC policy analysis** — warn about strict alignment and reject/quarantine policies
- **CNAME conflict detection** — warn when existing records prevent CNAME creation
