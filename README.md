# rule-io/dns

DNS validation, record generation, and auto-provisioning for Rule.io email setup.

## Installation

```bash
composer require rule-io/dns
```

## Usage

### Check DNS records

```php
use RuleIo\Dns\DnsChecker;
use RuleIo\Dns\DigDnsResolver;

$result = DnsChecker::check('example.com', new DigDnsResolver());

$result->allPassed;       // bool
$result->checks->mx;      // DnsRecordCheck (status, expected, actual)
$result->checks->spf;
$result->checks->dkim;
$result->checks->dmarc;
$result->checks->ns;
$result->warnings;         // DnsWarning[]
```

### Get required records

```php
use RuleIo\Dns\RequiredRecords;

// All 3 required records
$records = RequiredRecords::get('example.com');

// Only records that are missing/failing
$records = RequiredRecords::get('example.com', $checkResult);
```

### Detect DNS provider

```php
use RuleIo\Dns\ProviderDetector;

$provider = ProviderDetector::detect($checkResult->checks->ns->actual);
// DetectedProvider { slug: ProviderSlug::Cloudflare, nameservers: [...] }
```

### Auto-provision records

```php
use RuleIo\Dns\DnsProvisioner;
use RuleIo\Dns\Providers\CloudflareProvider;

$provider = new CloudflareProvider(apiToken: '...', domain: 'example.com');
$result = DnsProvisioner::provision('example.com', $provider);

$result->created;   // DnsRecord[]
$result->deleted;   // ProviderRecord[] (conflicting records removed)
$result->skipped;   // DnsRecord[] (already correct)
$result->warnings;  // DnsWarning[]
```

## Supported Providers

### Cloudflare

```php
new CloudflareProvider(apiToken: '...', domain: 'example.com');
```

**How to get credentials:**

1. Go to [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token**
3. Use the **Edit zone DNS** template
4. Under **Zone Resources**, select **Specific zone** and pick the domain
5. Click **Continue to summary** → **Create Token**
6. Copy the token (it is only shown once)

### Hetzner

```php
new HetznerProvider(apiToken: '...', domain: 'example.com');
```

**How to get credentials:**

1. Go to [dns.hetzner.com/settings/api-token](https://dns.hetzner.com/settings/api-token)
2. Click **Create API token**
3. Give it a name and click **Create API token**
4. Copy the token (it is only shown once)

### Loopia

```php
new LoopiaProvider(username: 'user@loopiaapi', password: '...', domain: 'example.com');
```

**How to get credentials:**

Loopia requires a dedicated API user — regular login credentials will **not** work.

1. Log in to [Loopia Customer Zone](https://customerzone.loopia.se/api/)
2. Go to **API-användare** (API Users)
3. Click **Skapa ny API-användare** (Create new API user)
4. Set a username and password — the full username will be `username@loopiaapi`
5. Enable permissions: **getZoneRecords**, **addZoneRecord**, **removeZoneRecord**, **addSubdomain**

### Gandi

```php
new GandiProvider(apiToken: '...', domain: 'example.com');
```

**How to get credentials:**

1. Go to [admin.gandi.net → Account → Personal Access Tokens](https://admin.gandi.net/organizations/account/pat)
2. Click **Create a token**
3. Give it a name, select your organization, and choose an expiration
4. Under permissions, enable **Manage domain name technical configurations**
5. Click **Create** and copy the token (it is only shown once)

### Domeneshop

```php
new DomeneshopProvider(token: '...', secret: '...', domain: 'example.com');
```

**How to get credentials:**

1. Log in to [domeneshop.no/admin](https://www.domeneshop.no/admin)
2. Go to **Mitt domene** → **API-tilgang** (API access)
3. Click **Generer nye nøkler** (Generate new keys)
4. Copy both the **Token** and the **Secret**

### IONOS

```php
new IonosProvider(apiKey: 'publicprefix.secret', domain: 'example.com');
```

**How to get credentials:**

1. Go to [developer.hosting.ionos.com/keys](https://developer.hosting.ionos.com/keys)
2. Click **Create new API key**
3. The key is displayed as two parts: a **Public Prefix** and a **Secret**
4. Combine them as `publicprefix.secret` (dot-separated)
5. Copy the combined key (the secret is only shown once)

### OVH

```php
new OvhProvider(
    appKey: '...',
    appSecret: '...',
    consumerKey: '...',
    zoneName: 'example.com',
);
```

**How to get credentials:**

OVH requires three keys:

1. Go to [eu.api.ovh.com/createApp](https://eu.api.ovh.com/createApp/)
2. Log in with your OVH account and fill in an application name and description
3. You will receive an **Application Key** and **Application Secret**
4. Request a Consumer Key by visiting [this link](https://eu.api.ovh.com/cgi-bin/api/createToken/index.cgi?GET=/domain/zone/*&PUT=/domain/zone/*&POST=/domain/zone/*&DELETE=/domain/zone/*) to grant DNS zone access
5. Log in and confirm — you will receive a **Consumer Key**

## DNS Resolvers

The package ships with two resolver implementations:

| Resolver | Description |
|----------|-------------|
| `NativeDnsResolver` | Uses PHP's `dns_get_record()`. Can be slow on macOS (5-10s per query for non-existent records). |
| `DigDnsResolver` | Requires `dig` CLI (macOS/Linux). Uses 3s timeout, queries `1.1.1.1` by default. |

Pass a resolver to `DnsChecker::check()` and `DnsProvisioner::provision()`:

```php
$resolver = new DigDnsResolver();
$result = DnsChecker::check('example.com', $resolver);
$provision = DnsProvisioner::provision('example.com', $provider, $resolver);

// Use a different nameserver
$resolver = new DigDnsResolver(nameserver: '8.8.8.8');
```
