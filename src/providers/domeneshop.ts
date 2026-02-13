import { cleanDomain } from '../domain.js';
import type { DnsProvider, ProviderRecord } from '../provider.js';

export interface DomeneshopOptions {
  token: string;
  secret: string;
  /** Provide the domain ID directly */
  domainId?: number;
  /** Or provide the domain name to auto-lookup the domain ID */
  domain?: string;
}

export interface DomeneshopDomain {
  id: number;
  domain: string;
}

interface DomeneshopDnsRecord {
  id: number;
  host: string;
  type: string;
  data: string;
  ttl: number;
}

const DS_API = 'https://api.domeneshop.no/v0';

async function dsFetch<T>(
  token: string,
  secret: string,
  path: string,
  init?: RequestInit
): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set(
    'Authorization',
    `Basic ${Buffer.from(`${token}:${secret}`, 'utf8').toString('base64')}`
  );
  headers.set('Content-Type', 'application/json');

  const res = await fetch(`${DS_API}${path}`, {
    ...init,
    headers,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Domeneshop API error ${res.status}: ${text}`);
  }

  // DELETE returns 204 No Content
  if (res.status === 204) {
    return undefined as T;
  }

  return (await res.json()) as T;
}

/**
 * List all domains accessible with the given credentials.
 */
export async function listDomeneshopDomains(
  token: string,
  secret: string
): Promise<DomeneshopDomain[]> {
  if (!token || !secret) {
    throw new Error('Domeneshop: token and secret are required');
  }
  const domains = await dsFetch<{ id: number; domain: string }[]>(
    token,
    secret,
    '/domains'
  );
  return domains.map((d) => ({ id: d.id, domain: d.domain }));
}

/**
 * Convert FQDN to a relative host for Domeneshop.
 *
 * "rm.example.com" with domain "example.com" → "rm"
 * "example.com" with domain "example.com" → "@"
 */
function toRelativeHost(fqdn: string, domainName: string): string {
  const lower = fqdn.toLowerCase();
  const domainLower = domainName.toLowerCase();

  if (lower === domainLower) {
    return '@';
  }

  const suffix = '.' + domainLower;
  if (lower.endsWith(suffix)) {
    return lower.slice(0, -suffix.length);
  }

  return lower;
}

/**
 * Convert relative host back to FQDN.
 *
 * "rm" with domain "example.com" → "rm.example.com"
 * "@" with domain "example.com" → "example.com"
 */
function toFqdn(host: string, domainName: string): string {
  if (host === '@' || host === '') {
    return domainName;
  }
  return `${host}.${domainName}`;
}

/**
 * Create a Domeneshop DNS provider adapter.
 *
 * Uses Domeneshop API v0 with native `fetch` (Node 18+).
 * Provide either `domainId` directly or `domain` for auto-lookup.
 */
export function domeneshop(options: DomeneshopOptions): DnsProvider {
  const { token, secret } = options;
  let resolvedDomainId: number | undefined = options.domainId;
  let resolvedDomainName: string | undefined;
  let domainIdPromise: Promise<{ id: number; name: string }> | undefined;

  if (!token) {
    throw new Error('Domeneshop: token is required');
  }
  if (!secret) {
    throw new Error('Domeneshop: secret is required');
  }
  if (options.domainId != null) {
    if (
      !Number.isFinite(options.domainId) ||
      !Number.isInteger(options.domainId) ||
      options.domainId <= 0
    ) {
      throw new Error('Domeneshop: domainId must be a positive integer');
    }
  } else if (!options.domain) {
    throw new Error('Domeneshop: either domainId or domain is required');
  }

  function apiFetch<T>(path: string, init?: RequestInit) {
    return dsFetch<T>(token, secret, path, init);
  }

  async function lookupDomainId(): Promise<{ id: number; name: string }> {
    const domain = cleanDomain(options.domain!);
    const domains = await apiFetch<{ id: number; domain: string }[]>(
      '/domains'
    );

    const match = domains.find(
      (d) => d.domain.toLowerCase() === domain
    );

    if (!match) {
      throw new Error(
        `Domeneshop: no domain found for "${domain}"`
      );
    }

    resolvedDomainId = match.id;
    resolvedDomainName = match.domain;
    return { id: match.id, name: match.domain };
  }

  function getDomainInfo(): Promise<{ id: number; name: string }> {
    if (resolvedDomainId != null && resolvedDomainName) {
      return Promise.resolve({ id: resolvedDomainId, name: resolvedDomainName });
    }
    if (!domainIdPromise) {
      domainIdPromise = lookupDomainId().catch((err) => {
        domainIdPromise = undefined;
        throw err;
      });
    }
    return domainIdPromise;
  }

  // When domainId is provided directly, we need the domain name for FQDN conversion.
  async function getDomainName(): Promise<string> {
    if (resolvedDomainName) return resolvedDomainName;

    if (options.domain) {
      resolvedDomainName = cleanDomain(options.domain);
      return resolvedDomainName;
    }

    // domainId was provided but not domain name — look it up
    const domains = await apiFetch<{ id: number; domain: string }[]>(
      '/domains'
    );
    const match = domains.find((d) => d.id === resolvedDomainId);
    if (!match) {
      throw new Error(
        `Domeneshop: no domain found for ID ${resolvedDomainId}`
      );
    }
    resolvedDomainName = match.domain;
    return resolvedDomainName;
  }

  return {
    async getRecords(name: string): Promise<ProviderRecord[]> {
      let domainId: number;

      if (resolvedDomainId != null) {
        domainId = resolvedDomainId;
      } else {
        const info = await getDomainInfo();
        domainId = info.id;
      }

      const domainName = await getDomainName();
      const host = toRelativeHost(name, domainName);

      const records = await apiFetch<DomeneshopDnsRecord[]>(
        `/domains/${domainId}/dns?host=${encodeURIComponent(host)}`
      );

      return records.map((r) => ({
        id: String(r.id),
        type: r.type,
        name: toFqdn(r.host, domainName),
        value: r.data,
      }));
    },

    async createRecord(record: {
      type: string;
      name: string;
      value: string;
    }): Promise<ProviderRecord> {
      let domainId: number;

      if (resolvedDomainId != null) {
        domainId = resolvedDomainId;
      } else {
        const info = await getDomainInfo();
        domainId = info.id;
      }

      const domainName = await getDomainName();
      const host = toRelativeHost(record.name, domainName);

      const created = await apiFetch<DomeneshopDnsRecord>(
        `/domains/${domainId}/dns`,
        {
          method: 'POST',
          body: JSON.stringify({
            host,
            type: record.type,
            data: record.value,
            ttl: 3600,
          }),
        }
      );

      return {
        id: String(created.id),
        type: created.type,
        name: toFqdn(created.host, domainName),
        value: created.data,
      };
    },

    async deleteRecord(id: string): Promise<void> {
      let domainId: number;

      if (resolvedDomainId != null) {
        domainId = resolvedDomainId;
      } else {
        const info = await getDomainInfo();
        domainId = info.id;
      }

      await apiFetch(
        `/domains/${domainId}/dns/${id}`,
        { method: 'DELETE' }
      );
    },
  };
}
