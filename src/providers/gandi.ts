import type { DnsProvider, ProviderRecord } from '../provider.js';

export interface GandiDomain {
  fqdn: string;
}

export interface GandiOptions {
  apiToken: string;
  /** The zone (domain) name, e.g. "example.com" */
  domain: string;
  /** Optional Gandi organization sharing ID */
  sharingId?: string;
}

interface GandiRrset {
  rrset_name: string;
  rrset_type: string;
  rrset_ttl: number;
  rrset_values: string[];
}

const GANDI_API = 'https://api.gandi.net/v5';

async function gandiFetch<T>(
  apiToken: string,
  path: string,
  init?: RequestInit
): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set('Authorization', `Bearer ${apiToken}`);
  headers.set('Content-Type', 'application/json');

  const res = await fetch(`${GANDI_API}${path}`, {
    ...init,
    headers,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Gandi API error ${res.status}: ${text}`);
  }

  return (await res.json()) as T;
}

/**
 * Convert a fully-qualified domain name to a Gandi relative record name.
 *
 * "rm.example.com" with domain "example.com" → "rm"
 * "example.com" with domain "example.com" → "@"
 */
function toRelativeName(fqdn: string, domain: string): string {
  const lower = fqdn.toLowerCase();
  const zoneLower = domain.toLowerCase();

  if (lower === zoneLower) return '@';

  const suffix = `.${zoneLower}`;
  if (lower.endsWith(suffix)) {
    return lower.slice(0, -suffix.length);
  }

  return lower;
}

/**
 * Convert a Gandi relative name back to a fully-qualified domain name.
 *
 * "@" with domain "example.com" → "example.com"
 * "rm" with domain "example.com" → "rm.example.com"
 */
function toFqdn(relativeName: string, domain: string): string {
  if (relativeName === '@') return domain;
  return `${relativeName}.${domain}`;
}

/**
 * List all domains accessible with the given Gandi API token.
 */
export async function listGandiDomains(
  apiToken: string
): Promise<GandiDomain[]> {
  if (!apiToken) {
    throw new Error('Gandi: apiToken is required');
  }

  const results = await gandiFetch<{ fqdn: string }[]>(
    apiToken,
    '/livedns/domains'
  );

  return results.map((d) => ({ fqdn: d.fqdn }));
}

/**
 * Create a Gandi DNS provider adapter.
 *
 * Uses Gandi LiveDNS API v5 with native `fetch` (Node 18+).
 */
export function gandi(options: GandiOptions): DnsProvider {
  const { apiToken, domain } = options;

  if (!apiToken) {
    throw new Error('Gandi: apiToken is required');
  }
  if (!domain) {
    throw new Error('Gandi: domain is required');
  }

  function apiFetch<T>(path: string, init?: RequestInit) {
    return gandiFetch<T>(apiToken, path, init);
  }

  return {
    async getRecords(name: string): Promise<ProviderRecord[]> {
      const relative = toRelativeName(name, domain);

      let rrsets: GandiRrset[];
      try {
        rrsets = await apiFetch<GandiRrset[]>(
          `/livedns/domains/${encodeURIComponent(domain)}/records/${encodeURIComponent(relative)}`
        );
      } catch (err) {
        // Gandi returns 404 when no records exist at a name
        if (err instanceof Error && err.message.includes('404')) {
          return [];
        }
        throw err;
      }

      const records: ProviderRecord[] = [];
      for (const rrset of rrsets) {
        for (const value of rrset.rrset_values) {
          records.push({
            id: `${rrset.rrset_name}/${rrset.rrset_type}`,
            type: rrset.rrset_type,
            name: toFqdn(rrset.rrset_name, domain),
            value,
          });
        }
      }

      return records;
    },

    async createRecord(record: {
      type: string;
      name: string;
      value: string;
    }): Promise<ProviderRecord> {
      const relative = toRelativeName(record.name, domain);

      await apiFetch<unknown>(
        `/livedns/domains/${encodeURIComponent(domain)}/records`,
        {
          method: 'POST',
          body: JSON.stringify({
            rrset_name: relative,
            rrset_type: record.type,
            rrset_ttl: 300,
            rrset_values: [record.value],
          }),
        }
      );

      return {
        id: `${relative}/${record.type}`,
        type: record.type,
        name: toFqdn(relative, domain),
        value: record.value,
      };
    },

    async deleteRecord(id: string): Promise<void> {
      const [name, type] = id.split('/');
      if (!name || !type) {
        throw new Error(`Gandi: invalid record id "${id}"`);
      }

      await apiFetch<unknown>(
        `/livedns/domains/${encodeURIComponent(domain)}/records/${encodeURIComponent(name)}/${encodeURIComponent(type)}`,
        { method: 'DELETE' }
      );
    },
  };
}
