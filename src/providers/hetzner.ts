import { cleanDomain } from '../domain.js';
import type { DnsProvider, ProviderRecord } from '../provider.js';

export interface HetznerOptions {
  apiToken: string;
  /** Provide the zone ID directly */
  zoneId?: string;
  /** Or provide the domain to auto-lookup the zone ID */
  domain?: string;
}

export interface HetznerZone {
  id: string;
  name: string;
}

interface HetznerDnsRecord {
  id: string;
  type: string;
  name: string;
  value: string;
  zone_id: string;
  ttl: number;
}

const HETZNER_API = 'https://dns.hetzner.com/api/v1';

async function hetznerFetchWithToken<T>(
  apiToken: string,
  path: string,
  init?: RequestInit
): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set('Auth-API-Token', apiToken);
  headers.set('Content-Type', 'application/json');

  const res = await fetch(`${HETZNER_API}${path}`, {
    ...init,
    headers,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Hetzner API error ${res.status}: ${text}`);
  }

  return (await res.json()) as T;
}

/**
 * List all zones (domains) accessible with the given API token.
 */
export async function listHetznerZones(
  apiToken: string
): Promise<HetznerZone[]> {
  if (!apiToken) {
    throw new Error('Hetzner: apiToken is required');
  }

  const data = await hetznerFetchWithToken<{ zones: HetznerZone[] }>(
    apiToken,
    '/zones'
  );

  return data.zones.map((z) => ({ id: z.id, name: z.name }));
}

/**
 * Create a Hetzner DNS provider adapter.
 *
 * Uses Hetzner DNS API v1 with native `fetch` (Node 18+).
 * Provide either `zoneId` directly or `domain` for auto-lookup.
 */
export function hetzner(options: HetznerOptions): DnsProvider {
  const { apiToken } = options;
  let resolvedZoneId: string | undefined = options.zoneId;
  let zoneIdPromise: Promise<string> | undefined;

  if (!apiToken) {
    throw new Error('Hetzner: apiToken is required');
  }
  if (!options.zoneId && !options.domain) {
    throw new Error('Hetzner: either zoneId or domain is required');
  }

  function hFetch<T>(path: string, init?: RequestInit) {
    return hetznerFetchWithToken<T>(apiToken, path, init);
  }

  async function lookupZoneId(): Promise<string> {
    const domain = cleanDomain(options.domain!);
    const data = await hFetch<{ zones: { id: string; name: string }[] }>(
      `/zones?name=${encodeURIComponent(domain)}`
    );

    if (!data.zones.length) {
      throw new Error(
        `Hetzner: no zone found for domain "${domain}"`
      );
    }

    resolvedZoneId = data.zones[0]!.id;
    return resolvedZoneId;
  }

  function getZoneId(): Promise<string> {
    if (resolvedZoneId) return Promise.resolve(resolvedZoneId);
    if (!zoneIdPromise) {
      zoneIdPromise = lookupZoneId().catch((err) => {
        zoneIdPromise = undefined;
        throw err;
      });
    }
    return zoneIdPromise;
  }

  return {
    async getRecords(name: string): Promise<ProviderRecord[]> {
      const zoneId = await getZoneId();
      const data = await hFetch<{ records: HetznerDnsRecord[] }>(
        `/records?zone_id=${encodeURIComponent(zoneId)}`
      );

      return data.records
        .filter((r) => r.name === name)
        .map((r) => ({
          id: r.id,
          type: r.type,
          name: r.name,
          value: r.value,
        }));
    },

    async createRecord(record: {
      type: string;
      name: string;
      value: string;
    }): Promise<ProviderRecord> {
      const zoneId = await getZoneId();
      const data = await hFetch<{ record: HetznerDnsRecord }>(
        '/records',
        {
          method: 'POST',
          body: JSON.stringify({
            zone_id: zoneId,
            type: record.type,
            name: record.name,
            value: record.value,
            ttl: 300,
          }),
        }
      );

      return {
        id: data.record.id,
        type: data.record.type,
        name: data.record.name,
        value: data.record.value,
      };
    },

    async deleteRecord(id: string): Promise<void> {
      await hFetch(`/records/${id}`, {
        method: 'DELETE',
      });
    },
  };
}
