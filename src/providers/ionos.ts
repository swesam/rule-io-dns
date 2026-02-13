import { cleanDomain } from '../domain.js';
import type { DnsProvider, ProviderRecord } from '../provider.js';

export interface IonosOptions {
  /** Full API key in "publicPrefix.secret" format */
  apiKey: string;
  /** Provide the zone ID directly */
  zoneId?: string;
  /** Or provide the domain to auto-lookup the zone ID */
  domain?: string;
}

export interface IonosZone {
  id: string;
  name: string;
  type: string;
}

interface IonosDnsRecord {
  id: string;
  name: string;
  type: string;
  content: string;
  ttl: number;
  prio: number;
}

interface IonosZoneResponse {
  id: string;
  name: string;
  type: string;
  records: IonosDnsRecord[];
}

const IONOS_API = 'https://dns.de.api.ionos.com/v1';

async function ionosFetch<T>(
  apiKey: string,
  path: string,
  init?: RequestInit
): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set('X-API-Key', apiKey);
  headers.set('Content-Type', 'application/json');

  const res = await fetch(`${IONOS_API}${path}`, {
    ...init,
    headers,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`IONOS API error ${res.status}: ${text}`);
  }

  const text = await res.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

/**
 * List all zones accessible with the given API key.
 */
export async function listIonosZones(apiKey: string): Promise<IonosZone[]> {
  if (!apiKey) {
    throw new Error('IONOS: apiKey is required');
  }

  const zones = await ionosFetch<{ id: string; name: string; type: string }[]>(
    apiKey,
    '/zones'
  );

  return zones.map((z) => ({ id: z.id, name: z.name, type: z.type }));
}

/**
 * Create an IONOS DNS provider adapter.
 *
 * Uses the IONOS DNS API with native `fetch` (Node 18+).
 * Provide either `zoneId` directly or `domain` for auto-lookup.
 */
export function ionos(options: IonosOptions): DnsProvider {
  const { apiKey } = options;
  let resolvedZoneId: string | undefined = options.zoneId;
  let zoneIdPromise: Promise<string> | undefined;

  if (!apiKey) {
    throw new Error('IONOS: apiKey is required');
  }
  if (!options.zoneId && !options.domain) {
    throw new Error('IONOS: either zoneId or domain is required');
  }

  async function lookupZoneId(): Promise<string> {
    const domain = cleanDomain(options.domain!);
    const zones = await ionosFetch<{ id: string; name: string }[]>(
      apiKey,
      '/zones'
    );

    const match = zones.find((z) => z.name === domain);
    if (!match) {
      throw new Error(`IONOS: no zone found for domain "${domain}"`);
    }

    resolvedZoneId = match.id;
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
      const zone = await ionosFetch<IonosZoneResponse>(
        apiKey,
        `/zones/${zoneId}?recordName=${encodeURIComponent(name)}&recordType=`
      );

      return zone.records.map((r) => ({
        id: r.id,
        type: r.type,
        name: r.name,
        value: r.content,
      }));
    },

    async createRecord(record: {
      type: string;
      name: string;
      value: string;
    }): Promise<ProviderRecord> {
      const zoneId = await getZoneId();
      const created = await ionosFetch<IonosDnsRecord[]>(
        apiKey,
        `/zones/${zoneId}/records`,
        {
          method: 'POST',
          body: JSON.stringify([
            {
              name: record.name,
              type: record.type,
              content: record.value,
              ttl: 3600,
              prio: 0,
            },
          ]),
        }
      );

      if (!Array.isArray(created) || created.length === 0) {
        throw new Error('IONOS: record was created but API returned no records');
      }

      const r = created[0]!;
      return {
        id: r.id,
        type: r.type,
        name: r.name,
        value: r.content,
      };
    },

    async deleteRecord(id: string): Promise<void> {
      const zoneId = await getZoneId();
      await ionosFetch(apiKey, `/zones/${zoneId}/records/${id}`, {
        method: 'DELETE',
      });
    },
  };
}
