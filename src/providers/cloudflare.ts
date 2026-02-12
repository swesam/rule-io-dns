import { cleanDomain } from '../domain.js';
import type { DnsProvider, ProviderRecord } from '../provider.js';

export interface CloudflareOptions {
  apiToken: string;
  /** Provide the zone ID directly */
  zoneId?: string;
  /** Or provide the domain to auto-lookup the zone ID */
  domain?: string;
}

export interface CloudflareZone {
  id: string;
  name: string;
}

interface CloudflareApiResponse<T> {
  success: boolean;
  errors: { code: number; message: string }[];
  result: T;
  result_info?: { page: number; total_pages: number };
}

interface CloudflareDnsRecord {
  id: string;
  type: string;
  name: string;
  content: string;
}

const CF_API = 'https://api.cloudflare.com/client/v4';

async function cfFetchWithToken<T>(
  apiToken: string,
  path: string,
  init?: RequestInit
): Promise<CloudflareApiResponse<T>> {
  const headers = new Headers(init?.headers);
  headers.set('Authorization', `Bearer ${apiToken}`);
  headers.set('Content-Type', 'application/json');

  const res = await fetch(`${CF_API}${path}`, {
    ...init,
    headers,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Cloudflare API error ${res.status}: ${text}`);
  }

  const data = (await res.json()) as CloudflareApiResponse<T>;

  if (!data.success) {
    const errorDetails =
      data.errors?.map((e) => `${e.code}: ${e.message}`).join(', ') ||
      'unknown error';
    throw new Error(`Cloudflare API error: ${errorDetails}`);
  }

  return data;
}

/**
 * List all zones (domains) accessible with the given API token.
 *
 * Useful for building a domain picker UI after the user provides a token.
 */
export async function listCloudflareZones(
  apiToken: string
): Promise<CloudflareZone[]> {
  if (!apiToken) {
    throw new Error('Cloudflare: apiToken is required');
  }
  const zones: CloudflareZone[] = [];
  let page = 1;

  while (true) {
    const data = await cfFetchWithToken<{ id: string; name: string }[]>(
      apiToken,
      `/zones?page=${page}&per_page=50`
    );

    for (const z of data.result) {
      zones.push({ id: z.id, name: z.name });
    }

    const info = data.result_info;
    if (!info || page >= info.total_pages) break;
    page++;
  }

  return zones;
}

/**
 * Create a Cloudflare DNS provider adapter.
 *
 * Uses Cloudflare API v4 with native `fetch` (Node 18+).
 * Provide either `zoneId` directly or `domain` for auto-lookup.
 */
export function cloudflare(options: CloudflareOptions): DnsProvider {
  const { apiToken } = options;
  let resolvedZoneId: string | undefined = options.zoneId;
  let zoneIdPromise: Promise<string> | undefined;

  if (!apiToken) {
    throw new Error('Cloudflare: apiToken is required');
  }
  if (!options.zoneId && !options.domain) {
    throw new Error('Cloudflare: either zoneId or domain is required');
  }

  function cfFetch<T>(path: string, init?: RequestInit) {
    return cfFetchWithToken<T>(apiToken, path, init);
  }

  async function lookupZoneId(): Promise<string> {
    const domain = cleanDomain(options.domain!);
    const data = await cfFetch<{ id: string }[]>(
      `/zones?name=${encodeURIComponent(domain)}`
    );

    if (!data.result.length) {
      throw new Error(
        `Cloudflare: no zone found for domain "${domain}"`
      );
    }

    resolvedZoneId = data.result[0]!.id;
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
      const data = await cfFetch<CloudflareDnsRecord[]>(
        `/zones/${zoneId}/dns_records?name=${encodeURIComponent(name)}`
      );

      return data.result.map((r) => ({
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
      const data = await cfFetch<CloudflareDnsRecord>(
        `/zones/${zoneId}/dns_records`,
        {
          method: 'POST',
          body: JSON.stringify({
            type: record.type,
            name: record.name,
            content: record.value,
          }),
        }
      );

      return {
        id: data.result.id,
        type: data.result.type,
        name: data.result.name,
        value: data.result.content,
      };
    },

    async deleteRecord(id: string): Promise<void> {
      const zoneId = await getZoneId();
      await cfFetch(`/zones/${zoneId}/dns_records/${id}`, {
        method: 'DELETE',
      });
    },
  };
}
