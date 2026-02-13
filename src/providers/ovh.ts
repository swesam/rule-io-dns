import { createHash } from 'node:crypto';
import { cleanDomain } from '../domain.js';
import type { DnsProvider, ProviderRecord } from '../provider.js';

export interface OvhOptions {
  appKey: string;
  appSecret: string;
  consumerKey: string;
  zoneName: string;
}

interface OvhRecordDetail {
  id: number;
  fieldType: string;
  subDomain: string;
  target: string;
  ttl: number;
  zone: string;
}

const OVH_API = 'https://eu.api.ovh.com/1.0';

function ovhSignature(
  appSecret: string,
  consumerKey: string,
  method: string,
  url: string,
  body: string,
  timestamp: number
): string {
  const raw = `${appSecret}+${consumerKey}+${method}+${url}+${body}+${timestamp}`;
  const hash = createHash('sha1').update(raw).digest('hex');
  return `$1$${hash}`;
}

async function getServerTime(): Promise<number> {
  const res = await fetch(`${OVH_API}/auth/time`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OVH: failed to get server time: ${res.status}: ${text}`);
  }
  return (await res.json()) as number;
}

/**
 * Convert an FQDN to an OVH relative subdomain.
 *
 * E.g. "rm.example.com" with zone "example.com" → "rm"
 *      "example.com" with zone "example.com" → "" (empty string = apex)
 */
function toSubDomain(fqdn: string, zoneName: string): string {
  const suffix = `.${zoneName}`;
  if (fqdn === zoneName) return '';
  if (fqdn.endsWith(suffix)) return fqdn.slice(0, -suffix.length);
  return fqdn;
}

/**
 * Convert an OVH relative subdomain back to FQDN.
 */
function toFqdn(subDomain: string, zoneName: string): string {
  if (!subDomain) return zoneName;
  return `${subDomain}.${zoneName}`;
}

/** Cache TTL for OVH server time (30 seconds) */
const TIME_CACHE_TTL = 30_000;

/**
 * Create an OVHcloud DNS provider adapter.
 *
 * Uses OVH API v1.0 with the OVH signature authentication scheme.
 * Requires application key, application secret, and consumer key.
 */
export function ovh(options: OvhOptions): DnsProvider {
  const { appKey, appSecret, consumerKey } = options;

  if (!appKey) throw new Error('OVH: appKey is required');
  if (!appSecret) throw new Error('OVH: appSecret is required');
  if (!consumerKey) throw new Error('OVH: consumerKey is required');
  if (!options.zoneName) throw new Error('OVH: zoneName is required');

  const zoneName = cleanDomain(options.zoneName);

  let cachedTimestamp: number | null = null;
  let cacheExpiry = 0;

  async function getTimestamp(): Promise<number> {
    const now = Date.now();
    if (cachedTimestamp !== null && now < cacheExpiry) {
      return cachedTimestamp;
    }
    const serverTime = await getServerTime();
    cachedTimestamp = serverTime;
    cacheExpiry = now + TIME_CACHE_TTL;
    return serverTime;
  }

  async function apiFetch<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = `${OVH_API}${path}`;
    const bodyStr = body !== undefined ? JSON.stringify(body) : '';
    const timestamp = await getTimestamp();
    const signature = ovhSignature(
      appSecret,
      consumerKey,
      method,
      url,
      bodyStr,
      timestamp
    );

    const headers: Record<string, string> = {
      'X-Ovh-Application': appKey,
      'X-Ovh-Consumer': consumerKey,
      'X-Ovh-Timestamp': String(timestamp),
      'X-Ovh-Signature': signature,
      'Content-Type': 'application/json',
    };

    const res = await fetch(url, {
      method,
      headers,
      ...(bodyStr ? { body: bodyStr } : {}),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`OVH: API error ${res.status}: ${text}`);
    }

    const text = await res.text();
    if (!text) return undefined as T;
    return JSON.parse(text) as T;
  }

  return {
    async getRecords(name: string): Promise<ProviderRecord[]> {
      const subDomain = toSubDomain(name, zoneName);
      const ids = await apiFetch<number[]>(
        'GET',
        `/domain/zone/${encodeURIComponent(zoneName)}/record?subDomain=${encodeURIComponent(subDomain)}`
      );

      const details = await Promise.all(
        ids.map((id) =>
          apiFetch<OvhRecordDetail>(
            'GET',
            `/domain/zone/${encodeURIComponent(zoneName)}/record/${id}`
          )
        )
      );

      return details.map((detail) => ({
        id: String(detail.id),
        type: detail.fieldType,
        name: toFqdn(detail.subDomain, zoneName),
        value: detail.target,
      }));
    },

    async createRecord(record: {
      type: string;
      name: string;
      value: string;
    }): Promise<ProviderRecord> {
      const subDomain = toSubDomain(record.name, zoneName);
      const detail = await apiFetch<OvhRecordDetail>(
        'POST',
        `/domain/zone/${encodeURIComponent(zoneName)}/record`,
        {
          fieldType: record.type,
          subDomain,
          target: record.value,
          ttl: 3600,
        }
      );

      // Refresh the zone to apply changes
      await apiFetch<void>(
        'POST',
        `/domain/zone/${encodeURIComponent(zoneName)}/refresh`
      );

      return {
        id: String(detail.id),
        type: detail.fieldType,
        name: toFqdn(detail.subDomain, zoneName),
        value: detail.target,
      };
    },

    async deleteRecord(id: string): Promise<void> {
      await apiFetch<void>(
        'DELETE',
        `/domain/zone/${encodeURIComponent(zoneName)}/record/${id}`
      );

      // Refresh the zone to apply changes
      await apiFetch<void>(
        'POST',
        `/domain/zone/${encodeURIComponent(zoneName)}/refresh`
      );
    },
  };
}
