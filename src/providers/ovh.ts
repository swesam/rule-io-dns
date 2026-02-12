import { createHash } from 'node:crypto';
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
    throw new Error(`OVH: failed to get server time: ${res.status} ${text}`);
  }
  return (await res.json()) as number;
}

async function ovhFetch<T>(
  options: OvhOptions,
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  const url = `${OVH_API}${path}`;
  const bodyStr = body !== undefined ? JSON.stringify(body) : '';
  const timestamp = await getServerTime();
  const signature = ovhSignature(
    options.appSecret,
    options.consumerKey,
    method,
    url,
    bodyStr,
    timestamp
  );

  const headers: Record<string, string> = {
    'X-Ovh-Application': options.appKey,
    'X-Ovh-Consumer': options.consumerKey,
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

/**
 * Create an OVHcloud DNS provider adapter.
 *
 * Uses OVH API v1.0 with the OVH signature authentication scheme.
 * Requires application key, application secret, and consumer key.
 */
export function ovh(options: OvhOptions): DnsProvider {
  const { appKey, appSecret, consumerKey, zoneName } = options;

  if (!appKey) throw new Error('OVH: appKey is required');
  if (!appSecret) throw new Error('OVH: appSecret is required');
  if (!consumerKey) throw new Error('OVH: consumerKey is required');
  if (!zoneName) throw new Error('OVH: zoneName is required');

  return {
    async getRecords(name: string): Promise<ProviderRecord[]> {
      const subDomain = toSubDomain(name, zoneName);
      const ids = await ovhFetch<number[]>(
        options,
        'GET',
        `/domain/zone/${encodeURIComponent(zoneName)}/record?subDomain=${encodeURIComponent(subDomain)}`
      );

      const records: ProviderRecord[] = [];
      for (const id of ids) {
        const detail = await ovhFetch<OvhRecordDetail>(
          options,
          'GET',
          `/domain/zone/${encodeURIComponent(zoneName)}/record/${id}`
        );
        records.push({
          id: String(detail.id),
          type: detail.fieldType,
          name: toFqdn(detail.subDomain, zoneName),
          value: detail.target,
        });
      }

      return records;
    },

    async createRecord(record: {
      type: string;
      name: string;
      value: string;
    }): Promise<ProviderRecord> {
      const subDomain = toSubDomain(record.name, zoneName);
      const detail = await ovhFetch<OvhRecordDetail>(
        options,
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
      await ovhFetch<void>(
        options,
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
      await ovhFetch<void>(
        options,
        'DELETE',
        `/domain/zone/${encodeURIComponent(zoneName)}/record/${id}`
      );

      // Refresh the zone to apply changes
      await ovhFetch<void>(
        options,
        'POST',
        `/domain/zone/${encodeURIComponent(zoneName)}/refresh`
      );
    },
  };
}
