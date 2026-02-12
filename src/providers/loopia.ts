import type { DnsProvider, ProviderRecord } from '../provider.js';

export interface LoopiaOptions {
  username: string;
  password: string;
  domain: string;
}

interface LoopiaRecord {
  type: string;
  ttl: number;
  priority: number;
  rdata: string;
  record_id: number;
}

const LOOPIA_API = 'https://api.loopia.se/RPCSERV';

function buildXmlRpcRequest(method: string, params: unknown[]): string {
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<methodCall>',
    `<methodName>${method}</methodName>`,
    '<params>',
    ...params.map((p) => `<param>${serializeValue(p)}</param>`),
    '</params>',
    '</methodCall>',
  ].join('');
}

function serializeValue(value: unknown): string {
  if (typeof value === 'string') {
    return `<value><string>${escapeXml(value)}</string></value>`;
  }
  if (typeof value === 'number') {
    if (Number.isInteger(value)) {
      return `<value><int>${value}</int></value>`;
    }
    return `<value><double>${value}</double></value>`;
  }
  if (typeof value === 'boolean') {
    return `<value><boolean>${value ? 1 : 0}</boolean></value>`;
  }
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const members = Object.entries(value as Record<string, unknown>)
      .map(
        ([k, v]) =>
          `<member><name>${escapeXml(k)}</name>${serializeValue(v)}</member>`
      )
      .join('');
    return `<value><struct>${members}</struct></value>`;
  }
  if (Array.isArray(value)) {
    const data = value.map((v) => serializeValue(v)).join('');
    return `<value><array><data>${data}</data></array></value>`;
  }
  return `<value><string>${escapeXml(String(value))}</string></value>`;
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function extractFault(xml: string): string | null {
  const faultMatch = xml.match(/<fault>([\s\S]*?)<\/fault>/);
  if (!faultMatch) return null;
  const codeMatch = faultMatch[1]!.match(
    /<name>faultCode<\/name>\s*<value><int>(\d+)<\/int><\/value>/
  );
  const stringMatch = faultMatch[1]!.match(
    /<name>faultString<\/name>\s*<value><string>([\s\S]*?)<\/string><\/value>/
  );
  const code = codeMatch ? codeMatch[1] : 'unknown';
  const msg = stringMatch ? stringMatch[1] : 'unknown error';
  return `${code}: ${msg}`;
}

function splitTopLevelValues(xml: string): string[] {
  const results: string[] = [];
  let depth = 0;
  let start = -1;
  const openTag = '<value>';
  const closeTag = '</value>';
  let i = 0;
  while (i < xml.length) {
    if (xml.startsWith(openTag, i)) {
      if (depth === 0) start = i + openTag.length;
      depth++;
      i += openTag.length;
    } else if (xml.startsWith(closeTag, i)) {
      depth--;
      if (depth === 0 && start !== -1) {
        results.push(xml.slice(start, i));
        start = -1;
      }
      i += closeTag.length;
    } else {
      i++;
    }
  }
  return results;
}

function splitTopLevelMembers(xml: string): string[] {
  const results: string[] = [];
  let depth = 0;
  let start = -1;
  const openTag = '<member>';
  const closeTag = '</member>';
  let i = 0;
  while (i < xml.length) {
    if (xml.startsWith(openTag, i)) {
      if (depth === 0) start = i + openTag.length;
      depth++;
      i += openTag.length;
    } else if (xml.startsWith(closeTag, i)) {
      depth--;
      if (depth === 0 && start !== -1) {
        results.push(xml.slice(start, i));
        start = -1;
      }
      i += closeTag.length;
    } else {
      i++;
    }
  }
  return results;
}

function parseValue(xml: string): unknown {
  const trimmed = xml.trim();

  if (trimmed.includes('<array>')) {
    const dataMatch = trimmed.match(/<array>\s*<data>([\s\S]*)<\/data>\s*<\/array>/);
    if (!dataMatch) return [];
    return splitTopLevelValues(dataMatch[1]!).map((inner) => parseValue(inner));
  }

  if (trimmed.includes('<struct>')) {
    const structMatch = trimmed.match(/<struct>([\s\S]*)<\/struct>/);
    if (!structMatch) return {};
    const obj: Record<string, unknown> = {};
    for (const memberXml of splitTopLevelMembers(structMatch[1]!)) {
      const nameMatch = memberXml.match(/<name>([\s\S]*?)<\/name>/);
      if (!nameMatch) continue;
      const valueInners = splitTopLevelValues(memberXml);
      if (valueInners.length > 0) {
        obj[nameMatch[1]!] = parseValue(valueInners[0]!);
      }
    }
    return obj;
  }

  const strMatch = trimmed.match(/<string>([\s\S]*?)<\/string>/);
  if (strMatch) return strMatch[1]!;

  const intMatch = trimmed.match(/<(?:int|i4)>([\s\S]*?)<\/(?:int|i4)>/);
  if (intMatch) return parseInt(intMatch[1]!, 10);

  const doubleMatch = trimmed.match(/<double>([\s\S]*?)<\/double>/);
  if (doubleMatch) return parseFloat(doubleMatch[1]!);

  const boolMatch = trimmed.match(/<boolean>([\s\S]*?)<\/boolean>/);
  if (boolMatch) return boolMatch[1] === '1';

  return trimmed.replace(/<\/?value>/g, '').trim();
}

function parseXmlRpcResponse(xml: string): unknown {
  const fault = extractFault(xml);
  if (fault) {
    throw new Error(`Loopia: XML-RPC fault ${fault}`);
  }

  const paramsMatch = xml.match(/<params>([\s\S]*?)<\/params>/);
  if (!paramsMatch) {
    throw new Error('Loopia: invalid XML-RPC response');
  }

  const paramMatch = paramsMatch[1]!.match(
    /<param>\s*<value>([\s\S]*?)<\/value>\s*<\/param>/
  );
  if (!paramMatch) {
    throw new Error('Loopia: invalid XML-RPC response');
  }

  return parseValue(`<value>${paramMatch[1]!}</value>`);
}

async function loopiaCall(
  method: string,
  params: unknown[]
): Promise<unknown> {
  const body = buildXmlRpcRequest(method, params);

  const res = await fetch(LOOPIA_API, {
    method: 'POST',
    headers: { 'Content-Type': 'text/xml' },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Loopia: API error ${res.status}: ${text}`);
  }

  const xml = await res.text();
  return parseXmlRpcResponse(xml);
}

function toSubdomain(fqdn: string, domain: string): string {
  const lower = fqdn.toLowerCase();
  const domainLower = domain.toLowerCase();
  if (lower === domainLower) return '@';
  const suffix = `.${domainLower}`;
  if (lower.endsWith(suffix)) {
    return lower.slice(0, -suffix.length);
  }
  return lower;
}

function encodeId(subdomain: string, recordId: number): string {
  return `${subdomain}:${recordId}`;
}

function decodeId(id: string): { subdomain: string; recordId: number } {
  const sep = id.lastIndexOf(':');
  if (sep === -1) {
    throw new Error(`Loopia: invalid record id "${id}"`);
  }
  return {
    subdomain: id.slice(0, sep),
    recordId: parseInt(id.slice(sep + 1), 10),
  };
}

/**
 * Create a Loopia DNS provider adapter.
 *
 * Uses Loopia's XML-RPC API with native `fetch` (Node 18+).
 * Record IDs are encoded as `subdomain:record_id` to allow
 * deleteRecord to work without additional context.
 */
export function loopia(options: LoopiaOptions): DnsProvider {
  const { username, password, domain } = options;

  if (!username) {
    throw new Error('Loopia: username is required');
  }
  if (!password) {
    throw new Error('Loopia: password is required');
  }
  if (!domain) {
    throw new Error('Loopia: domain is required');
  }

  function call(method: string, extraParams: unknown[]) {
    return loopiaCall(method, [username, password, ...extraParams]);
  }

  return {
    async getRecords(name: string): Promise<ProviderRecord[]> {
      const subdomain = toSubdomain(name, domain);
      const result = (await call('getZoneRecords', [
        domain,
        subdomain,
      ])) as LoopiaRecord[] | string;

      if (typeof result === 'string') {
        throw new Error(`Loopia: getZoneRecords failed: ${result}`);
      }

      return result.map((r) => ({
        id: encodeId(subdomain, r.record_id),
        type: r.type,
        name,
        value: r.rdata,
      }));
    },

    async createRecord(record: {
      type: string;
      name: string;
      value: string;
    }): Promise<ProviderRecord> {
      const subdomain = toSubdomain(record.name, domain);
      const loopiaRecord = {
        type: record.type,
        ttl: 300,
        priority: 0,
        rdata: record.value,
      };

      const result = await call('addZoneRecord', [
        domain,
        subdomain,
        loopiaRecord,
      ]);

      if (result !== 'OK') {
        throw new Error(`Loopia: addZoneRecord failed: ${result}`);
      }

      const records = (await call('getZoneRecords', [
        domain,
        subdomain,
      ])) as LoopiaRecord[];

      const created = records.find(
        (r) => r.type === record.type && r.rdata === record.value
      );

      if (!created) {
        throw new Error('Loopia: record was created but could not be found');
      }

      return {
        id: encodeId(subdomain, created.record_id),
        type: created.type,
        name: record.name,
        value: created.rdata,
      };
    },

    async deleteRecord(id: string): Promise<void> {
      const { subdomain, recordId } = decodeId(id);

      const result = await call('removeZoneRecord', [
        domain,
        subdomain,
        recordId,
      ]);

      if (result !== 'OK') {
        throw new Error(`Loopia: removeZoneRecord failed: ${result}`);
      }
    },
  };
}
