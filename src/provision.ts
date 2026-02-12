import { checkDns } from './check-dns.js';
import { getRequiredDnsRecords } from './get-required-records.js';
import type { DnsProvider, ProviderRecord } from './provider.js';
import type { DnsRecord, DnsWarning } from './types.js';

export interface ProvisionResult {
  domain: string;
  created: DnsRecord[];
  deleted: ProviderRecord[];
  skipped: DnsRecord[];
  warnings: DnsWarning[];
}

/**
 * Auto-provision all required Rule.io DNS records via a provider adapter.
 *
 * 1. Runs `checkDns` to get current state + warnings
 * 2. Gets required records (only those not already passing)
 * 3. For each required record: deletes conflicting records, then creates the correct one
 * 4. Returns what was created, deleted, skipped, and any warnings
 */
export async function provisionDns(
  input: string,
  provider: DnsProvider
): Promise<ProvisionResult> {
  const checkResult = await checkDns(input);
  const required = getRequiredDnsRecords(input, checkResult);

  const created: DnsRecord[] = [];
  const deleted: ProviderRecord[] = [];
  const skipped: DnsRecord[] = [];

  // All 3 required records (if all pass, `required` is empty → everything is skipped)
  const allRecords = getRequiredDnsRecords(input);
  for (const record of allRecords) {
    if (!required.some((r) => r.name === record.name && r.type === record.type)) {
      skipped.push(record);
    }
  }

  for (const record of required) {
    const existing = await provider.getRecords(record.name);

    // Delete conflicting records (wrong type or wrong value at the same name)
    for (const ex of existing) {
      const sameType = ex.type.toUpperCase() === record.type;
      const sameValue = ex.value.toLowerCase() === record.value.toLowerCase();
      if (!sameType || !sameValue) {
        await provider.deleteRecord(ex.id);
        deleted.push(ex);
      }
    }

    // Check if the correct record already exists from the provider's perspective
    const alreadyExists = existing.some(
      (ex) =>
        ex.type.toUpperCase() === record.type &&
        ex.value.toLowerCase() === record.value.toLowerCase()
    );

    if (!alreadyExists) {
      await provider.createRecord({
        type: record.type,
        name: record.name,
        value: record.value,
      });
      created.push(record);
    } else {
      skipped.push(record);
    }
  }

  return {
    domain: checkResult.domain,
    created,
    deleted,
    skipped,
    warnings: checkResult.warnings,
  };
}
