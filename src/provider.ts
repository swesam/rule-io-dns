/** A DNS record returned by a provider, including its provider-specific ID */
export interface ProviderRecord {
  id: string;
  type: string;
  name: string;
  value: string;
}

/** Minimal interface for a DNS provider adapter (3 methods, no update needed) */
export interface DnsProvider {
  /** Get all DNS records at a specific name */
  getRecords(name: string): Promise<ProviderRecord[]>;
  /** Create a DNS record */
  createRecord(record: {
    type: string;
    name: string;
    value: string;
  }): Promise<ProviderRecord>;
  /** Delete a DNS record by provider ID */
  deleteRecord(id: string): Promise<void>;
}
