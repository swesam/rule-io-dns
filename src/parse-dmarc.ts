/** Parsed DMARC record */
export interface DmarcRecord {
  p: 'none' | 'quarantine' | 'reject';
  sp?: 'none' | 'quarantine' | 'reject';
  aspf?: 'r' | 's';
  adkim?: 'r' | 's';
  rua?: string[];
  ruf?: string[];
  pct?: number;
}

/**
 * Parse a DMARC TXT record string into a structured object.
 * Returns `null` if the string is not a valid DMARC record.
 */
export function parseDmarc(raw: string): DmarcRecord | null {
  const trimmed = raw.trim();
  if (!trimmed.startsWith('v=DMARC1')) {
    return null;
  }

  const tags = new Map<string, string>();
  const parts = trimmed.split(';');
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    tags.set(key, value);
  }

  const p = tags.get('p');
  if (p !== 'none' && p !== 'quarantine' && p !== 'reject') {
    return null;
  }

  const result: DmarcRecord = { p };

  const sp = tags.get('sp');
  if (sp === 'none' || sp === 'quarantine' || sp === 'reject') {
    result.sp = sp;
  }

  const aspf = tags.get('aspf');
  if (aspf === 'r' || aspf === 's') {
    result.aspf = aspf;
  }

  const adkim = tags.get('adkim');
  if (adkim === 'r' || adkim === 's') {
    result.adkim = adkim;
  }

  const rua = tags.get('rua');
  if (rua) {
    result.rua = parseMailtoList(rua);
  }

  const ruf = tags.get('ruf');
  if (ruf) {
    result.ruf = parseMailtoList(ruf);
  }

  const pct = tags.get('pct');
  if (pct !== undefined) {
    const num = Number(pct);
    if (!Number.isNaN(num)) {
      result.pct = num;
    }
  }

  return result;
}

function parseMailtoList(value: string): string[] {
  return value
    .split(',')
    .map((uri) => uri.trim())
    .filter((uri) => uri.startsWith('mailto:'))
    .map((uri) => uri.slice('mailto:'.length));
}
