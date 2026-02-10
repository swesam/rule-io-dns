/**
 * Clean a domain input — accepts email addresses, URLs, or bare domains.
 *
 * Examples:
 * - `user@example.com` → `example.com`
 * - `https://www.example.com/path` → `example.com`
 * - `www.example.com` → `example.com`
 * - `example.com` → `example.com`
 * - `EXAMPLE.COM.` → `example.com`
 */
export function cleanDomain(input: string): string {
  let domain = input.trim().toLowerCase();

  // Extract domain from email
  if (domain.includes('@')) {
    domain = domain.split('@').pop()!;
  }

  // Extract hostname from URL
  if (domain.includes('://')) {
    try {
      domain = new URL(domain).hostname;
    } catch {
      // If URL parsing fails, strip protocol manually
      domain = domain.split('://')[1]?.split('/')[0] ?? domain;
    }
  }

  // Remove path, query, fragment if present (non-URL input with path)
  domain = domain.split('/')[0]!;

  // Remove trailing dot (FQDN notation)
  if (domain.endsWith('.')) {
    domain = domain.slice(0, -1);
  }

  // Remove www prefix
  if (domain.startsWith('www.')) {
    domain = domain.slice(4);
  }

  return domain;
}
