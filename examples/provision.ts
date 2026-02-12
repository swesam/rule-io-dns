/**
 * Live test: provision Rule.io DNS records via Cloudflare.
 *
 * Usage:
 *   CF_API_TOKEN=xxx npx tsx examples/provision.ts alright.se
 */

import { provisionDns } from '../src/index.js';
import { cloudflare, listCloudflareZones } from '../src/providers/cloudflare.js';

const domain = process.argv[2];
const apiToken = process.env.CF_API_TOKEN;

if (!domain) {
  console.error('Usage: CF_API_TOKEN=xxx npx tsx examples/provision.ts <domain>');
  process.exit(1);
}

if (!apiToken) {
  console.error('Missing CF_API_TOKEN environment variable.');
  console.error('Create one at: https://dash.cloudflare.com/profile/api-tokens');
  console.error('Required permission: Zone > DNS > Edit');
  process.exit(1);
}

async function main() {
  console.log(`\nLooking up zones for your API token...`);
  const zones = await listCloudflareZones(apiToken!);

  if (zones.length === 0) {
    console.error('No zones found. Check your API token permissions.');
    process.exit(1);
  }

  console.log(`Found ${zones.length} zone(s):`);
  for (const z of zones) {
    const marker = z.name === domain ? ' <--' : '';
    console.log(`  ${z.name} (${z.id})${marker}`);
  }

  const match = zones.find((z) => z.name === domain);
  if (!match) {
    console.error(`\nZone "${domain}" not found. Available: ${zones.map((z) => z.name).join(', ')}`);
    process.exit(1);
  }

  console.log(`\nProvisioning DNS for ${domain}...`);
  const provider = cloudflare({ apiToken: apiToken!, zoneId: match.id });
  const result = await provisionDns(domain, provider);

  for (const r of result.created) {
    console.log(`  + Created: ${r.type} ${r.name} -> ${r.value}`);
  }
  for (const r of result.skipped) {
    console.log(`  = Skipped: ${r.type} ${r.name} (already correct)`);
  }
  for (const r of result.deleted) {
    console.log(`  - Deleted: ${r.type} ${r.name} (${r.value})`);
  }

  if (result.warnings.length > 0) {
    console.log(`\nWarnings:`);
    for (const w of result.warnings) {
      console.log(`  [${w.severity}] ${w.message}`);
    }
  }

  console.log(
    `\nDone! ${result.created.length} created, ${result.skipped.length} skipped, ${result.deleted.length} deleted.`
  );
}

main().catch((err) => {
  console.error('\nError:', err.message);
  process.exit(1);
});
