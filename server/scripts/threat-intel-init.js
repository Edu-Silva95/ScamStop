import "dotenv/config";

import { initThreatIntelSchema, canUseThreatIntel } from "../src/enrichment/threat-intel.js";

try {
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is required");
    process.exit(1);
  }

  // Init doesn't require ENABLE_THREAT_INTEL.
  await initThreatIntelSchema();
  console.log("Threat intel schema is ready.");

  if (!canUseThreatIntel()) {
    console.log("Note: ENABLE_THREAT_INTEL is not enabled (runtime lookups disabled). ");
  }
} catch (err) {
  console.error(err);
  process.exit(1);
}
