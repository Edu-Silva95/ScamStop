import "dotenv/config";

import {
  initThreatIntelSchema,
  syncPhishTank,
  syncUrlHausFull,
  syncUrlHausRecent,
} from "../src/enrichment/threat-intel.js";

function flag(name) {
  const v = String(process.env[name] || "").toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

// Defaults:
// - If URLHAUS_AUTH_KEY is set, sync recent by default
// - If URLHAUS_EXPORT_FULL is set, also sync full
// - PhishTank requires explicit enable via SYNC_PHISHTANK or PHISHTANK_APP_KEY
const wantPhishTank = flag("SYNC_PHISHTANK") || !!String(process.env.PHISHTANK_APP_KEY || "").trim();

const args = new Set(process.argv.slice(2));
const onlyRecent = args.has("--recent");
const onlyFull = args.has("--full");
const wantAll = args.has("--all");

const authKeyConfigured = !!String(process.env.URLHAUS_AUTH_KEY || "").trim();
const fullExportConfigured = !!String(process.env.URLHAUS_EXPORT_FULL || "").trim();

// If explicit flags are passed, respect them. Otherwise, sync recent by default if auth is configured.
const hasExplicitArgs = onlyRecent || onlyFull || wantAll;
const wantUrlHausRecent =
  (authKeyConfigured && (!hasExplicitArgs || wantAll || onlyRecent)) ||
  flag("SYNC_URLHAUS_RECENT") ||
  flag("SYNC_URLHAUS");

const wantUrlHausFull =
  authKeyConfigured &&
  (
    wantAll ||
    onlyFull ||
    flag("SYNC_URLHAUS_FULL") ||
    (flag("SYNC_URLHAUS") && fullExportConfigured)
  );

try {
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is required");
    process.exit(1);
  }

  await initThreatIntelSchema();

  if (!wantPhishTank && !wantUrlHausRecent && !wantUrlHausFull) {
    console.log(
      "No feeds selected. Configure URLHAUS_AUTH_KEY and/or PHISHTANK_APP_KEY, or set SYNC_URLHAUS_RECENT/SYNC_URLHAUS_FULL/SYNC_PHISHTANK=true.",
    );
    process.exit(0);
  }

  if (wantPhishTank) {
    console.log("Syncing PhishTank...");
    const res = await syncPhishTank();
    console.log(`PhishTank: upserted ${res.insertedOrUpdated}`);
  }

  if (wantUrlHausRecent) {
    console.log("Syncing URLHaus (recent)...");
    const res = await syncUrlHausRecent();
    console.log(`URLHaus (recent): upserted ${res.insertedOrUpdated}`);
  }

  if (wantUrlHausFull) {
    console.log("Syncing URLHaus (full)...");
    const res = await syncUrlHausFull();
    console.log(`URLHaus (full): upserted ${res.insertedOrUpdated}`);
  }

  console.log("Done.");
} catch (err) {
  console.error(err?.message || err);
  process.exit(1);
}
