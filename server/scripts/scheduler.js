import cron from "node-cron";
import "dotenv/config";

import { spawn } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const serverRoot = path.resolve(__dirname, "..");

const cronExpr = String(process.env.THREAT_INTEL_SYNC_CRON || "0 * * * *");
const recentCronExpr = String(process.env.THREAT_INTEL_SYNC_RECENT_CRON || "").trim();
const fullCronExpr = String(process.env.THREAT_INTEL_SYNC_FULL_CRON || "").trim();
const runOnStart = ["1", "true", "yes"].includes(
  String(process.env.THREAT_INTEL_RUN_ON_START || "").toLowerCase(),
);

if (!process.env.DATABASE_URL) {
  console.error("[Scheduler] DATABASE_URL is required");
  process.exit(1);
}

const useSplitSchedules = !!recentCronExpr || !!fullCronExpr;

if (!useSplitSchedules) {
  if (!cron.validate(cronExpr)) {
    console.error(`[Scheduler] Invalid THREAT_INTEL_SYNC_CRON: ${cronExpr}`);
    process.exit(1);
  }
} else {
  if (recentCronExpr && !cron.validate(recentCronExpr)) {
    console.error(`[Scheduler] Invalid THREAT_INTEL_SYNC_RECENT_CRON: ${recentCronExpr}`);
    process.exit(1);
  }
  if (fullCronExpr && !cron.validate(fullCronExpr)) {
    console.error(`[Scheduler] Invalid THREAT_INTEL_SYNC_FULL_CRON: ${fullCronExpr}`);
    process.exit(1);
  }
}

let running = false;

function runSync(args = []) {
  if (running) {
    console.log("[Scheduler] Previous sync still running; skipping this tick");
    return Promise.resolve(0);
  }

  running = true;
  const label = args.includes("--recent")
    ? "recent"
    : args.includes("--full")
      ? "full"
      : "all";

  console.log(`[Scheduler] Running threat-intel sync (${label})...`);

  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["scripts/threat-intel-sync.js", ...args], {
      cwd: serverRoot,
      stdio: "inherit",
      env: process.env,
    });

    child.on("error", (err) => {
      running = false;
      console.error("[Scheduler] Failed to start sync:", err?.message || err);
      resolve(1);
    });

    child.on("exit", (code) => {
      running = false;
      resolve(Number(code || 0));
    });
  });
}

if (process.argv.includes("--once")) {
  const code = await runSync([]);
  process.exit(code);
}

console.log("Threat intel scheduler started");
if (!useSplitSchedules) {
  console.log(`[Scheduler] THREAT_INTEL_SYNC_CRON=${cronExpr}`);
  cron.schedule(cronExpr, () => runSync([]));
  if (runOnStart) await runSync([]);
} else {
  if (recentCronExpr) {
    console.log(`[Scheduler] THREAT_INTEL_SYNC_RECENT_CRON=${recentCronExpr}`);
    cron.schedule(recentCronExpr, () => runSync(["--recent"]));
  }
  if (fullCronExpr) {
    console.log(`[Scheduler] THREAT_INTEL_SYNC_FULL_CRON=${fullCronExpr}`);
    cron.schedule(fullCronExpr, () => runSync(["--full"]));
  }
  if (runOnStart) await runSync(["--recent"]);
}