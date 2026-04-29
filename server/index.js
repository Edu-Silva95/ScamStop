import express from "express";
import cors from "cors";
import "dotenv/config";

import { analyzeMessage } from "./src/analyzers/message-analyzer.js";
import { enrichAnalysisWithNetwork } from "./src/enrichment/network-enrichment.js";
import {
  enrichAnalysisWithThreatIntel,
  initThreatIntelSchema,
  syncPhishTank,
  syncUrlHausRecent,
  syncUrlHausFull,
} from "./src/enrichment/threat-intel.js";

function envFlagTrue(value) {
  const v = String(value || "").toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("API running");
});

function getBearerToken(req) {
  const h = req?.headers?.authorization;
  if (typeof h !== "string") return null;
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

// Optional operational endpoint: trigger a sync without shell access.
// Enabled only when ADMIN_SYNC_TOKEN is set.
app.post("/api/admin/threat-intel/sync", async (req, res) => {
  const token = String(process.env.ADMIN_SYNC_TOKEN || "");
  if (!token) return res.status(404).json({ error: "Not found" });

  const provided = getBearerToken(req);
  if (!provided || provided !== token) return res.status(401).json({ error: "Unauthorized" });

  if (!process.env.DATABASE_URL) {
    return res.status(400).json({ error: "DATABASE_URL is required" });
  }

  const phishTankQuery = typeof req.query?.phishtank === "string" ? req.query.phishtank.toLowerCase() : null;
  const urlhausQuery = typeof req.query?.urlhaus === "string" ? req.query.urlhaus.toLowerCase() : null;

  const doPhishTank = phishTankQuery === "false" ? false : true;
  const doUrlHaus = urlhausQuery === "false" ? false : true;

  try {
    await initThreatIntelSchema();

    const out = {};
    if (doPhishTank) out.phishtank = await syncPhishTank();
    if (doUrlHaus) {
      out.urlhaus = {};
      out.urlhaus.recent = await syncUrlHausRecent().catch((e) => ({ error: String(e) }));
      out.urlhaus.full = await syncUrlHausFull().catch((e) => ({ error: String(e) }));
    }

    return res.json({ ok: true, ...out });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Sync failed" });
  }
});

app.post("/api/analyze", async (req, res) => {
  try {
    const { message } = req.body || {};
    if (typeof message !== "string") {
      return res.status(400).json({ error: "'message' must be a string" });
    }

    const baseResult = analyzeMessage(message);

    const enrichQuery = typeof req.query?.enrich === "string" ? req.query.enrich.toLowerCase() : null;
    const envEnabled = envFlagTrue(process.env.ENABLE_NETWORK_ENRICHMENT);
    const requestEnabled = enrichQuery === "true" ? true : enrichQuery === "false" ? false : envEnabled;

    const threshold = Number(process.env.ENRICH_MIN_SCORE || 30);
    const forceEnrich = enrichQuery === "true";
    const enrichNeutral = baseResult?.status === "neutral";
    const shouldEnrich =
      requestEnabled &&
      (forceEnrich || enrichNeutral || (Number.isFinite(baseResult.score) && baseResult.score >= threshold));

    const finalResult = shouldEnrich
      ? await enrichAnalysisWithNetwork(baseResult, { enabled: true })
      : baseResult;

    const withThreatIntel = await enrichAnalysisWithThreatIntel(finalResult);

    return res.json(withThreatIntel);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal error" });
  }
});

const server = app.listen(process.env.PORT || 3001, () => {
  console.log("Server running on port", process.env.PORT || 3001);
});

server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE") {
    console.error("Port already in use. Stop the other server and try again.");
    process.exit(1);
  }
  console.error(err);
  process.exit(1);
});
