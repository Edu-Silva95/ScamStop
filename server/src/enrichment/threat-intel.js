import axios from "axios";
import crypto from "node:crypto";
import zlib from "node:zlib";

import { query } from "../db.js";
import { getDomain, getHostname, normalizeDomain } from "../utils/url-utils.js";
import { parseUrlSafely } from "../utils/url-parsing.js";

function isEnabled() {
  const v = String(process.env.ENABLE_THREAT_INTEL || "").toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

export function canUseThreatIntel() {
  return isEnabled() && !!process.env.DATABASE_URL;
}

export async function initThreatIntelSchema() {
  await query(
    `
    CREATE TABLE IF NOT EXISTS threat_sources (
      id TEXT PRIMARY KEY,
      display_name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS threat_urls (
      source_id TEXT NOT NULL REFERENCES threat_sources(id) ON DELETE CASCADE,
      url_hash TEXT NOT NULL,
      canonical TEXT NOT NULL,
      url TEXT NOT NULL,
      hostname TEXT,
      domain TEXT,
      first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (source_id, url_hash)
    );

    CREATE INDEX IF NOT EXISTS threat_urls_url_hash_idx ON threat_urls (url_hash);
    CREATE INDEX IF NOT EXISTS threat_urls_domain_idx ON threat_urls (domain);
    `,
  );
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalizeForLookup(inputUrl) {
  const parsed = parseUrlSafely(inputUrl);
  if (!parsed) return null;

  const hostname = normalizeDomain(parsed.hostname);
  if (!hostname) return null;

  const pathname = parsed.pathname && parsed.pathname.length > 0 ? parsed.pathname : "/";
  const search = typeof parsed.search === "string" ? parsed.search : "";

  return `${hostname}${pathname}${search}`;
}

function canonicalCandidatesForLookup(inputUrl) {
  const canonical = canonicalizeForLookup(inputUrl);
  if (!canonical) return [];

  const candidates = new Set([canonical]);

  const slash = canonical.indexOf("/");
  const host = slash === -1 ? canonical : canonical.slice(0, slash);
  const rest = slash === -1 ? "" : canonical.slice(slash);

  if (host.startsWith("www.")) {
    candidates.add(`${host.slice(4)}${rest}`);
  } else {
    candidates.add(`www.${host}${rest}`);
  }

  return Array.from(candidates);
}

function normalizeThreatUrl(raw) {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;

  const u = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  const parsed = parseUrlSafely(u);
  if (!parsed) return null;

  const normalizedHostname = normalizeDomain(parsed.hostname);
  if (!normalizedHostname) return null;

  const proto = parsed.protocol && parsed.protocol.endsWith(":") ? parsed.protocol : "http:";
  const pathname = parsed.pathname && parsed.pathname.length > 0 ? parsed.pathname : "/";
  const search = typeof parsed.search === "string" ? parsed.search : "";

  const url = `${proto}//${normalizedHostname}${pathname}${search}`;
  const canonical = `${normalizedHostname}${pathname}${search}`;

  const hostname = getHostname(url);
  const domain = getDomain(url);

  return {
    url,
    canonical,
    urlHash: sha256Hex(canonical),
    hostname: hostname ? normalizeDomain(hostname) : null,
    domain: domain ? normalizeDomain(domain) : null,
  };
}

async function upsertThreatUrls(sourceId, sourceName, rawUrls) {
  await query(
    `INSERT INTO threat_sources (id, display_name)
     VALUES ($1, $2)
     ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name`,
    [sourceId, sourceName],
  );

  const cleaned = [];
  for (const raw of rawUrls) {
    const rec = normalizeThreatUrl(raw);
    if (!rec) continue;
    cleaned.push(rec);
  }

  const uniqueByHash = new Map();
  for (const c of cleaned) {
    if (!uniqueByHash.has(c.urlHash)) uniqueByHash.set(c.urlHash, c);
  }
  const unique = Array.from(uniqueByHash.values());

  if (unique.length === 0) return { insertedOrUpdated: 0 };

  const chunkSize = 1000;
  let count = 0;

  for (let i = 0; i < unique.length; i += chunkSize) {
    const chunk = unique.slice(i, i + chunkSize);

    const values = [];
    const params = [];
    let p = 1;

    for (const c of chunk) {
      values.push(`($${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, NOW(), NOW())`);
      params.push(sourceId, c.urlHash, c.canonical, c.url, c.hostname, c.domain);
    }

    const sql = `
      INSERT INTO threat_urls (source_id, url_hash, canonical, url, hostname, domain, first_seen, last_seen)
      VALUES ${values.join(",\n")}
      ON CONFLICT (source_id, url_hash)
      DO UPDATE SET last_seen = NOW();
    `;

    await query(sql, params);
    count += chunk.length;
  }

  return { insertedOrUpdated: count };
}

async function fetchJsonGzip(url, { timeoutMs, userAgent } = {}) {
  const timeout = Number.isFinite(timeoutMs) ? timeoutMs : 15000;
  const ua = typeof userAgent === "string" && userAgent ? userAgent : "ScamStop/1.0 (threat-intel sync)";

  const res = await axios.get(url, {
    responseType: "arraybuffer",
    timeout,
    maxRedirects: 5,
    headers: {
      "Accept": "application/json, */*;q=0.8",
      "User-Agent": ua,
    },
    validateStatus: (s) => s >= 200 && s < 400,
  });

  const buf = Buffer.from(res.data);
  const isGz = url.toLowerCase().endsWith(".gz");
  const payload = isGz ? zlib.gunzipSync(buf) : buf;
  return JSON.parse(payload.toString("utf8"));
}

export async function syncPhishTank() {
  const appKey = String(process.env.PHISHTANK_APP_KEY || "").trim();

  const base = appKey
    ? `http://data.phishtank.com/data/${encodeURIComponent(appKey)}/online-valid.json.gz`
    : "http://data.phishtank.com/data/online-valid.json.gz";

  const json = await fetchJsonGzip(base, { userAgent: process.env.THREAT_INTEL_USER_AGENT });

  const urls = Array.isArray(json) ? json.map((x) => x?.url).filter(Boolean) : [];
  return upsertThreatUrls("phishtank", "PhishTank", urls);
}

function extractUrlsFromTextLines(text) {
  const lines = String(text || "").split(/\r?\n/);
  const out = [];

  for (const line of lines) {
    const l = line.trim();
    if (!l) continue;

    const m = l.match(/https?:\/\/[^\s\",]+/i);
    if (m && m[0]) out.push(m[0]);
  }

  return out;
}

export async function syncUrlHausExport({ exportName, sourceId, sourceDisplayName }) {
  const authKey = String(process.env.URLHAUS_AUTH_KEY || "").trim();
  if (!authKey) throw new Error("URLHAUS_AUTH_KEY is required to download URLHaus exports");

  const safeExport = String(exportName || "").trim();
  if (!safeExport) throw new Error("URLHaus export name is required");

  const url = `https://urlhaus-api.abuse.ch/v2/files/exports/${encodeURIComponent(authKey)}/${encodeURIComponent(safeExport)}`;

  const res = await axios.get(url, {
    responseType: "text",
    timeout: 20000,
    maxRedirects: 5,
    headers: {
      "User-Agent": process.env.THREAT_INTEL_USER_AGENT || "ScamStop/1.0 (threat-intel sync)",
      "Accept": "text/csv, text/plain;q=0.9, */*;q=0.8",
    },
    validateStatus: (s) => s >= 200 && s < 400,
  });

  const urls = extractUrlsFromTextLines(res.data);
  return upsertThreatUrls(sourceId, sourceDisplayName, urls);
}

export async function syncUrlHausRecent() {
  const exportName = String(process.env.URLHAUS_EXPORT_RECENT || "recent.csv").trim() || "recent.csv";
  return syncUrlHausExport({
    exportName,
    sourceId: "urlhaus_recent",
    sourceDisplayName: "URLHaus (recent)",
  });
}

export async function syncUrlHausFull() {
  const exportName = String(process.env.URLHAUS_EXPORT_FULL || "").trim();
  if (!exportName) {
    throw new Error("URLHAUS_EXPORT_FULL is required to sync the full URLHaus dataset");
  }

  return syncUrlHausExport({
    exportName,
    sourceId: "urlhaus_full",
    sourceDisplayName: "URLHaus (full)",
  });
}

export async function lookupThreatMatches(urls) {
  if (!Array.isArray(urls) || urls.length === 0) return new Map();

  const hashes = [];
  const candidateToInput = new Map();

  for (const u of urls) {
    const candidates = canonicalCandidatesForLookup(u);
    if (candidates.length === 0) continue;

    for (const c of candidates) {
      candidateToInput.set(c, u);
      hashes.push(sha256Hex(c));
    }
  }

  if (hashes.length === 0) return new Map();

  const res = await query(
    `SELECT tu.source_id, ts.display_name, tu.url_hash, tu.canonical, tu.url
     FROM threat_urls tu
     JOIN threat_sources ts ON ts.id = tu.source_id
     WHERE tu.url_hash = ANY($1)`,
    [hashes],
  );

  const out = new Map();
  for (const row of res.rows || []) {
    const prev = out.get(row.canonical) || { sources: new Set(), urls: [] };
    prev.sources.add(row.display_name || row.source_id);
    if (row.url) prev.urls.push(row.url);
    out.set(row.canonical, prev);
  }

  return out;
}

export async function enrichAnalysisWithThreatIntel(analysis) {
  if (!canUseThreatIntel()) return analysis;
  if (!analysis || !Array.isArray(analysis.urls)) return analysis;

  await initThreatIntelSchema();

  let dbSources = [];
  try {
    const src = await query(
      `SELECT DISTINCT display_name
       FROM threat_sources
       ORDER BY display_name ASC`,
    );
    dbSources = (src.rows || []).map((r) => r.display_name).filter(Boolean);
  } catch {
    dbSources = [];
  }

  const urls = analysis.urls.map((u) => u?.url).filter(Boolean);
  const matches = await lookupThreatMatches(urls);

  analysis.threatIntel = {
    checked: urls.length > 0,
    match: matches.size > 0,
    sources: [],
    matchedCount: matches.size,
    dbSources,
  };

  if (matches.size === 0) return analysis;

  let hit = false;
  const sources = new Set();

  for (const u of analysis.urls) {
    const candidates = u?.url ? canonicalCandidatesForLookup(u.url) : [];
    if (candidates.length === 0) continue;

    let match = null;
    for (const c of candidates) {
      const m = matches.get(c);
      if (m) {
        match = m;
        break;
      }
    }
    if (!match) continue;

    hit = true;
    const matchSources = match?.sources ? Array.from(match.sources) : [];
    for (const s of matchSources) sources.add(s);
    u.notes = Array.isArray(u.notes) ? u.notes : [];
    if (matchSources.length > 0) {
      u.notes.push(`Known in threat feed: ${matchSources.join(", ")}`);
    } else {
      u.notes.push("Known in threat feed");
    }

    if (u.verdict !== "official") {
      if (u.verdict === "unknown" || u.verdict === "unverified") u.verdict = "suspicious";
    }
  }

  if (hit) {
    analysis.threatIntel.sources = Array.from(sources);
    analysis.score = Math.max(Number(analysis.score) || 0, 95);
    analysis.reasons = Array.isArray(analysis.reasons) ? analysis.reasons : [];
    analysis.reasons.push("Known malicious URL in threat intelligence feed");
    analysis.status = "malicious";
    analysis.reasons = Array.from(new Set(analysis.reasons));
  }

  return analysis;
}
