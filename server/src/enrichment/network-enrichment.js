import "dotenv/config";
import axios from "axios";

import { getDomain } from "../utils/url-utils.js";

export async function getDomainAgeDaysViaRdap(domain) {
  try {
    const res = await axios.get(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      timeout: Number(process.env.NETWORK_TIMEOUT_MS || 3500),
      validateStatus: (s) => s >= 200 && s < 400,
    });

    const created = res?.data?.events?.find((e) => e.eventAction === "registration");
    if (created?.eventDate) {
      const createdAt = new Date(created.eventDate);
      const diff = Date.now() - createdAt.getTime();
      return Math.floor(diff / (1000 * 60 * 60 * 24));
    }
  } catch (err) {
    return null;
  }

  return null;
}

export async function enrichAnalysisWithNetwork(analysis, { enabled } = {}) {
  if (!enabled) return analysis;
  if (!analysis || !Array.isArray(analysis.urls)) return analysis;

  for (const u of analysis.urls) {
    if (!u.domain) continue;
    const age = await getDomainAgeDaysViaRdap(u.domain).catch(() => null);
    if (age != null) {
      u.notes = Array.isArray(u.notes) ? u.notes : [];
      u.notes.push(`Domain age (days): ${age}`);
    }
  }

  return analysis;
}
