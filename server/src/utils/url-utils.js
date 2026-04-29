import { parse } from "tldts";

export function extractUrls(text) {
  const safeText = typeof text === "string" ? text : "";
  let normalizedText = safeText.replace(/[\u200B-\u200D\uFEFF]/g, "");
  normalizedText = normalizedText
    .replace(/\bhxxps:\/\//gi, "https://")
    .replace(/\bhxxp:\/\//gi, "http://")
    .replace(/([a-z0-9])\[\.\]([a-z0-9])/gi, "$1.$2");

  function cleanUrlToken(token) {
    if (!token) return null;
    let cleaned = String(token).trim();
    cleaned = cleaned.replace(/^[<([{\"']+/, "");
    cleaned = cleaned.replace(/[>)}\]\"']+$/g, "");
    cleaned = cleaned.replace(/[)\]}>.,!?;:]+$/g, "");
    if (!cleaned) return null;
    if (cleaned.length > 2048) return null;
    return cleaned;
  }

  const found = [];
  const schemeRegex = /https?:\/\/[^\s<>\"']+/gi;
  for (const match of normalizedText.matchAll(schemeRegex)) {
    const cleaned = cleanUrlToken(match[0]);
    if (cleaned) found.push(cleaned);
  }

  const bareRegex = /\b(?:www\.)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?(?:[/?#][^\s<>\"']*)?\b/gi;
  const lower = normalizedText.toLowerCase();

  for (const match of normalizedText.matchAll(bareRegex)) {
    const raw = match[0];
    if (!raw) continue;

    const idx = typeof match.index === "number" ? match.index : -1;
    if (idx > 0 && normalizedText[idx - 1] === "@") continue;
    if (idx >= 3) {
      const prefix = lower.slice(Math.max(0, idx - 8), idx);
      if (prefix.includes("://")) continue;
    }

    const cleaned = cleanUrlToken(raw);
    if (cleaned) found.push(cleaned);
  }

  return Array.from(new Set(found));
}

function ensureScheme(value) {
  if (!value) return value;
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`;
}

export function normalizeDomain(domain) {
  if (!domain) return null;
  try {
    const hostname = new URL(`http://${domain}`).hostname;
    return hostname.toLowerCase().trim().replace(/\.$/, "");
  } catch {
    return domain.toLowerCase().trim().replace(/\.$/, "");
  }
}

export function getHostname(url) {
  try {
    const u = new URL(ensureScheme(url));
    return normalizeDomain(u.hostname);
  } catch {
    return null;
  }
}

export function getRegistrableDomain(value) {
  try {
    const parsed = parse(ensureScheme(value));
    return normalizeDomain(parsed.domain);
  } catch {
    return null;
  }
}

export function getDomain(url) {
  return getRegistrableDomain(url);
}

const SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "t.co",
  "tinyurl.com",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "cutt.ly",
  "rebrand.ly",
  "shorturl.at",
  "rb.gy",
  "buff.ly",
  "lnkd.in",
  "shorte.st",
]);

export function isShortenerDomain(domain) {
  const normalized = normalizeDomain(domain);
  return normalized ? SHORTENER_DOMAINS.has(normalized) : false;
}

export function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a) return b.length;
  if (!b) return a.length;

  const matrix = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1));
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost);
    }
  }

  return matrix[a.length][b.length];
}

export function similarityToAnyDomain(domain, officialDomains) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return null;

  let best = null;

  for (const official of officialDomains) {
    const off = normalizeDomain(official);
    if (!off) continue;

    const distance = levenshtein(normalized, off);
    const ratio = distance / Math.max(normalized.length, off.length);

    if (!best || ratio < best.ratio) {
      best = {
        officialDomain: off,
        distance,
        ratio,
        isLikelyTyposquat: ratio < 0.3 && normalized !== off,
      };
    }
  }

  return best;
}

export function isSubdomainOf(domain, base) {
  const d = normalizeDomain(domain);
  const b = normalizeDomain(base);
  if (!d || !b) return false;
  return d === b || d.endsWith(`.${b}`);
}
