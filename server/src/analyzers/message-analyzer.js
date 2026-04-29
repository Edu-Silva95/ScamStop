import {
  extractUrls,
  getHostname,
  getDomain,
  isShortenerDomain,
  normalizeDomain,
  similarityToAnyDomain,
} from "../utils/url-utils.js";

import {
  BRAND_RULES,
  findBrandMentions,
  inferBrandsFromUrl,
  matchesOfficial,
} from "../utils/brands.js";

import {
  isBrandInjectedIntoFakeDomain,
  isTrustedRootDomain,
} from "../utils/trust.js";

import {
  getUrlPathname,
  getUrlSearch,
  parseUrlSafely,
} from "../utils/url-parsing.js";

import { scorePhishingPatterns } from "../utils/url-heuristics.js";

const RISKY_TLDS = new Set([
  "top",
  "xyz",
  "click",
  "work",
  "shop",
  "info",
  "buzz",
  "cfd",
]);

function enforceMinimumScore(score, urlDetails) {
  let adjusted = score;

  for (const u of urlDetails) {
    if (u.verdict === "lookalike") adjusted = Math.max(adjusted, 60);
    if (u.verdict === "impersonation") adjusted = Math.max(adjusted, 75);
    if (u.verdict === "shortener") adjusted = Math.max(adjusted, 50);
    if (u.verdict === "suspicious") adjusted = Math.max(adjusted, 40);
  }

  return adjusted;
}

function isKnownOfficialUrl(hostname, domain) {
  if (isTrustedRootDomain(domain)) return true;

  for (const brand of BRAND_RULES) {
    const official = [
      ...(brand.officialDomains || []),
      ...(brand.regionalDomains || []),
      ...(brand.officialHostnames || []),
    ];

    if (official.some((o) => matchesOfficial(hostname, domain, o))) return true;
  }

  return false;
}

export function analyzeMessage(message) {
  const safeMessage = typeof message === "string" ? message : "";

  const urls = extractUrls(safeMessage);
  const hostnames = urls.map(getHostname);
  const domains = urls.map(getDomain);

  let score = 0;
  const reasons = [];

  const lower = safeMessage.toLowerCase();
  const brandsMentionedInText = new Set(
    findBrandMentions(lower).map((b) => b.id),
  );
  let brandMentions = findBrandMentions(lower);

  const PAYMENT_REGEX = /(?:\b(pay|fee|eur|payment|invoice)\b|€)/;
  const SCAM_CONTEXT =
    /(payment|fee|customs|tax|delivery fee|re-delivery|pending|invoice|pagar|pagamento|multa|penhora)/;

  const urlDetails = urls.map((url, idx) => {
    const hostname = hostnames[idx];
    const domain = domains[idx];

    const parsed = parseUrlSafely(url);
    const hasUserInfo = !!(parsed && (parsed.username || parsed.password));
    const usesPunycode =
      (typeof hostname === "string" && hostname.includes("xn--")) ||
      (typeof domain === "string" && domain.includes("xn--"));

    const pathname = getUrlPathname(url);
    const search = getUrlSearch(url);

    const isShortener =
      isShortenerDomain(hostname) || isShortenerDomain(domain);

    return {
      url,
      hostname,
      domain,
      isShortener,
      hasUserInfo,
      usesPunycode,
      pathname,
      search,
      brandMatches: [],
      verdict: "unknown",
      notes: [],
    };
  });

  for (const u of urlDetails) {
    if (isTrustedRootDomain(u.domain)) {
      u.notes.push("Trusted root domain");
      if (u.verdict === "unknown") u.verdict = "official";
    }
  }

  for (const u of urlDetails) {
    if (!u.hostname || !u.domain) continue;
    if (isTrustedRootDomain(u.domain)) continue;

    const injectedBrand = isBrandInjectedIntoFakeDomain(u.hostname, u.domain);
    if (injectedBrand) {
      score = Math.max(score, 85);
      score += 20;
      reasons.push("Brand injected into fake domain");
      u.verdict = "impersonation";
      u.notes.push(`Injected brand: ${injectedBrand}`);
    }
  }

  for (const u of urlDetails) {
    if (u.hasUserInfo) {
      score += 40;
      reasons.push("URL contains userinfo (possible hostname masking)");
      u.notes.push(
        "Contains userinfo (text before '@' is not the real hostname)",
      );
      if (u.verdict === "unknown") u.verdict = "suspicious";
    }

    if (u.usesPunycode) {
      score += 20;
      reasons.push("Punycode/IDN domain used");
      u.notes.push("Hostname contains 'xn--' (possible homograph/IDN abuse)");
      if (u.verdict === "unknown") u.verdict = "suspicious";
    }
  }

  for (const u of urlDetails) {
    const inferred = inferBrandsFromUrl(u.hostname, u.domain);
    for (const b of inferred) {
      if (!u.brandMatches.includes(b.id)) u.brandMatches.push(b.id);
      if (!brandMentions.some((x) => x.id === b.id)) brandMentions.push(b);
    }
  }

  const addScore = (n) => {
    if (Number.isFinite(n)) score += n;
  };

  for (const u of urlDetails) {
    scorePhishingPatterns(u, reasons, addScore, {
      isKnownOfficialUrl,
      riskyTlds: RISKY_TLDS,
    });
  }

  if (urls.length === 0 && PAYMENT_REGEX.test(lower)) {
    score += 10;
    reasons.push("Payment wording without links");
  }

  if (
    urls.length > 0 &&
    (PAYMENT_REGEX.test(lower) || SCAM_CONTEXT.test(lower))
  ) {
    score += 40;
    reasons.push("Scam/payment context with link");
  }

  for (const u of urlDetails) {
    if (u.isShortener) {
      u.verdict = "shortener";
      score += 25;
      reasons.push("Shortened link detected");
    }
  }

  for (const brand of brandMentions) {
    const mentionedInText = brandsMentionedInText.has(brand.id);
    const official = [
      ...(brand.officialDomains || []),
      ...(brand.regionalDomains || []),
      ...(brand.officialHostnames || []),
    ].map(normalizeDomain);

    const suspiciousExtras = (brand.suspiciousButSeenInScams || []).map(
      normalizeDomain,
    );

    const hasOfficial = urlDetails.some((u) =>
      official.some((o) => matchesOfficial(u.hostname, u.domain, o)),
    );

    const hasBrandInUrl = urlDetails.some(
      (u) => u.verdict !== "official" && u.brandMatches?.includes(brand.id),
    );

    if (!hasOfficial && hasBrandInUrl) {
      score += 40;
      reasons.push(`${brand.displayName} referenced in non-official domain`);
    }

    if (!hasOfficial && urls.length > 0) {
      score += 50;
      reasons.push(`${brand.displayName} impersonation detected`);

      for (const u of urlDetails) {
        if (u.verdict === "official") continue;
        if (mentionedInText || u.brandMatches?.includes(brand.id)) {
          u.verdict = "impersonation";
        }
      }
    }

    for (const u of urlDetails) {
      if (!u.domain) continue;

      const best = similarityToAnyDomain(u.domain, official);

      if (best) {
        if (best.isLikelyTyposquat) {
          u.verdict = "lookalike";
          score += 35;
          reasons.push(`${brand.displayName} lookalike detected`);
        } else if (best.ratio <= 0.45 && u.domain !== best.officialDomain) {
          u.verdict = "suspicious";
          score += 20;
        }
      }

      if (suspiciousExtras.includes(u.domain)) {
        u.verdict = "impersonation";
        score += 45;
      }
    }
  }

  for (const u of urlDetails) {
    const tld = u.hostname?.split(".").pop();
    if (tld && RISKY_TLDS.has(tld)) {
      score += 20;
      reasons.push("Risky TLD used");

      if (u.verdict === "unknown" && !isTrustedRootDomain(u.domain)) {
        u.verdict = "suspicious";
      }
    }
  }

  for (const u of urlDetails) {
    if (u.verdict === "unknown" && u.domain && !isTrustedRootDomain(u.domain)) {
      u.verdict = "unverified";
      u.notes.push("Untrusted / unknown domain");
    }
  }

  score = enforceMinimumScore(score, urlDetails);

  const hasOnlyOfficialPayPal =
    brandMentions.some((b) => b.id === "paypal") &&
    urlDetails.length > 0 &&
    urlDetails.every((u) => u.verdict === "official");

  const hasNoScamSignals = reasons.length === 0 || score <= 10;

  if (hasOnlyOfficialPayPal && hasNoScamSignals) {
    score = 0;
  }

  const hasLinks = urlDetails.length > 0;
  const allLinksOfficial =
    hasLinks && urlDetails.every((u) => u.verdict === "official");

  const status =
    score >= 80
      ? "malicious"
      : score >= 40
        ? "suspicious"
        : hasLinks
          ? allLinksOfficial
            ? "safe"
            : "neutral"
          : "safe";

  return {
    status,
    score,
    reasons: Array.from(new Set(reasons)),
    urls: urlDetails,
    brandMentions,
  };
}
