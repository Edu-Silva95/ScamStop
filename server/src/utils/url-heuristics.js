import { isSubdomainOf } from "./url-utils.js";

export function scorePhishingPatterns(u, reasons, addScore, { isKnownOfficialUrl, riskyTlds }) {
  if (!u || !u.hostname) return;

  if (u.pathname && /(^|\/)confirm($|\/|\.)/i.test(u.pathname)) {
    addScore(30);
    reasons.push("Confirm/verification page pattern");
  }

  if (u.search && /token=|sessionid=|auth=/i.test(u.search)) {
    addScore(15);
    reasons.push("Auth token in URL");
  }

  if (u.brandMatches && u.brandMatches.length > 0 && !isKnownOfficialUrl(u.hostname, u.domain)) {
    addScore(30);
    reasons.push("Brand name embedded in domain/path");
  }

  if (u.hostname && u.hostname.split(".").length >= 4 && !isSubdomainOf(u.hostname, u.domain)) {
    addScore(10);
    reasons.push("Long subdomain chain (possible redirection/service)");
  }

  const tld = u.hostname?.split(".").pop();
  if (tld && riskyTlds && riskyTlds.has(tld)) {
    addScore(20);
    reasons.push("Risky TLD in use");
  }
}
