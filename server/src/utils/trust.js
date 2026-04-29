import { normalizeDomain, isSubdomainOf } from "./url-utils.js";

const TRUSTED_ROOT_DOMAINS = new Set([
  "google.com",
  "gmail.com",
  "apple.com",
  "microsoft.com",
  "paypal.com",
  "amazon.com",
  "facebook.com",
  "twitter.com",
  "linkedin.com",
  "github.com",
]);

export function isTrustedRootDomain(domain) {
  const d = normalizeDomain(domain);
  if (!d) return false;
  if (TRUSTED_ROOT_DOMAINS.has(d)) return true;
  return false;
}

export function isBrandInjectedIntoFakeDomain(hostname, domain) {
  if (!hostname || !domain) return null;
  const h = normalizeDomain(hostname);
  const d = normalizeDomain(domain);
  if (!h || !d) return null;

  // If hostname contains known brand as subdomain but the registrable domain is not the brand
  for (const brand of ["amazon", "paypal", "google", "apple"]) {
    if (h.includes(brand) && !d.endsWith(`${brand}.com`)) return brand;
  }

  return null;
}
