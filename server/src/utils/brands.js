import {
  similarityToAnyDomain,
  normalizeDomain,
  levenshtein,
} from "./url-utils.js";

export const BRAND_RULES = [
  {
    id: "amazon",
    displayName: "Amazon",
    officialDomains: [
      "amazon.com",
      "amazon.es",
      "amazon.de",
      "amazon.fr",
      "amazon.it",
      "amazon.co.uk",
    ],
    officialHostnames: ["sellercentral.amazon.com", "pay.amazon.com"],
    suspiciousButSeenInScams: [
      "arnazon-account-check.net",
      "amazon-secure-login.net",
    ],
  },
  {
    id: "google",
    displayName: "Google",
    officialDomains: [
      "google.com",
      "google.pt",
      "gmail.com",
      "googleusercontent.com",
    ],
    officialHostnames: ["accounts.google.com", "myaccount.google.com"],
  },
  {
    id: "paypal",
    displayName: "PayPal",
    officialDomains: ["paypal.com", "paypal.me"],
    officialHostnames: ["www.paypal.com", "checkout.paypal.com"],
  },
  {
    id: "apple",
    displayName: "Apple",
    officialDomains: ["apple.com", "icloud.com", "me.com"],
    officialHostnames: ["appleid.apple.com"],
  },
  {
    id: "microsoft",
    displayName: "Microsoft",
    officialDomains: ["microsoft.com", "live.com", "outlook.com"],
    officialHostnames: ["login.microsoftonline.com"],
  },
  {
    id: "mbway",
    displayName: "MB WAY",
    officialDomains: ["mbway.pt", "sibspay.pt"],
  },
  {
    id: "ctt",
    displayName: "CTT",
    officialDomains: ["ctt.pt"],
  },
  {
    id: "dpd",
    displayName: "DPD",
    officialDomains: ["dpd.com", "dpd.pt", "dpd.de", "dpd.co.uk"],
  },
  {
    id: "gls",
    displayName: "GLS",
    officialDomains: ["gls-group.eu", "gls-spain.es", "gls-italy.com"],
  },
  {
    id: "dhl",
    displayName: "DHL",
    officialDomains: ["dhl.com", "dhl.de"],
    officialHostnames: ["express.dhl.com", "mydhl.express.dhl"],
  },
  {
    id: "ups",
    displayName: "UPS",
    officialDomains: ["ups.com"],
  },
  {
    id: "fedex",
    displayName: "FedEx",
    officialDomains: ["fedex.com"],
  },
  {
    id: "facebook",
    displayName: "Facebook",
    officialDomains: ["facebook.com", "fb.com", "messenger.com"],
  },
  {
    id: "instagram",
    displayName: "Instagram",
    officialDomains: ["instagram.com"],
  },
  {
    id: "netflix",
    displayName: "Netflix",
    officialDomains: ["netflix.com"],
  },
  {
    id: "spotify",
    displayName: "Spotify",
    officialDomains: ["spotify.com"],
  },
  { 
    id: "mbway",
    displayName: "MB WAY",
    officialDomains: ["mbway.pt", "sibspay.pt"],
  }
];

export function findBrandMentions(textLower) {
  const out = [];
  for (const b of BRAND_RULES) {
    const needle = b.displayName.toLowerCase();
    if (textLower.includes(needle) || textLower.includes(b.id)) out.push(b);
  }
  return out;
}

export function inferBrandsFromUrl(hostname, domain) {
  const out = [];
  if (!hostname && !domain) return out;
  const h = hostname ? hostname.toLowerCase() : "";
  const d = domain ? domain.toLowerCase() : "";
  const labels = [
    ...new Set(
      [h, d]
        .flatMap((value) => String(value).split("."))
        .flatMap((part) => part.split("-"))
        .filter(Boolean),
    ),
  ];

  for (const b of BRAND_RULES) {
    const officialDomains = (b.officialDomains || [])
      .map(normalizeDomain)
      .filter(Boolean);
    const officialHostnames = (b.officialHostnames || [])
      .map(normalizeDomain)
      .filter(Boolean);

    if (h.includes(b.id) || d.includes(b.id)) out.push(b);
    if (officialDomains.some((od) => d === od)) out.push(b);
    if (officialHostnames.some((oh) => h === oh || h.endsWith(`.${oh}`)))
      out.push(b);

    const similarity = similarityToAnyDomain(d, officialDomains);
    if (similarity?.isLikelyTyposquat) out.push(b);

    const brandNeedle = b.id.toLowerCase();
    const labelMatch = labels.some((label) => {
      if (label === brandNeedle) return true;
      if (label.length < 5 || brandNeedle.length < 5) return false;
      const ratio =
        levenshtein(label, brandNeedle) /
        Math.max(label.length, brandNeedle.length);
      return ratio <= 0.35;
    });

    if (labelMatch) out.push(b);
  }

  return Array.from(new Map(out.map((b) => [b.id, b])).values());
}

export function matchesOfficial(hostname, domain, official) {
  const h = hostname ? hostname.toLowerCase() : "";
  const d = domain ? domain.toLowerCase() : "";
  const o = official ? official.toLowerCase() : "";

  if (!o) return false;
  if (d === o) return true;
  if (h === o) return true;
  if (h.endsWith(`.${o}`)) return true;
  return false;
}
