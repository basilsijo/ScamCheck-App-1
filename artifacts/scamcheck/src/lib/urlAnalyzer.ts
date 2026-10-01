// ScamCheck — URL Analysis module
//
// Static URL analysis only. No fetching, no scraping, no JavaScript execution.
// To integrate a real URL reputation API later, add a post-processing step
// that merges additional UrlCheck results into the UrlAnalysis — the rest of
// the app won't need to change.

export type CheckStatus = "good" | "warning" | "danger";

export interface UrlCheck {
  id: string;
  label: string;
  status: CheckStatus;
  detail: string;
}

export interface UrlSignal {
  id: string;
  points: number;
}

export interface UrlAnalysis {
  url: string;
  domain: string;
  rootDomain: string;
  checks: UrlCheck[];
  signals: UrlSignal[];
  summary: string;
}

// ---- Configurable data --------------------------------------------------

export const SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "lnkd.in",
];

// Common organizations scammers impersonate, with their known legitimate domains.
// To add more organizations, add entries here — the rest of the app adapts automatically.
export interface OrgEntry {
  displayName: string;
  names: string[];
  domains: string[];
  /** Canonical URL selected from this entry's known legitimate domains. */
  officialUrl?: string;
}

export const ORGANIZATIONS: OrgEntry[] = [
  { displayName: "SBI", names: ["sbi", "state bank of india"], domains: ["sbi.co.in", "onlinesbi.com", "sbicard.com"], officialUrl: "https://www.sbi.co.in/" },
  { displayName: "HDFC", names: ["hdfc", "hdfc bank"], domains: ["hdfcbank.com", "hdfcbank.co.in"], officialUrl: "https://www.hdfcbank.com/" },
  { displayName: "ICICI", names: ["icici", "icici bank"], domains: ["icicibank.com"], officialUrl: "https://www.icicibank.com/" },
  { displayName: "Axis Bank", names: ["axis bank", "axis"], domains: ["axisbank.com"], officialUrl: "https://www.axisbank.com/" },
  { displayName: "Bank", names: ["bank"], domains: ["hsbc.co.uk", "barclays.co.uk", "natwest.com", "lloydsbanking.com", "santander.co.uk", "chase.com", "wellsfargo.com", "citi.com"] },
  { displayName: "PayPal", names: ["paypal"], domains: ["paypal.com"], officialUrl: "https://www.paypal.com/" },
  { displayName: "Amazon", names: ["amazon"], domains: ["amazon.com", "amazon.co.uk", "amazon.in"], officialUrl: "https://www.amazon.in/" },
  { displayName: "Flipkart", names: ["flipkart"], domains: ["flipkart.com"], officialUrl: "https://www.flipkart.com/" },
  { displayName: "Apple", names: ["apple"], domains: ["apple.com"], officialUrl: "https://www.apple.com/" },
  { displayName: "Google", names: ["google"], domains: ["google.com", "gmail.com"], officialUrl: "https://www.google.com/" },
  { displayName: "Microsoft", names: ["microsoft"], domains: ["microsoft.com", "outlook.com", "live.com"], officialUrl: "https://www.microsoft.com/" },
  { displayName: "WhatsApp", names: ["whatsapp"], domains: ["whatsapp.com", "whatsapp.net"], officialUrl: "https://www.whatsapp.com/" },
  { displayName: "Netflix", names: ["netflix"], domains: ["netflix.com"], officialUrl: "https://www.netflix.com/" },
  { displayName: "DHL", names: ["dhl"], domains: ["dhl.com"], officialUrl: "https://www.dhl.com/" },
  { displayName: "FedEx", names: ["fedex"], domains: ["fedex.com"], officialUrl: "https://www.fedex.com/" },
  { displayName: "UPS", names: ["ups"], domains: ["ups.com"], officialUrl: "https://www.ups.com/" },
  { displayName: "India Post", names: ["india post", "indiapost"], domains: ["indiapost.gov.in"], officialUrl: "https://www.indiapost.gov.in/" },
  { displayName: "Royal Mail", names: ["royal mail"], domains: ["royalmail.com"], officialUrl: "https://www.royalmail.com/" },
  { displayName: "USPS", names: ["usps"], domains: ["usps.com"], officialUrl: "https://www.usps.com/" },
  { displayName: "Hermes / Evri", names: ["hermes", "evri"], domains: ["hermesworld.com", "evri.com"], officialUrl: "https://www.evri.com/" },
  { displayName: "IRS", names: ["irs"], domains: ["irs.gov"], officialUrl: "https://www.irs.gov/" },
  { displayName: "HMRC", names: ["hmrc"], domains: ["gov.uk"], officialUrl: "https://www.gov.uk/" },
  { displayName: "Government", names: ["government"], domains: ["gov.uk", "gov.com"], officialUrl: "https://www.gov.uk/" },
  { displayName: "Social Security", names: ["social security"], domains: ["ssa.gov"], officialUrl: "https://www.ssa.gov/" },
  { displayName: "Safaricom", names: ["safaricom"], domains: ["safaricom.co.ke"], officialUrl: "https://www.safaricom.co.ke/" },
  { displayName: "MTN", names: ["mtn"], domains: ["mtn.com"], officialUrl: "https://www.mtn.com/" },
];

export interface VerifiedAlternative {
  organization: string;
  officialUrl?: string;
}

/** Finds organizations using the same local name matching as URL analysis. */
export function getVerifiedAlternatives(messageText: string): VerifiedAlternative[] {
  const matches = findMentionedOrgs(messageText.toLowerCase());
  // The legacy "bank" entry represents many institutions, not a single brand.
  // Avoid turning it into a duplicate alternative when a named bank is present.
  const hasNamedBank = matches.some(({ entry }) => entry.displayName !== "Bank" &&
    ["SBI", "HDFC", "ICICI", "Axis Bank"].includes(entry.displayName));
  const seen = new Set<string>();
  return matches
    .filter(({ entry }) => {
      if (entry.displayName === "Bank" && hasNamedBank) return false;
      if (seen.has(entry.displayName)) return false;
      seen.add(entry.displayName);
      return true;
    })
    .map(({ entry }) => ({ organization: entry.displayName, officialUrl: entry.officialUrl }));
}

const SUSPICIOUS_TLDS = [
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
  ".click", ".country", ".stream", ".bid", ".loan", ".men", ".party",
  ".review", ".trade", ".date", ".download", ".science", ".racing",
  ".accountant", ".cricket", ".faith", ".win",
];

const PHISHING_KEYWORDS = [
  "login", "verify", "verification", "secure", "account", "update",
  "password", "payment", "wallet", "banking", "reward", "prize", "claim",
];

// Lookalike detection: brand name with character substitutions
interface LookalikeDef {
  org: string;
  legit: string;
  pattern: RegExp;
}

const LOOKALIKE_DEFS: LookalikeDef[] = [
  { org: "PayPal", legit: "paypal.com", pattern: /payp[a4]l|paypol|paypa1/i },
  { org: "Amazon", legit: "amazon.com", pattern: /amaz[o0]n|arnazon|amazn/i },
  { org: "Apple", legit: "apple.com", pattern: /app[l1]e|appie/i },
  { org: "Google", legit: "google.com", pattern: /g[o0][o0]gle|g00gle|goog1e/i },
  { org: "Microsoft", legit: "microsoft.com", pattern: /micr[o0]s[o0]ft|microsft/i },
  { org: "Netflix", legit: "netflix.com", pattern: /netfl[i1]x|netfix/i },
  { org: "SBI", legit: "sbi.co.in", pattern: /sb[l1]|s[b8]i/i },
  { org: "WhatsApp", legit: "whatsapp.com", pattern: /whats[a4]pp|whatsapp|whatsa[p]p/i },
  { org: "Flipkart", legit: "flipkart.com", pattern: /fl[i1]pkart|fl[i1]pcart/i },
  { org: "HDFC", legit: "hdfcbank.com", pattern: /hdf[c<]|hd[f]c/i },
  { org: "ICICI", legit: "icicibank.com", pattern: /[i1]c[i1]c[i1]/i },
  { org: "DHL", legit: "dhl.com", pattern: /dh[l1]-|dh1\./i },
  { org: "USPS", legit: "usps.com", pattern: /usp[s5]-|usp1\./i },
  { org: "HMRC", legit: "gov.uk", pattern: /hm-r-c|hmrç/i },
];

// ---- URL extraction -----------------------------------------------------

const FULL_URL_REGEX = /https?:\/\/[^\s<>"')]+/gi;
const BARE_URL_REGEX = /(?:www\.)?[a-z0-9-]+\.[a-z]{2,}(?:\/[^\s<>"')]*)?/gi;

function stripTrailingPunctuation(url: string): string {
  return url.replace(/[.,;:!?)\]}>]+$/g, "");
}

/**
 * Treat scheme and a leading www. as presentation differences, while keeping
 * the hostname, port, path, query, and fragment in the identity. This avoids
 * hiding genuinely different links in the same message.
 */
export function getUrlDeduplicationKey(url: string): string {
  const candidate = /^https?:\/\//i.test(url) ? url : `http://${url}`;
  try {
    const parsed = new URL(candidate);
    const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
    return `${hostname}${parsed.port ? `:${parsed.port}` : ""}${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return url.trim().toLowerCase().replace(/^https?:\/\//i, "").replace(/^www\./i, "");
  }
}

export function extractUrls(text: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>();

  for (const m of text.match(FULL_URL_REGEX) ?? []) {
    const cleaned = stripTrailingPunctuation(m);
    const key = getUrlDeduplicationKey(cleaned);
    if (!seen.has(key)) { seen.add(key); found.push(cleaned); }
  }

  for (const m of text.match(BARE_URL_REGEX) ?? []) {
    const cleaned = stripTrailingPunctuation(m);
    const lower = cleaned.toLowerCase();
    const key = getUrlDeduplicationKey(cleaned);
    if (seen.has(key)) continue;
    const isShortener = SHORTENERS.some((s) => lower.startsWith(s) || lower.includes(s + "/"));
    const isWww = lower.startsWith("www.");
    if (isShortener || isWww) {
      seen.add(key);
      found.push(cleaned.startsWith("http") ? cleaned : `http://${cleaned}`);
    }
  }

  return found;
}

/**
 * Accepts one full URL or bare domain for local analysis. Bare domains are
 * treated as HTTP rather than assuming the user supplied HTTPS.
 */
export function normalizeWebsiteUrlInput(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || /\s/.test(trimmed)) return null;

  const extracted = extractUrls(trimmed);
  if (extracted.length > 1) return null;

  let candidate = extracted[0] ?? trimmed;
  if (!/^https?:\/\//i.test(candidate)) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) return null;
    candidate = `http://${candidate}`;
  }

  try {
    const parsed = new URL(candidate);
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      !parsed.hostname.includes(".") ||
      parsed.username ||
      parsed.password
    ) {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
}

// ---- Domain parsing -----------------------------------------------------

function getDomain(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    const m = url.replace(/^https?:\/\//i, "").match(/[^/]+/);
    return (m ? m[0] : "").replace(/^www\./, "").toLowerCase();
  }
}

const IP_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIpAddress(host: string): boolean {
  const m = host.match(IP_REGEX);
  if (!m) return false;
  return m.slice(1).every((octet) => {
    const n = parseInt(octet, 10);
    return n >= 0 && n <= 255;
  });
}

function getRootDomain(domain: string): string {
  if (isIpAddress(domain)) return domain;
  const parts = domain.split(".");
  if (parts.length <= 2) return domain;

  // Handle common multi-part TLDs (co.uk, co.in, com.au, etc.)
  const twoPartTlds = ["co.uk", "co.in", "co.jp", "co.kr", "co.za", "com.au", "com.br", "com.cn", "com.sg", "com.hk", "org.uk", "ac.uk", "gov.uk", "net.au", "ne.jp", "or.jp", "or.kr"];
  const lastTwo = parts.slice(-2).join(".");
  if (twoPartTlds.includes(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function domainMatchesOrgDomain(domain: string, orgDomain: string): boolean {
  const root = getRootDomain(domain);
  return root === orgDomain || root.endsWith("." + orgDomain);
}

/** True only when `name` appears as a whole word (so "ups" does not match "groups"). */
export function mentionsWholeWord(textLower: string, name: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![a-z0-9])${escaped}(?![a-z0-9])`, "i").test(textLower);
}

function findMentionedOrgs(textLower: string): { entry: OrgEntry; name: string }[] {
  const found: { entry: OrgEntry; name: string }[] = [];
  for (const entry of ORGANIZATIONS) {
    for (const name of entry.names) {
      if (mentionsWholeWord(textLower, name)) {
        found.push({ entry, name });
        break;
      }
    }
  }
  return found;
}

// ---- Main URL analysis --------------------------------------------------

export function analyzeUrl(url: string, messageText: string): UrlAnalysis {
  const domain = getDomain(url);
  const rootDomain = getRootDomain(domain);
  const checks: UrlCheck[] = [];
  const signals: UrlSignal[] = [];

  const lowerUrl = url.toLowerCase();
  const lowerDomain = domain.toLowerCase();
  const messageLower = messageText.toLowerCase();
  const mentionedOrgs = findMentionedOrgs(messageLower);

  // --- Check 1: HTTPS ---
  const usesHttps = lowerUrl.startsWith("https://");
  if (usesHttps) {
    checks.push({
      id: "https",
      label: "HTTPS",
      status: "good",
      detail: "Uses HTTPS — the connection is encrypted. HTTPS does not mean the website is trustworthy, only that the connection is secure.",
    });
  } else {
    checks.push({
      id: "https",
      label: "HTTPS",
      status: "warning",
      detail: "This link does not use HTTPS. This doesn't prove it is a scam, but you should be cautious — the connection is not encrypted.",
    });
    signals.push({ id: "http_link", points: 1 });
  }

  // --- Check 2: Domain structure ---
  if (isIpAddress(lowerDomain)) {
    checks.push({
      id: "domain_structure",
      label: "Domain",
      status: "warning",
      detail: "The link uses an IP address instead of a normal website domain. This can sometimes be suspicious.",
    });
    signals.push({ id: "ip_address_url", points: 2 });
  } else if (SUSPICIOUS_TLDS.some((tld) => lowerDomain.endsWith(tld))) {
    checks.push({
      id: "domain_structure",
      label: "Domain",
      status: "warning",
      detail: `This web address ends in ".${lowerDomain.split(".").slice(-1)[0]}", an extension often associated with suspicious activity.`,
    });
    signals.push({ id: "suspicious_tld", points: 2 });
  } else if (lowerDomain.split(".").length > 3) {
    checks.push({
      id: "domain_structure",
      label: "Domain",
      status: "warning",
      detail: `This domain has many subdomains. The actual registered domain is "${rootDomain}" — the extra parts before it are subdomains that anyone can set up.`,
    });
    signals.push({ id: "excessive_subdomains", points: 2 });
  } else if (/\d{4,}/.test(lowerDomain)) {
    checks.push({
      id: "domain_structure",
      label: "Domain",
      status: "warning",
      detail: "This web address contains many numbers, which is unusual for legitimate websites.",
    });
    signals.push({ id: "numeric_domain", points: 2 });
  } else {
    checks.push({
      id: "domain_structure",
      label: "Domain",
      status: "good",
      detail: "Normal domain structure detected. This does not guarantee the site is safe.",
    });
  }

  // --- Check 3: Shortened URL ---
  const matchedShortener = SHORTENERS.find((s) => lowerDomain === s || lowerDomain.endsWith("." + s));
  if (matchedShortener) {
    checks.push({
      id: "shortened",
      label: "Shortened URL",
      status: "warning",
      detail: `This is a shortened link (${matchedShortener}). It hides its final destination. Verify where it leads before opening it.`,
    });
    signals.push({ id: "shortened_link", points: 2 });
  } else {
    checks.push({
      id: "shortened",
      label: "Shortened URL",
      status: "good",
      detail: "No URL shortening service detected.",
    });
  }

  // --- Check 4: Lookalike domain ---
  let lookalikeOrg: string | null = null;
  for (const def of LOOKALIKE_DEFS) {
    if (def.pattern.test(lowerDomain) && !domainMatchesOrgDomain(lowerDomain, def.legit)) {
      lookalikeOrg = def.org;
      break;
    }
  }
  if (lookalikeOrg) {
    checks.push({
      id: "lookalike",
      label: "Lookalike domain",
      status: "danger",
      detail: `This web address looks like it is pretending to be ${lookalikeOrg}. The domain uses character substitutions or misspellings that resemble the real brand but may not be legitimate.`,
    });
    signals.push({ id: "lookalike_domain", points: 3 });
  } else {
    checks.push({
      id: "lookalike",
      label: "Lookalike domain",
      status: "good",
      detail: "No obvious lookalike domain patterns detected.",
    });
  }

  // --- Check 5: Suspicious URL keywords ---
  const foundKeywords = PHISHING_KEYWORDS.filter((kw) => lowerUrl.includes(kw));
  if (foundKeywords.length >= 3) {
    checks.push({
      id: "url_keywords",
      label: "URL keywords",
      status: "warning",
      detail: `This URL contains several words commonly used in phishing: ${foundKeywords.join(", ")}. These words alone don't confirm a scam, but they add to the concern when combined with other warning signs.`,
    });
    signals.push({ id: "url_keywords", points: 1 });
  } else if (foundKeywords.length > 0) {
    checks.push({
      id: "url_keywords",
      label: "URL keywords",
      status: "good",
      detail: foundKeywords.length === 1
        ? `The URL contains the word "${foundKeywords[0]}", which is common on many legitimate websites too.`
        : `The URL contains "${foundKeywords.join('", "')}" — these words appear on many legitimate websites as well.`,
    });
    // No signal for 1-2 keywords — too common on legitimate sites
  } else {
    checks.push({
      id: "url_keywords",
      label: "URL keywords",
      status: "good",
      detail: "No suspicious keywords detected in the URL.",
    });
  }

  // --- Check 6: URL obfuscation ---
  let obfuscationNote = "";
  const urlPath = lowerUrl.replace(/^https?:\/\//, "");
  const queryStart = urlPath.indexOf("?");
  const queryString = queryStart >= 0 ? urlPath.slice(queryStart) : "";
  const paramCount = (queryString.match(/&/g) ?? []).length + (queryString ? 1 : 0);
  const hasEncoded = /%[0-9a-f]{2}/i.test(queryString);
  const isVeryLong = url.length > 100;

  if (isVeryLong && paramCount > 5) {
    obfuscationNote = "This URL is very long and has many query parameters, which can be used to hide the real destination.";
    checks.push({ id: "obfuscation", label: "URL complexity", status: "warning", detail: obfuscationNote });
    signals.push({ id: "url_obfuscation", points: 1 });
  } else if (hasEncoded && paramCount > 3) {
    obfuscationNote = "This URL contains encoded characters and multiple parameters, which can be used to obfuscate the destination.";
    checks.push({ id: "obfuscation", label: "URL complexity", status: "warning", detail: obfuscationNote });
    signals.push({ id: "url_obfuscation", points: 1 });
  } else if (isVeryLong) {
    obfuscationNote = "This URL is unusually long, which can sometimes be used to hide the real destination.";
    checks.push({ id: "obfuscation", label: "URL complexity", status: "warning", detail: obfuscationNote });
    signals.push({ id: "url_obfuscation", points: 1 });
  } else {
    checks.push({ id: "obfuscation", label: "URL complexity", status: "good", detail: "No obvious URL obfuscation detected." });
  }

  // --- Check 7: Organization/domain mismatch ---
  if (mentionedOrgs.length > 0 && !isIpAddress(lowerDomain)) {
    const matchedOrg = mentionedOrgs.find(({ entry }) =>
      entry.domains.some((d) => domainMatchesOrgDomain(lowerDomain, d))
    );

    if (matchedOrg) {
      checks.push({
        id: "org_mismatch",
        label: "Organization match",
        status: "good",
        detail: `The domain appears to match the organization mentioned in the message (${matchedOrg.name}). This is a good sign, but does not guarantee the message is legitimate.`,
      });
    } else {
      const orgNames = mentionedOrgs.map((o) => o.name);
      const orgLabel = orgNames.length === 1 ? orgNames[0] : orgNames.slice(0, -1).join(", ") + " or " + orgNames[orgNames.length - 1];

      // If the org name appears in the domain itself, we can't confidently
      // call it a mismatch — the domain might be the org's real domain that
      // we simply don't have in our list. Treat as inconclusive (warning, not danger).
      const domainContainsOrgName = mentionedOrgs.some(({ name }) =>
        lowerDomain.includes(name) || lowerDomain.includes(name.replace(/\s+/g, ""))
      );

      if (domainContainsOrgName) {
        checks.push({
          id: "org_mismatch",
          label: "Organization match",
          status: "warning",
          detail: `The message mentions ${orgLabel}, and the domain "${rootDomain}" contains that name. However, we could not verify whether this domain officially belongs to the organization. Verify through an official source before continuing.`,
        });
        signals.push({ id: "org_domain_mismatch", points: 1 });
      } else {
        checks.push({
          id: "org_mismatch",
          label: "Organization match",
          status: "danger",
          detail: `The message mentions ${orgLabel}, but the domain "${rootDomain}" does not appear to match that organization's known domain. This is a significant warning sign.`,
        });
        signals.push({ id: "org_domain_mismatch", points: 4 });
      }
    }
  } else if (mentionedOrgs.length === 0) {
    checks.push({
      id: "org_mismatch",
      label: "Organization match",
      status: "good",
      detail: "No specific organization was mentioned in the message, so there is no domain to compare.",
    });
  }

  // --- Summary ---
  const dangerCount = checks.filter((c) => c.status === "danger").length;
  const warningCount = checks.filter((c) => c.status === "warning").length;

  let summary: string;
  if (dangerCount > 0) {
    summary = "We found several warning signs with this link. Be very cautious and verify through an official source before visiting it.";
  } else if (warningCount > 0) {
    summary = `We found ${warningCount} warning sign${warningCount > 1 ? "s" : ""} with this link. This doesn't confirm it is a scam, but you should be cautious.`;
  } else {
    summary = "No obvious issues were found with this link, but that does not guarantee it is safe. We couldn't verify this link — verify through an official source before continuing.";
  }

  return {
    url,
    domain,
    rootDomain,
    checks,
    signals,
    summary,
  };
}

// ---- Helper exports for the main analyzer -------------------------------

export function getAllUrlSignals(urls: string[], messageText: string): {
  analyses: UrlAnalysis[];
  signals: UrlSignal[];
} {
  const analyses = urls.map((u) => analyzeUrl(u, messageText));
  // Merge signals from all URLs, taking the max points per signal id
  const signalMap = new Map<string, number>();
  for (const a of analyses) {
    for (const s of a.signals) {
      const existing = signalMap.get(s.id);
      if (existing === undefined || s.points > existing) {
        signalMap.set(s.id, s.points);
      }
    }
  }
  const signals = Array.from(signalMap.entries()).map(([id, points]) => ({ id, points }));
  return { analyses, signals };
}

/** Resolve alternatives from the URL host, including recognized lookalikes. */
export function getVerifiedAlternativesForUrl(url: string): VerifiedAlternative[] {
  const domain = getDomain(url);
  if (!domain) return [];

  const directMatches = getVerifiedAlternatives(domain);
  if (directMatches.some((entry) => entry.officialUrl)) return directMatches;

  const lookalike = LOOKALIKE_DEFS.find(
    (entry) => entry.pattern.test(domain) && !domainMatchesOrgDomain(domain, entry.legit),
  );
  if (!lookalike) return directMatches;

  const organization = ORGANIZATIONS.find(
    (entry) => entry.displayName.toLowerCase() === lookalike.org.toLowerCase(),
  );
  if (!organization?.officialUrl) return directMatches;
  return [{ organization: organization.displayName, officialUrl: organization.officialUrl }];
}
