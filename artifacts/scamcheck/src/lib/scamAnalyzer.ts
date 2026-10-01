// ScamCheck — context-aware weighted scam detection engine
//
// Design principles:
//  - Fewer false positives > more aggressive detection
//  - Single weak signals never produce High Risk
//  - Combinations of signals amplify the score
//  - Each signal belongs to a category for clear reporting
//  - URL analysis is delegated to urlAnalyzer.ts for modularity
//
// To add a new text detector: add a TEXT_SIGNALS entry, and optionally a
// COMBINATIONS entry. To add a new URL detector, add it in urlAnalyzer.ts.
// To integrate an AI API later, add a post-processing step that merges
// additional signals into the same AnalysisResult — the UI won't change.

import {
  extractUrls,
  getAllUrlSignals,
  mentionsWholeWord,
  ORGANIZATIONS,
  type UrlAnalysis,
  type UrlSignal,
} from "./urlAnalyzer";

export type RiskLevel = "low" | "suspicious" | "high";

export type SignalCategory =
  | "urgency"
  | "sensitive"
  | "money"
  | "prize"
  | "link"
  | "threat";

export interface Signal {
  id: string;
  category: SignalCategory;
  icon: string;
  label: string;
  detail?: string;
  points: number;
}

export interface CategoryScore {
  category: SignalCategory;
  label: string;
  icon: string;
  level: "none" | "low" | "medium" | "high";
  points: number;
  signals: Signal[];
}

export interface Combination {
  id: string;
  label: string;
  bonus: number;
}

export interface AdviceItem {
  id: string;
  text: string;
}

export interface AnalysisResult {
  riskLevel: RiskLevel;
  totalScore: number;
  signals: Signal[];
  categories: CategoryScore[];
  combinations: Combination[];
  explanation: string;
  advice: AdviceItem[];
  linkAnalyses: UrlAnalysis[];
  disclaimer: string;
  rawText: string;
}

// ---- Organization helpers (re-exported from urlAnalyzer) ----------------

function findMentionedOrgNames(textLower: string): string[] {
  const found: string[] = [];
  for (const entry of ORGANIZATIONS) {
    for (const name of entry.names) {
      if (mentionsWholeWord(textLower, name)) {
        if (!found.includes(name)) found.push(name);
        break;
      }
    }
  }
  return found;
}

// ---- Signal definitions -------------------------------------------------

interface SignalDef {
  id: string;
  category: SignalCategory;
  icon: string;
  label: string;
  detail?: string;
  points: number;
  test: (ctx: AnalysisContext) => boolean;
  advice?: string;
}

interface AnalysisContext {
  text: string;
  lower: string;
  urls: string[];
  hasUrl: boolean;
  mentionedOrgs: string[];
}

// Helpers for the sensitive-information check
const SENSITIVE_WORDS = /\b(otp|one.?time.?password|password|pin\b|cvv|cvc|card number|sort code|banking details|login details|security code|passcode|secret code|verification code|full card details)\b/i;
const SAFETY_WARNING = /\b(do not|don'?t|never|not to|please do not|kindly do not)\s+(share|disclose|give|tell|reveal|provide|forward)\b[^.!?\n]{0,60}/gi;
const OTP_DELIVERY = /(\b\d{4,8}\b[^.!?\n]{0,30}\b(otp|verification code|security code|login code)\b|\b(otp|verification code|security code|login code)\b[^.!?\n]{0,30}\b\d{4,8}\b)/i;
const ASKS_FOR_CODE = /\b(send|share|reply|forward|tell|provide|give|submit|confirm|text)\b[^.!?\n]{0,40}\b(otp|pin|password|cvv|code)\b/i;
const MONEY_AMOUNT = /(₹|\brs\.?|\binr\b|\$|\busd\b)\s*\d|\b\d[\d,]{3,}\b/i;

const TEXT_SIGNALS: SignalDef[] = [
  // --- Urgency ---
  {
    id: "urgency_weak",
    category: "urgency",
    icon: "⏰",
    label: "Mentions a time pressure word",
    detail: "Contains words like 'today', 'now', or 'important'.",
    points: 1,
    test: (c) => /\b(today|now|important)\b/i.test(c.lower),
  },
  {
    id: "urgency_medium",
    category: "urgency",
    icon: "⏰",
    label: "Creates strong urgency",
    detail: "Pushes you to act fast — 'act now', 'immediately', 'within 24 hours'.",
    points: 2,
    test: (c) => /\b(act now|urgent|urgently|immediately|right away|without delay|within 24 hours|within 24hrs|final (notice|warning|reminder)|last chance|don'?t delay|hurry|limited time|expires (today|soon)|today only|before it'?s too late)\b/i.test(c.lower),
  },

  // --- Sensitive information ---
  {
    id: "sensitive_info",
    category: "sensitive",
    icon: "🔐",
    label: "Requests sensitive information",
    detail: "Asks for OTP, password, PIN, CVV, or banking details.",
    points: 5,
    test: (c) => {
      // Safety warnings like "Do not share this OTP with anyone" are not a request.
      const withoutWarnings = c.lower.replace(SAFETY_WARNING, " ");
      if (!SENSITIVE_WORDS.test(withoutWarnings)) return false;
      // A normal OTP message ("123456 is your OTP") with no link and no request is fine.
      if (!c.hasUrl && OTP_DELIVERY.test(withoutWarnings) && !ASKS_FOR_CODE.test(withoutWarnings)) return false;
      return true;
    },
    advice: "Never share OTPs, passwords, PINs, or card codes. No real organization will ask for these in a message.",
  },

  // --- Money ---
  {
    id: "money_request",
    category: "money",
    icon: "💰",
    label: "Asks for money or a fee",
    detail: "Wants you to pay a fee, transfer money, or send funds.",
    points: 3,
    test: (c) => /\b(processing fee|release fee|clearance fee|registration fee|tax fee|customs fee|admin fee|wire (money|transfer)|transfer (money|funds)|send (money|funds|cash) to|western union|moneygram|bitcoin|crypto|gift ?cards?|vouchers?|pay (a )?fee|pay to (claim|receive|release)|deposit (required|needed|fee))\b/i.test(c.lower),
    advice: "Don't send money or buy gift cards in response to an unexpected message.",
  },

  // --- Prize / reward ---
  {
    id: "prize_weak",
    category: "prize",
    icon: "🎁",
    label: "Mentions congratulations or a reward",
    detail: "Uses congratulatory language.",
    points: 1,
    test: (c) => /\bcongratulations\b/i.test(c.lower),
  },
  {
    id: "prize_medium",
    category: "prize",
    icon: "🎁",
    label: "Prize, lottery, or winnings claim",
    detail: "Claims you won a prize, lottery, or reward.",
    points: 2,
    test: (c) => /\b(you'?ve? won|you have won|winner|prize|lottery|lotto|raffle|sweepstake|jackpot|claim your (prize|reward|winnings)|you have been (selected|chosen))\b/i.test(c.lower),
    advice: "If you didn't enter a competition, you didn't win. Don't pay to claim a prize.",
  },

  // --- Threat / impersonation ---
  {
    id: "threat",
    category: "threat",
    icon: "🏦",
    label: "Threatens account or legal consequences",
    detail: "Warns of account suspension, legal action, or arrest.",
    points: 3,
    test: (c) => /\b(account (will be )?(blocked|suspend(ed)?|closed|terminat(ed)?|locked)|legal action|arrest|lawsuit|deport|prosecut|penalt(y|ies)|cut off|disconnect(ed|ion)?|shut down|(unpaid|pending|overdue) (electricity |water |gas |phone |mobile )?bill|bill (is |has been )?(pending|unpaid|overdue)|permanently closed|service (will be )?(interrupt(ed)?|disrupt(ed)?|suspend(ed)?)|overdue|avoid (service )?interruption)\b/i.test(c.lower),
    advice: "Legitimate organizations do not threaten you over a message. Contact them directly to verify.",
  },
  {
    id: "verify_kyc",
    category: "threat",
    icon: "📋",
    label: "Account verification or KYC request",
    detail: "Asks you to 'verify' or 'update' your account or KYC.",
    points: 2,
    test: (c) => /\b(verify (your )?account|kyc (update|required|pending)|update (your )?(account|details|info)|confirm (your )?(identity|account)|re-?verify|account (verification|update) (required|needed|pending))\b/i.test(c.lower),
    advice: "Don't verify your account through a link in a message. Log in directly via the official app or website.",
  },
  {
    id: "authority_request",
    category: "threat",
    icon: "🎭",
    label: "Pretends to be someone you trust",
    detail: "Claims to be your boss or a family member on a new number and asks for a favour or money.",
    points: 3,
    test: (c) => {
      const claimsRole = /\b(it'?s|this is|i am|i'?m)\s+(your\s+)?(boss|ceo|manager|principal|director|md|chairman)\b|\b(new number|changed my number|lost my phone)\b/i.test(c.lower);
      const asks = /\b(gift ?cards?|vouchers?|transfer|pay|send|buy|recharge|urgent(ly)?|quick favou?r|paytm|gpay|phonepe|upi)\b/i.test(c.lower);
      return claimsRole && asks;
    },
    advice: "Call the person on the number you already have before sending anything. Scammers copy bosses and relatives.",
  },
  {
    id: "easy_money_job",
    category: "money",
    icon: "💼",
    label: "Offers easy money for simple work",
    detail: "Promises daily pay for work-from-home, liking videos, or simple online tasks.",
    points: 4,
    test: (c) => {
      const earnClaim = /\b(earn|earning|income)\b[^.!?\n]{0,60}\b(daily|per day|a day|every day|weekly|per week|a week|monthly|per month|a month|per hour)\b/i.test(c.lower) && MONEY_AMOUNT.test(c.lower);
      const taskJob = /\b(like|follow|subscribe|rate|review)\b[^.!?\n]{0,40}\b(videos?|reels?|posts?|channels?|products?|hotels?|restaurants?|apps?)\b[^.!?\n]{0,80}\b(earn|paid|get paid|income|per task|commission)\b/i.test(c.lower);
      const homeJob = /\b(work from home|work-from-home|part[- ]?time job|online job|home[- ]?based job)\b/i.test(c.lower) && MONEY_AMOUNT.test(c.lower) && /\b(earn|salary|income|daily|weekly|per day|per week)\b/i.test(c.lower);
      return earnClaim || taskJob || homeJob;
    },
    advice: "Real jobs don't pay you daily for liking videos or ask you to chat on Telegram. Never pay a 'registration fee' to get work.",
  },
  {
    id: "delivery_problem",
    category: "threat",
    icon: "📦",
    label: "Claims a delivery problem and gives a link",
    detail: "Says a parcel is held or the address is incomplete and sends you to a link.",
    points: 2,
    test: (c) =>
      c.hasUrl &&
      /\b(parcel|package|shipment|courier|delivery)\b[^.!?\n]{0,80}\b(held|on hold|stuck|returned|undelivered|could not be delivered|not delivered|failed|incomplete address|address (is )?(incomplete|invalid|missing)|customs|unable to deliver)\b/i.test(c.lower),
    advice: "Track parcels only on the courier's official website or app, not through a link in a message.",
  },
  {
    id: "callback_number",
    category: "threat",
    icon: "📞",
    label: "Asks you to call a number in the message",
    detail: "Gives a phone number to call or message instead of an official channel.",
    points: 2,
    test: (c) => /\b(call|contact|whatsapp|dial)\b[^.!?\n]{0,25}(\+?\d[\d\s-]{8,13}\d)/i.test(c.lower),
    advice: "Don't call numbers from a message. Look up the official number on the company's website or your card.",
  },
  {
    id: "generic_greeting",
    category: "threat",
    icon: "👤",
    label: "Uses a vague greeting",
    detail: "Starts with 'Dear Customer' instead of your name.",
    points: 1,
    test: (c) => /\b(dear (customer|user|sir|madam|valued customer|member)|hello (customer|user))\b/i.test(c.lower),
  },
  {
    id: "impersonation",
    category: "threat",
    icon: "🏢",
    label: "Impersonates an organization",
    detail: "Claims to be a bank, delivery service, or government body.",
    points: 2,
    test: (c) => {
      if (c.mentionedOrgs.length === 0) return false;
      return c.hasUrl ||
        /\b(account (will be )?(blocked|suspend|closed|locked)|legal action|arrest|verify (your )?account|kyc|otp|password|pin\b|cvv|processing fee|transfer (money|funds)|send (money|funds) to|pay (a )?fee|click (here|this|below|the link)|claim (here|your (prize|reward)))\b/i.test(c.lower);
    },
    advice: "Verify the request using the organization's official website, app, or phone number — not the contact info in the message.",
  },

  // --- Link (text-based) ---
  {
    id: "click_link",
    category: "link",
    icon: "🔗",
    label: "Asks you to click a link",
    detail: "Directs you to click, tap, or visit a link.",
    points: 1,
    test: (c) => {
      if (!c.hasUrl) {
        return /\b(click (here|this link|below|the link)|tap (here|this link))\b/i.test(c.lower);
      }
      return /\b(click|tap|claim (here|now)|visit (this|the|our) (link|site|website)|follow (this|the) link|go to (this|the) link)\b/i.test(c.lower);
    },
    advice: "Don't click links in unexpected messages. Go to the organization's official website directly.",
  },
];

// ---- URL signal → Signal mapping ----------------------------------------
//
// The urlAnalyzer produces raw signals (id + points). Here we map them to
// the Signal type with category, icon, label, and detail for the UI/scoring.

const URL_SIGNAL_META: Record<string, {
  category: SignalCategory;
  icon: string;
  label: string;
  detail?: string;
  advice?: string;
}> = {
  http_link: {
    category: "link",
    icon: "🔓",
    label: "Link uses HTTP instead of HTTPS",
    detail: "The connection is not encrypted.",
    advice: "Be cautious of links that don't use HTTPS — the connection is not encrypted.",
  },
  shortened_link: {
    category: "link",
    icon: "🔗",
    label: "Contains a shortened link",
    detail: "Short links hide the real destination.",
    advice: "Don't click shortened links from unknown sources — they can hide the real destination.",
  },
  ip_address_url: {
    category: "link",
    icon: "🌐",
    label: "Link uses an IP address instead of a domain",
    detail: "The link uses a raw IP address rather than a normal website name.",
    advice: "Be cautious of links that use IP addresses instead of normal domain names.",
  },
  suspicious_tld: {
    category: "link",
    icon: "🌐",
    label: "Suspicious domain extension",
    detail: "The web address ends in an unusual extension often used in scams.",
    advice: "Be cautious of links with unusual domain extensions. Verify through an official source.",
  },
  excessive_subdomains: {
    category: "link",
    icon: "🌐",
    label: "Suspicious domain structure",
    detail: "The domain has many subdomains. The extra parts before the root domain can be set up by anyone.",
    advice: "Check the web address carefully — the root domain is what matters, not the subdomains.",
  },
  numeric_domain: {
    category: "link",
    icon: "🌐",
    label: "Domain contains many numbers",
    detail: "This web address contains many numbers, which is unusual for legitimate sites.",
    advice: "Be cautious of links with domains that contain many numbers.",
  },
  lookalike_domain: {
    category: "link",
    icon: "🔍",
    label: "Possible lookalike domain",
    detail: "The domain uses character substitutions that resemble a real brand.",
    advice: "Check the web address very carefully — it may be pretending to be a well-known brand.",
  },
  url_keywords: {
    category: "link",
    icon: "🔑",
    label: "URL contains multiple phishing-related keywords",
    detail: "The URL contains several words commonly used in phishing.",
  },
  url_obfuscation: {
    category: "link",
    icon: "🔗",
    label: "URL is unusually complex or obfuscated",
    detail: "The URL is very long or contains many encoded parameters.",
    advice: "Be cautious of very long or complex URLs — they can hide the real destination.",
  },
  org_domain_mismatch: {
    category: "link",
    icon: "🔀",
    label: "Domain does not appear to match the organization",
    detail: "The web address doesn't belong to the organization mentioned in the message.",
    advice: "The domain does not appear to match the organization mentioned in the message. Verify through the official website or app.",
  },
};

function urlSignalsToSignals(urlSignals: UrlSignal[]): Signal[] {
  const result: Signal[] = [];
  for (const us of urlSignals) {
    const meta = URL_SIGNAL_META[us.id];
    if (!meta) continue;
    result.push({
      id: us.id,
      category: meta.category,
      icon: meta.icon,
      label: meta.label,
      detail: meta.detail,
      points: us.points,
    });
  }
  return result;
}

// ---- Combination rules --------------------------------------------------

interface CombinationDef {
  id: string;
  label: string;
  bonus: number;
  test: (signalIds: Set<string>) => boolean;
}

const URL_LINK_SIGNALS = new Set([
  "click_link", "shortened_link", "http_link", "ip_address_url",
  "suspicious_tld", "excessive_subdomains", "numeric_domain",
  "lookalike_domain", "url_keywords", "url_obfuscation", "org_domain_mismatch",
]);

const SUSPICIOUS_URL_SIGNALS = new Set([
  "shortened_link", "ip_address_url", "suspicious_tld", "excessive_subdomains",
  "numeric_domain", "lookalike_domain", "url_obfuscation", "org_domain_mismatch",
]);

const ANY_LINK_SIGNAL = (s: Set<string>) =>
  Array.from(URL_LINK_SIGNALS).some((id) => s.has(id));

const ANY_SUSPICIOUS_URL = (s: Set<string>) =>
  Array.from(SUSPICIOUS_URL_SIGNALS).some((id) => s.has(id));

const COMBINATIONS: CombinationDef[] = [
  {
    id: "urgency_plus_sensitive",
    label: "Urgency combined with a request for sensitive information is a classic phishing pattern.",
    bonus: 3,
    test: (s) => (s.has("urgency_weak") || s.has("urgency_medium")) && s.has("sensitive_info"),
  },
  {
    id: "threat_plus_link",
    label: "The message threatens consequences and directs you to a link — a common intimidation tactic.",
    bonus: 3,
    test: (s) => s.has("threat") && ANY_LINK_SIGNAL(s),
  },
  {
    id: "impersonation_plus_suspicious_url",
    label: "The message claims to be from a known organization, but the web address doesn't match — a common impersonation tactic.",
    bonus: 3,
    test: (s) => s.has("impersonation") && (ANY_SUSPICIOUS_URL(s) || s.has("org_domain_mismatch")),
  },
  {
    id: "prize_plus_money",
    label: "The message says you've won a prize but asks you to pay a fee first — this is a classic advance-fee scam.",
    bonus: 5,
    test: (s) => (s.has("prize_weak") || s.has("prize_medium")) && s.has("money_request"),
  },
  {
    id: "threat_plus_verify",
    label: "The message threatens your account and asks you to verify your identity — real organizations don't combine threats with verification requests.",
    bonus: 2,
    test: (s) => s.has("threat") && s.has("verify_kyc"),
  },
  {
    id: "money_plus_suspicious_link",
    label: "The message asks for payment and contains a suspicious link — be very careful before paying or clicking.",
    bonus: 3,
    test: (s) => s.has("money_request") && ANY_SUSPICIOUS_URL(s),
  },
  {
    id: "urgency_plus_threat",
    label: "The message combines urgency with threats — designed to make you panic and act without thinking.",
    bonus: 2,
    test: (s) => (s.has("urgency_weak") || s.has("urgency_medium")) && s.has("threat"),
  },
  {
    id: "sensitive_plus_link",
    label: "The message asks for sensitive information and includes a link — this combination is commonly associated with phishing attempts.",
    bonus: 2,
    test: (s) => s.has("sensitive_info") && ANY_LINK_SIGNAL(s),
  },
  {
    id: "verify_plus_link",
    label: "The message asks you to verify your account through a link — log in through the official app or website instead.",
    bonus: 2,
    test: (s) => s.has("verify_kyc") && ANY_LINK_SIGNAL(s),
  },
  {
    id: "sensitive_plus_suspicious_url",
    label: "The message asks for sensitive information like passwords or OTPs and contains a suspicious link — this is a strong phishing indicator.",
    bonus: 4,
    test: (s) => s.has("sensitive_info") && ANY_SUSPICIOUS_URL(s),
  },
  {
    id: "threat_plus_suspicious_url",
    label: "The message threatens your account and contains a suspicious link — this is a strong phishing indicator.",
    bonus: 4,
    test: (s) => s.has("threat") && ANY_SUSPICIOUS_URL(s),
  },
  {
    id: "authority_plus_money",
    label: "Someone claiming to be your boss or a relative is asking for gift cards or money — a very common scam.",
    bonus: 3,
    test: (s) => s.has("authority_request") && s.has("money_request"),
  },
  {
    id: "delivery_plus_suspicious_url",
    label: "A delivery problem message with a suspicious link — a common parcel scam.",
    bonus: 3,
    test: (s) => s.has("delivery_problem") && ANY_SUSPICIOUS_URL(s),
  },
  {
    id: "threat_plus_callback",
    label: "The message threatens you and asks you to call a number — a common bill and bank scam.",
    bonus: 2,
    test: (s) => s.has("threat") && s.has("callback_number"),
  },
  {
    id: "org_mismatch_plus_sensitive",
    label: "The message claims to be from an organization and asks for sensitive information, but the link doesn't match that organization — this is a very dangerous combination.",
    bonus: 4,
    test: (s) => s.has("org_domain_mismatch") && s.has("sensitive_info"),
  },
];

// ---- Category metadata --------------------------------------------------

const CATEGORY_META: Record<SignalCategory, { label: string; icon: string }> = {
  urgency: { label: "Urgency", icon: "⏰" },
  sensitive: { label: "Sensitive information", icon: "🔐" },
  money: { label: "Money", icon: "💰" },
  prize: { label: "Prize / reward", icon: "🎁" },
  link: { label: "Link risk", icon: "🔗" },
  threat: { label: "Threat / impersonation", icon: "🏦" },
};

function categoryLevel(points: number): "none" | "low" | "medium" | "high" {
  if (points === 0) return "none";
  if (points <= 2) return "low";
  if (points <= 5) return "medium";
  return "high";
}

// ---- Explanation generation ---------------------------------------------

function generateExplanation(
  signals: Signal[],
  combinations: Combination[],
  riskLevel: RiskLevel
): string {
  if (riskLevel === "low" && signals.length === 0) {
    return "No significant warning signs were detected. Always stay cautious with unexpected messages, but this message looks normal.";
  }

  if (riskLevel === "low") {
    const labels = signals.map((s) => s.label.toLowerCase());
    return `This message contains a minor signal (${labels.join(", ")}), but nothing that strongly suggests a scam. It is likely safe, but always use your judgement.`;
  }

  if (combinations.length > 0) {
    const top = combinations.slice(0, 2);
    if (top.length === 1) return top[0].label;
    return top.map((c) => c.label).join(" ");
  }

  const sorted = [...signals].sort((a, b) => b.points - a.points);
  const top = sorted.slice(0, 2);

  if (top.length === 1) {
    return `The message ${describeSignal(top[0])}. While this alone doesn't confirm a scam, be cautious and verify before acting.`;
  }

  return `The message ${describeSignal(top[0])} and also ${describeSignal(top[1])}. These signs together suggest you should be cautious.`;
}

function describeSignal(s: Signal): string {
  switch (s.id) {
    case "urgency_weak": return "mentions a time pressure word like 'today' or 'now'";
    case "urgency_medium": return "creates a strong sense of urgency, pushing you to act fast";
    case "sensitive_info": return "requests sensitive information like passwords, OTPs, or card details";
    case "money_request": return "asks you to send money or pay a fee";
    case "prize_weak": return "uses congratulatory language";
    case "prize_medium": return "claims you have won a prize or lottery";
    case "threat": return "threatens consequences like account suspension or legal action";
    case "verify_kyc": return "asks you to verify your account or identity";
    case "generic_greeting": return "uses a vague greeting like 'Dear Customer' instead of your name";
    case "impersonation": return "claims to be from a bank, delivery service, or government organization";
    case "authority_request": return "pretends to be your boss or a relative and asks for money or gift cards";
    case "easy_money_job": return "offers easy daily money for simple online work";
    case "delivery_problem": return "claims a delivery problem and sends you to a link";
    case "callback_number": return "asks you to call a number given in the message";
    case "click_link": return "directs you to click a link";
    case "shortened_link": return "contains a shortened link that hides the real destination";
    case "http_link": return "contains a link that uses an unencrypted connection (HTTP)";
    case "ip_address_url": return "uses an IP address instead of a normal domain name";
    case "suspicious_tld": return "ends in an unusual domain extension often used in scams";
    case "excessive_subdomains": return "has a suspicious domain structure with many subdomains";
    case "numeric_domain": return "contains many numbers in the domain";
    case "lookalike_domain": return "looks like it is pretending to be a well-known brand";
    case "url_keywords": return "contains multiple phishing-related keywords in the URL";
    case "url_obfuscation": return "is unusually long or complex, which can hide the real destination";
    case "org_domain_mismatch": return "contains a web address that doesn't match the organization mentioned";
    default: return s.label.toLowerCase();
  }
}

// ---- Advice generation --------------------------------------------------

function generateAdvice(signals: Signal[]): AdviceItem[] {
  const advice: AdviceItem[] = [];
  const seen = new Set<string>();

  for (const s of signals) {
    const meta = URL_SIGNAL_META[s.id];
    const adviceText = meta?.advice;
    if (adviceText && !seen.has(adviceText)) {
      seen.add(adviceText);
      advice.push({ id: s.id, text: adviceText });
      continue;
    }
    const def = TEXT_SIGNALS.find((d) => d.id === s.id);
    if (def?.advice && !seen.has(def.advice)) {
      seen.add(def.advice);
      advice.push({ id: s.id, text: def.advice });
    }
  }

  if (signals.length > 0) {
    const generalVerify = "Verify the request using the organization's official website or app — not the contact details in the message.";
    const generalContact = "Contact the organization through an official phone number you already trust.";
    if (!seen.has(generalVerify)) advice.push({ id: "general-verify", text: generalVerify });
    if (!seen.has(generalContact)) advice.push({ id: "general-contact", text: generalContact });
  }

  return advice;
}

// ---- Main analyze function ----------------------------------------------

export function analyzeMessage(text: string): AnalysisResult {
  const trimmed = text.trim();
  const lower = trimmed.toLowerCase();
  const urls = extractUrls(trimmed);
  const mentionedOrgs = findMentionedOrgNames(lower);

  const ctx: AnalysisContext = {
    text: trimmed,
    lower,
    urls,
    hasUrl: urls.length > 0,
    mentionedOrgs,
  };

  // 1. Detect text-based signals
  const triggeredText = TEXT_SIGNALS.filter((s) => s.test(ctx));

  // 2. Detect URL-based signals via urlAnalyzer
  const { analyses: linkAnalyses, signals: urlRawSignals } =
    getAllUrlSignals(urls, trimmed);
  const urlSignals = urlSignalsToSignals(urlRawSignals);

  // 3. Combine all signals
  const textSignalObjects: Signal[] = triggeredText.map((d) => ({
    id: d.id,
    category: d.category,
    icon: d.icon,
    label: d.label,
    detail: d.detail,
    points: d.points,
  }));

  const signals = [...textSignalObjects, ...urlSignals];
  const signalIds = new Set(signals.map((s) => s.id));
  const signalPoints = signals.reduce((sum, s) => sum + s.points, 0);

  // 4. Detect combinations
  const triggeredCombos = COMBINATIONS.filter((c) => c.test(signalIds));
  const combinations: Combination[] = triggeredCombos.map((c) => ({
    id: c.id,
    label: c.label,
    bonus: c.bonus,
  }));

  const comboBonus = combinations.reduce((sum, c) => sum + c.bonus, 0);
  const totalScore = signalPoints + comboBonus;

  // 5. Determine risk level (conservative thresholds)
  let riskLevel: RiskLevel = "low";
  if (totalScore >= 9) {
    riskLevel = "high";
  } else if (totalScore >= 3) {
    riskLevel = "suspicious";
  } else if (totalScore >= 1) {
    riskLevel = "low";
  }

  // 6. Build category scores
  const categories: CategoryScore[] = (
    Object.keys(CATEGORY_META) as SignalCategory[]
  )
    .map((cat) => {
      const catSignals = signals.filter((s) => s.category === cat);
      const points = catSignals.reduce((sum, s) => sum + s.points, 0);
      return {
        category: cat,
        label: CATEGORY_META[cat].label,
        icon: CATEGORY_META[cat].icon,
        level: categoryLevel(points),
        points,
        signals: catSignals,
      };
    })
    .filter((c) => c.points > 0);

  // 7. Generate explanation
  const explanation = generateExplanation(signals, combinations, riskLevel);

  // 8. Generate advice
  const advice = generateAdvice(signals);

  const disclaimer =
    "ScamCheck detects warning signs. It cannot guarantee that a message is legitimate or fraudulent.";

  return {
    riskLevel,
    totalScore,
    signals,
    categories,
    combinations,
    explanation,
    advice,
    linkAnalyses,
    disclaimer,
    rawText: trimmed,
  };
}

// ---- Example messages (UI) ---------------------------------------------

export interface ExampleMessage {
  label: string;
  text: string;
}

export const EXAMPLE_MESSAGES: ExampleMessage[] = [
  {
    label: "Bank scam with suspicious link (high risk)",
    text: "Dear Customer, your account will be suspended within 24 hours due to suspicious activity. Please verify your account immediately by clicking this link: http://barclays-secure-verify.tk/login — Act now to avoid losing access to your funds.",
  },
  {
    label: "Prize scam with shortened link (high risk)",
    text: "CONGRATULATIONS! You have been selected as the winner of a $1,000,000 lottery. To claim your prize, pay a processing fee of $50 via Bitcoin. Contact us now before this offer expires today! Claim here: http://bit.ly/claim-prize-now",
  },
  {
    label: "SBI phishing with OTP (high risk)",
    text: "URGENT: Your bank account will be blocked today. Click https://sbi-secure-login.example.com and enter your OTP and password immediately.",
  },
  {
    label: "PayPal lookalike domain (suspicious)",
    text: "Your PayPal account needs verification: https://paypa1-login.example.com",
  },
  {
    label: "IP address URL (suspicious)",
    text: "Your account will be suspended today. Verify immediately at http://192.168.1.50/login",
  },
  {
    label: "Shortened payment link (suspicious)",
    text: "Your package requires payment. Complete it here: http://bit.ly/example",
  },
  {
    label: "Normal message (low risk)",
    text: "Hi Sarah, just wanted to confirm we're still meeting at the cafe at 3pm on Saturday. Let me know if you need to reschedule. Thanks!",
  },
  {
    label: "Normal link (low risk)",
    text: "Check the event details at https://www.example.com/event",
  },
  {
    label: "Everyday message (low risk)",
    text: "Your Amazon package will arrive today between 2pm and 6pm. Please make sure someone is available to receive it.",
  },
];

// ---- Test messages (developer/testing) ----------------------------------

export interface TestCase {
  label: string;
  text: string;
  expected: RiskLevel;
}

export const TEST_MESSAGES: {
  normal: TestCase[];
  suspicious: TestCase[];
  scam: TestCase[];
} = {
  normal: [
    { label: "Assignment deadline", text: "Your assignment is due today.", expected: "low" },
    { label: "ID reminder", text: "Please bring your ID tomorrow.", expected: "low" },
    { label: "Package delivery", text: "Your Amazon package will arrive today.", expected: "low" },
    { label: "School fee", text: "Please pay the school fee before Friday.", expected: "low" },
    { label: "Owe money casual", text: "Hey, can you send me the money you owe me?", expected: "low" },
    { label: "Normal URL", text: "Check the event details at https://www.example.com/event", expected: "low" },
    { label: "Physics assignment", text: "Your physics assignment is due today. Please submit it in class tomorrow.", expected: "low" },
    { label: "Physics assignment reminder", text: "Hi Rahul, just a reminder that your physics assignment is due tomorrow. Please submit it before 4 PM in the classroom.", expected: "low" },
    { label: "Real bank OTP message", text: "123456 is your OTP for a transaction of Rs 500 at Amazon. Do not share this OTP with anyone. -HDFC Bank", expected: "low" },
    { label: "Word 'groups' is not UPS", text: "The groups meeting is at 5, details here https://example.com/meeting", expected: "low" },
    { label: "Amazon delivery window", text: "Your Amazon package will arrive tomorrow between 2 PM and 5 PM.", expected: "low" },
  ],
  suspicious: [
    { label: "Bank statement ready", text: "Your bank statement is ready. Log in to view your recent transactions. Visit www.yourbank.com to access your account.", expected: "suspicious" },
    { label: "Package on hold", text: "Your package is on hold. Please pay a small processing fee to resume delivery. Click here to continue.", expected: "suspicious" },
    { label: "Account update request", text: "Dear Customer, please update your account details to continue using our service. Confirm your identity here.", expected: "suspicious" },
    { label: "Unexpected prize notification", text: "Congratulations! You have been selected for a special reward. Reply YES to claim.", expected: "suspicious" },
    { label: "Urgent payment reminder", text: "URGENT: Your invoice is overdue. Please complete your payment immediately to avoid service interruption.", expected: "suspicious" },
    { label: "Shortened payment link", text: "Your package requires payment. Complete it here: http://bit.ly/example", expected: "suspicious" },
    { label: "PayPal lookalike", text: "Your PayPal account needs verification: https://paypa1-login.example.com", expected: "high" },
    { label: "Easy-money job offer", text: "Earn Rs 5000 daily working from home. Just like YouTube videos and message us on Telegram", expected: "suspicious" },
    { label: "Delivery address confirm", text: "Your delivery could not be completed. Please confirm your address using the link below.", expected: "low" },
  ],
  scam: [
    { label: "Bank account suspension + OTP", text: "Your bank account will be blocked today. Click this link and enter your OTP to verify your account.", expected: "high" },
    { label: "Lottery + processing fee", text: "CONGRATULATIONS! You've won the $500,000 lottery. Pay a processing fee of $100 via gift card to claim your prize. Send money to claim here: http://bit.ly/lucky-claim", expected: "high" },
    { label: "HMRC legal threat + link", text: "URGENT NOTICE: You owe £2,500 in unpaid taxes. Legal action will be taken immediately. Pay now at http://hmrc-tax.work/pay or face arrest today.", expected: "high" },
    { label: "Amazon OTP + password phishing", text: "Your Amazon account is locked. Reply with your OTP and password immediately. Your account will be permanently closed if you do not act now.", expected: "high" },
    { label: "Bank impersonation + suspicious link", text: "Dear Customer, your bank account has been suspended due to suspicious activity. Verify your account immediately at http://hsbc-secure-verify.tk/login or your account will be permanently closed.", expected: "high" },
    { label: "SBI phishing + OTP + password", text: "URGENT: Your bank account will be blocked today. Click https://sbi-secure-login.example.com and enter your OTP and password immediately.", expected: "high" },
    { label: "IP address + account threat", text: "Your account will be suspended today. Verify immediately at http://192.168.1.50/login", expected: "high" },
    { label: "KYC expired + OTP + legal threat", text: "URGENT: Your bank account will be permanently BLOCKED today! Your KYC has expired. Click https://secure-bank-verify.com immediately and enter your account number, password and OTP to prevent suspension. Failure to act within 30 minutes will result in legal action.", expected: "high" },
    { label: "Boss gift-card request", text: "Hi it's your boss. I'm in a meeting, buy 5 Google Play gift cards of 1000 each and send me the codes urgently", expected: "high" },
    { label: "Parcel held + lookalike link", text: "India Post: your parcel is held due to incomplete address. Update within 12 hrs: http://indiapost-track.top/ab", expected: "high" },
    { label: "Electricity cut threat + phone number", text: "Dear customer your electricity will be disconnected tonight 9:30 PM due to unpaid bill. Call 9876543210 immediately", expected: "high" },
    { label: "Lottery + processing fee (INR)", text: "Congratulations! You have won ₹50,000 in our lottery. Pay ₹999 processing fee immediately to claim your prize.", expected: "high" },
  ],
};

export interface TestResult {
  label: string;
  text: string;
  expected: RiskLevel;
  actual: RiskLevel;
  passed: boolean;
  score: number;
}

export function runTests(): TestResult[] {
  const results: TestResult[] = [];
  for (const group of Object.values(TEST_MESSAGES)) {
    for (const tc of group) {
      const analysis = analyzeMessage(tc.text);
      results.push({
        label: tc.label,
        text: tc.text,
        expected: tc.expected,
        actual: analysis.riskLevel,
        passed: analysis.riskLevel === tc.expected,
        score: analysis.totalScore,
      });
    }
  }
  return results;
}
