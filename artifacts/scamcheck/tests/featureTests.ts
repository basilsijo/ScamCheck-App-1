import {
  SYNTHETIC_PHONE_REPORT_DEMO,
  PHONE_REPORT_IMPORT_STATS,
  USER_SUBMITTED_INDIAN_PHONE_REPORTS,
  VERIFIED_INDIAN_PHONE_REPORTS,
} from "../src/lib/indiaScamNumbers.ts";
import {
  findVerifiedIndianPhoneReport,
  findUserSubmittedIndianPhoneReport,
  isPhoneThreatDetected,
  normalizeIndianMobileNumber,
} from "../src/lib/phoneNumberAnalyzer.ts";
import {
  getVerifiedAlternativesForUrl,
  normalizeWebsiteUrlInput,
} from "../src/lib/urlAnalyzer.ts";

export interface FeatureTestResult {
  label: string;
  expected: string;
  actual: string;
  score: number;
  text: string;
  passed: boolean;
}

export function runFeatureTests(): FeatureTestResult[] {
  const cases: Array<{ label: string; actual: string; expected: string }> = [
    {
      label: "normalize a 10-digit Indian mobile",
      actual: normalizeIndianMobileNumber("9876543210") === "9876543210" ? "normalized" : "incorrect",
      expected: "normalized",
    },
    {
      label: "normalize +91 with spaces and hyphens",
      actual: normalizeIndianMobileNumber("+91 98765-43210") === "9876543210" ? "normalized" : "incorrect",
      expected: "normalized",
    },
    {
      label: "normalize apostrophe-formatted country prefix",
      actual: normalizeIndianMobileNumber("'+91 98765 43210'") === "9876543210" ? "normalized" : "incorrect",
      expected: "normalized",
    },
    {
      label: "normalize 91 country code without plus",
      actual: normalizeIndianMobileNumber("91 98765 43210") === "9876543210" ? "normalized" : "incorrect",
      expected: "normalized",
    },
    {
      label: "normalize domestic trunk prefix",
      actual: normalizeIndianMobileNumber("09876543210") === "9876543210" ? "normalized" : "incorrect",
      expected: "normalized",
    },
    {
      label: "reject a mobile number with an invalid starting digit",
      actual: normalizeIndianMobileNumber("5876543210") ?? "invalid",
      expected: "invalid",
    },
    {
      label: "reject a truncated 9-digit number without repairing it",
      actual: normalizeIndianMobileNumber("987654321") ?? "invalid",
      expected: "invalid",
    },
    {
      label: "reject an 11-digit number without a recognized prefix",
      actual: normalizeIndianMobileNumber("98765432109") ?? "invalid",
      expected: "invalid",
    },
    {
      label: "reject letters mixed into a phone number",
      actual: normalizeIndianMobileNumber("98765abc210") ?? "invalid",
      expected: "invalid",
    },
    {
      label: "do not match an unreported phone number",
      actual: findUserSubmittedIndianPhoneReport("0000000000")?.number ?? "not found",
      expected: "not found",
    },
    {
      label: "imported unique count matches stored entries",
      actual: String(USER_SUBMITTED_INDIAN_PHONE_REPORTS.length),
      expected: String(PHONE_REPORT_IMPORT_STATS.uniqueImported),
    },
    {
      label: "lookup finds an imported user-submitted record locally",
      actual: USER_SUBMITTED_INDIAN_PHONE_REPORTS.length > 0 &&
        findUserSubmittedIndianPhoneReport(USER_SUBMITTED_INDIAN_PHONE_REPORTS[0].number)?.number === USER_SUBMITTED_INDIAN_PHONE_REPORTS[0].number
        ? "found" : "not found",
      expected: "found",
    },
    {
      label: "user-submitted matches count as HIGH RISK in ScamCheck",
      actual: USER_SUBMITTED_INDIAN_PHONE_REPORTS[0] &&
        isPhoneThreatDetected(undefined, USER_SUBMITTED_INDIAN_PHONE_REPORTS[0])
        ? "HIGH RISK" : "not found",
      expected: "HIGH RISK",
    },
    {
      label: "an unmatched number has no threat classification",
      actual: isPhoneThreatDetected() ? "HIGH RISK" : "not found",
      expected: "not found",
    },
    {
      label: "record source and import date for every entry",
      actual: USER_SUBMITTED_INDIAN_PHONE_REPORTS.every((entry) =>
        entry.source === "User-provided number list" &&
        entry.importDate === "2026-10-02" &&
        entry.verificationStatus === "unverified"
      ) ? "consistent" : "inconsistent",
      expected: "consistent",
    },
    {
      label: "keep verified reports separate until credible source records exist",
      actual: String(VERIFIED_INDIAN_PHONE_REPORTS.length),
      expected: "0",
    },
    {
      label: "do not promote a user-submitted entry to verified",
      actual: USER_SUBMITTED_INDIAN_PHONE_REPORTS[0] &&
        findVerifiedIndianPhoneReport(USER_SUBMITTED_INDIAN_PHONE_REPORTS[0].number)
        ? "verified" : "unverified",
      expected: "unverified",
    },
    {
      label: "stored entries are unique and normalized",
      actual: new Set(USER_SUBMITTED_INDIAN_PHONE_REPORTS.map((entry) => entry.number)).size === USER_SUBMITTED_INDIAN_PHONE_REPORTS.length &&
        USER_SUBMITTED_INDIAN_PHONE_REPORTS.every((entry) => /^[6-9]\d{9}$/.test(entry.number))
        ? "unique and valid" : "invalid",
      expected: "unique and valid",
    },
    {
      label: "import summary matches the file processing",
      actual: `${PHONE_REPORT_IMPORT_STATS.entriesRead}/${PHONE_REPORT_IMPORT_STATS.duplicateEntriesRemoved}/${PHONE_REPORT_IMPORT_STATS.invalidEntriesSkipped}`,
      expected: "1050/14/2",
    },
    {
      label: "keep the synthetic example outside plausible Indian mobile numbers",
      actual: normalizeIndianMobileNumber(SYNTHETIC_PHONE_REPORT_DEMO.number) ?? "invalid",
      expected: "invalid",
    },
    {
      label: "accept a bare website domain",
      actual: normalizeWebsiteUrlInput("example.com") ?? "invalid",
      expected: "http://example.com/",
    },
    {
      label: "accept one explicit HTTPS website URL",
      actual: normalizeWebsiteUrlInput("https://example.com") ?? "invalid",
      expected: "https://example.com/",
    },
    {
      label: "reject multiple website addresses",
      actual: normalizeWebsiteUrlInput("https://example.com https://example.org") ?? "invalid",
      expected: "invalid",
    },
    {
      label: "reject a non-web protocol",
      actual: normalizeWebsiteUrlInput("javascript://example.com") ?? "invalid",
      expected: "invalid",
    },
    {
      label: "offer the verified alternative for a recognized lookalike",
      actual: getVerifiedAlternativesForUrl("https://amaz0n-login.example")
        .map((alternative) => alternative.organization)
        .join(", ") || "none",
      expected: "Amazon",
    },
    {
      label: "do not invent an organization for an unknown domain",
      actual: getVerifiedAlternativesForUrl("https://example.com")
        .map((alternative) => alternative.organization)
        .join(", ") || "none",
      expected: "none",
    },
  ];

  return cases.map(({ label, actual, expected }) => ({
    label,
    actual,
    expected,
    score: 0,
    text: "",
    passed: actual === expected,
  }));
}