import {
  SYNTHETIC_PHONE_REPORT_DEMO,
  VERIFIED_INDIAN_PHONE_REPORTS,
} from "../src/lib/indiaScamNumbers.ts";
import {
  findVerifiedIndianPhoneReport,
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
      actual: normalizeIndianMobileNumber("9876543210") ?? "invalid",
      expected: "9876543210",
    },
    {
      label: "normalize +91 with spaces and hyphens",
      actual: normalizeIndianMobileNumber("+91 98765-43210") ?? "invalid",
      expected: "9876543210",
    },
    {
      label: "normalize 91 country code without plus",
      actual: normalizeIndianMobileNumber("91 98765 43210") ?? "invalid",
      expected: "9876543210",
    },
    {
      label: "normalize domestic trunk prefix",
      actual: normalizeIndianMobileNumber("09876543210") ?? "invalid",
      expected: "9876543210",
    },
    {
      label: "reject a mobile number with an invalid starting digit",
      actual: normalizeIndianMobileNumber("5876543210") ?? "invalid",
      expected: "invalid",
    },
    {
      label: "reject letters mixed into a phone number",
      actual: normalizeIndianMobileNumber("98765abc210") ?? "invalid",
      expected: "invalid",
    },
    {
      label: "do not match an unreported phone number",
      actual: findVerifiedIndianPhoneReport("9876543210")?.number ?? "not found",
      expected: "not found",
    },
    {
      label: "keep the phone report list empty without sourced dated entries",
      actual: String(VERIFIED_INDIAN_PHONE_REPORTS.length),
      expected: "0",
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