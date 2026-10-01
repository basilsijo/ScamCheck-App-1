import {
  USER_SUBMITTED_INDIAN_PHONE_REPORTS,
  VERIFIED_INDIAN_PHONE_REPORTS,
  type VerifiedIndianPhoneReport,
  type UserSubmittedIndianPhoneReport,
} from "./indiaScamNumbers";

/**
 * Return the normalized 10-digit Indian mobile number, or null if the value
 * is not a plausible Indian mobile number. This function is local-only.
 */
export function normalizeIndianMobileNumber(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  let parenthesisDepth = 0;
  for (const character of trimmed) {
    if (character === "(") parenthesisDepth += 1;
    if (character === ")") parenthesisDepth -= 1;
    if (parenthesisDepth < 0) return null;
  }
  if (parenthesisDepth !== 0) return null;

  // Only remove common formatting. Other characters make the input invalid.
  const compact = trimmed.replace(/[\s\-‐‑‒–—'‘’ʼ`()]/gu, "");
  if (!/^\+?\d+$/.test(compact)) return null;

  const hasPlusPrefix = compact.startsWith("+");
  const digits = hasPlusPrefix ? compact.slice(1) : compact;
  let nationalNumber = digits;

  if (hasPlusPrefix) {
    if (!digits.startsWith("91") || digits.length !== 12) return null;
    nationalNumber = digits.slice(2);
  } else if (digits.length === 12 && digits.startsWith("91")) {
    nationalNumber = digits.slice(2);
  } else if (digits.length === 11 && digits.startsWith("0")) {
    nationalNumber = digits.slice(1);
  }

  return /^[6-9]\d{9}$/.test(nationalNumber) ? nationalNumber : null;
}

export function findUserSubmittedIndianPhoneReport(
  normalizedNumber: string,
): UserSubmittedIndianPhoneReport | undefined {
  return USER_SUBMITTED_INDIAN_PHONE_REPORTS.find(
    (report) => report.number === normalizedNumber,
  );
}

export function findVerifiedIndianPhoneReport(
  normalizedNumber: string,
): VerifiedIndianPhoneReport | undefined {
  return VERIFIED_INDIAN_PHONE_REPORTS.find(
    (report) =>
      report.number === normalizedNumber &&
      report.verificationStatus === "verified" &&
      report.source.trim().length > 0 &&
      report.reportDate.trim().length > 0 &&
      report.evidenceSummary.trim().length > 0,
  );
}

/** Any local-list match is a high-risk signal for ScamCheck, regardless of verification status. */
export function isPhoneThreatDetected(
  verifiedReport?: VerifiedIndianPhoneReport,
  userSubmittedReport?: UserSubmittedIndianPhoneReport,
): boolean {
  return Boolean(verifiedReport || userSubmittedReport);
}