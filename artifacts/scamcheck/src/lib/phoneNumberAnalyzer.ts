import {
  VERIFIED_INDIAN_PHONE_REPORTS,
  type VerifiedIndianPhoneReport,
} from "./indiaScamNumbers";

/**
 * Return the normalized 10-digit Indian mobile number, or null if the value
 * is not a plausible Indian mobile number. This function is local-only.
 */
export function normalizeIndianMobileNumber(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || !/^\+?[\d\s()-]+$/.test(trimmed)) return null;

  const digits = trimmed.replace(/\D/g, "");
  let nationalNumber = digits;

  if (trimmed.startsWith("+")) {
    if (!digits.startsWith("91") || digits.length !== 12) return null;
    nationalNumber = digits.slice(2);
  } else if (digits.length === 12 && digits.startsWith("91")) {
    nationalNumber = digits.slice(2);
  } else if (digits.length === 11 && digits.startsWith("0")) {
    nationalNumber = digits.slice(1);
  }

  return /^[6-9]\d{9}$/.test(nationalNumber) ? nationalNumber : null;
}

export function findVerifiedIndianPhoneReport(
  normalizedNumber: string,
): VerifiedIndianPhoneReport | undefined {
  return VERIFIED_INDIAN_PHONE_REPORTS.find(
    (report) => report.number === normalizedNumber,
  );
}