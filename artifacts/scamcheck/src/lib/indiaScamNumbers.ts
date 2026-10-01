export interface VerifiedIndianPhoneReport {
  /** Normalized 10-digit Indian mobile number. */
  number: string;
  /** Public source that identifies this number as reported. */
  source: string;
  /** Date the source published or recorded the report. */
  reportDate: string;
}

/**
 * Intentionally empty until individual entries can be verified against a
 * credible public source with a report date. Do not add generated or
 * valid-looking demo numbers: a real person could own them.
 */
export const VERIFIED_INDIAN_PHONE_REPORTS: readonly VerifiedIndianPhoneReport[] = [];

/**
 * A visibly synthetic example for demonstrating the report fields. The
 * placeholder is invalid as an Indian mobile number and is never searched.
 */
export const SYNTHETIC_PHONE_REPORT_DEMO = {
  number: "0000000000",
  source: "Synthetic demo only — not a public report",
  reportDate: "Not applicable — fictional example",
} as const;