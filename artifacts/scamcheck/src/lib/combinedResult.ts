// ScamCheck — Combined result logic
//
// Merges the rule-based risk level with the AI contextual analysis to produce
// a single combined risk level. The rule-based system is the evidence layer;
// the AI adds contextual interpretation.
//
// Priority:
// 1. Avoid false positives — don't escalate to HIGH based on AI alone
// 2. Give useful explanations
// 3. Detect obvious scams reliably
// 4. Never claim 100% certainty

import type { RiskLevel } from "@/lib/scamAnalyzer";
import type { AiRisk } from "@/lib/aiAnalysis";

export type CombinedRisk = RiskLevel;

export interface CombinedResult {
  combinedRisk: CombinedRisk;
  combinedConfidence: number;
  ruleRisk: RiskLevel;
  aiRisk: AiRisk | null;
  note: string | null;
}

const RISK_ORDER: Record<string, number> = { low: 0, suspicious: 1, high: 2 };

export function combineResults(
  ruleRisk: RiskLevel,
  ruleScore: number,
  aiRisk: AiRisk | null,
  aiConfidence: number
): CombinedResult {
  if (!aiRisk) {
    return {
      combinedRisk: ruleRisk,
      combinedConfidence: 0,
      ruleRisk,
      aiRisk: null,
      note: null,
    };
  }

  const ruleVal = RISK_ORDER[ruleRisk] ?? 0;
  const aiVal = RISK_ORDER[aiRisk.toLowerCase() as RiskLevel] ?? 0;

  let combinedRisk: CombinedRisk = ruleRisk;
  let note: string | null = null;

  if (ruleVal === aiVal) {
    // Agreement — increase confidence, keep the risk level
    combinedRisk = ruleRisk;
    note = null;
  } else if (ruleVal > aiVal) {
    // Rules say higher than AI — keep the rule-based level (objective evidence wins)
    combinedRisk = ruleRisk;
    if (ruleRisk === "high") {
      note = "The rule-based system detected strong objective warning signs. AI analysis was less certain, but the objective evidence keeps the risk level high.";
    } else {
      note = "The rule-based system found more warning signs than the AI analysis. The combined result follows the stronger evidence.";
    }
  } else {
    // AI says higher than rules — escalate conservatively
    if (aiRisk === "HIGH" && ruleRisk === "low") {
      // AI says HIGH but rules say LOW — only escalate to suspicious, not high
      combinedRisk = "suspicious";
      note = "The AI analysis detected contextual warning signs that the rule-based system did not. The combined result is elevated to Suspicious, but not High, because the rule-based system did not find strong objective evidence.";
    } else if (aiRisk === "HIGH" && ruleRisk === "suspicious") {
      // AI says HIGH, rules say SUSPICIOUS — can go to high if confidence is strong
      if (aiConfidence >= 75) {
        combinedRisk = "high";
        note = "Both the AI analysis and the rule-based system identified warning signs. The AI's high confidence combined with the rule-based findings elevates the risk to High.";
      } else {
        combinedRisk = "suspicious";
        note = "The AI analysis suggests high risk, but without strong rule-based evidence and high AI confidence, the combined result remains Suspicious.";
      }
    } else if (aiRisk === "SUSPICIOUS" && ruleRisk === "low") {
      // AI says SUSPICIOUS, rules say LOW — stay suspicious only if confidence is decent
      if (aiConfidence >= 50) {
        combinedRisk = "suspicious";
        note = "The AI analysis detected some contextual warning signs. The combined result is elevated to Suspicious.";
      } else {
        combinedRisk = "low";
        note = "The AI analysis mentioned some concerns but with low confidence. The combined result remains Low.";
      }
    } else {
      combinedRisk = ruleRisk;
    }
  }

  // Confidence: average of rule-based score-weighted confidence and AI confidence
  const ruleConfidence = Math.min(100, ruleScore * 8);
  const combinedConfidence = aiRisk
    ? Math.round((ruleConfidence + aiConfidence) / 2)
    : ruleConfidence;

  return {
    combinedRisk,
    combinedConfidence,
    ruleRisk,
    aiRisk,
    note,
  };
}
