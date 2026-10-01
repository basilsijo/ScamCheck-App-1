// ScamCheck — AI analysis client
//
// Calls the Supabase Edge Function "ai-analyze" which securely contacts the
// OpenAI API server-side. The API key is never exposed to the frontend.
//
// If the edge function is unavailable or returns an error, the caller can
// fall back to the existing rule-based result — the app stays functional.

import type { AnalysisResult } from "@/lib/scamAnalyzer";

export type AiRisk = "LOW" | "SUSPICIOUS" | "HIGH";

export interface AiAnalysis {
  risk: AiRisk;
  confidence: number;
  reasons: string[];
  red_flags: string[];
  advice: string[];
}

export interface AiAnalysisResponse {
  analysis: AiAnalysis | null;
  error: string | null;
}

function buildRuleFindings(result: AnalysisResult): string[] {
  const findings: string[] = [];

  for (const s of result.signals) {
    findings.push(s.label);
  }

  for (const la of result.linkAnalyses) {
    const flagged = la.checks.filter((c) => c.status !== "good");
    for (const c of flagged) {
      findings.push(`URL check: ${c.label} — ${c.detail}`);
    }
  }

  for (const c of result.combinations) {
    findings.push(`Combination: ${c.label}`);
  }

  return findings;
}

export async function fetchAiAnalysis(
  message: string,
  result: AnalysisResult
): Promise<AiAnalysisResponse> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;
  if (!supabaseUrl || !supabaseAnonKey) {
    const missing = [
      !supabaseUrl && "VITE_SUPABASE_URL",
      !supabaseAnonKey && "VITE_SUPABASE_ANON_KEY",
    ].filter(Boolean).join(" and ");
    return {
      analysis: null,
      error: `Missing ${missing}. Add the value${missing.includes(" and ") ? "s" : ""} in Replit Secrets/environment settings and rebuild the app. Rule-based analysis is still available.`,
    };
  }

  let parsedSupabaseUrl: URL;
  try {
    parsedSupabaseUrl = new URL(supabaseUrl);
    if (parsedSupabaseUrl.protocol !== "https:" && parsedSupabaseUrl.protocol !== "http:") {
      throw new Error("Unsupported protocol");
    }
  } catch {
    return {
      analysis: null,
      error: "VITE_SUPABASE_URL is not a valid HTTP(S) URL. Check the Supabase project URL in Replit Secrets.",
    };
  }

  const urls = result.linkAnalyses.map((la) => la.url);
  const ruleFindings = buildRuleFindings(result);

  const functionUrl = `${parsedSupabaseUrl.toString().replace(/\/$/, "")}/functions/v1/ai-analyze`;

  try {
    const response = await fetch(functionUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${supabaseAnonKey}`,
        "apikey": supabaseAnonKey,
      },
      body: JSON.stringify({
        message: message.slice(0, 3000),
        ruleFindings,
        urls,
      }),
    });

    let data: unknown;
    try {
      data = await response.json();
    } catch {
      if (response.ok) {
        return {
          analysis: null,
          error: "The Supabase AI function returned a non-JSON response. Confirm that ai-analyze is deployed at the configured project URL.",
        };
      }
    }

    if (!response.ok) {
      const errorBody = data && typeof data === "object" ? data as Record<string, unknown> : {};
      const serverMessage = typeof errorBody.error === "string"
        ? errorBody.error.trim()
        : typeof errorBody.message === "string"
          ? errorBody.message.trim()
          : "";
      if (response.status === 401 || response.status === 403) {
        return {
          analysis: null,
          error: `Supabase rejected the request (HTTP ${response.status}). Check VITE_SUPABASE_ANON_KEY and the Edge Function authorization/deployment settings.${serverMessage ? ` ${serverMessage}` : ""}`,
        };
      }
      if (response.status === 404) {
        return {
          analysis: null,
          error: "The ai-analyze Edge Function was not found (HTTP 404). Deploy it to this Supabase project and check VITE_SUPABASE_URL.",
        };
      }
      return {
        analysis: null,
        error: serverMessage
          ? `The Supabase AI function returned HTTP ${response.status}: ${serverMessage}`
          : `The Supabase AI function returned HTTP ${response.status}. Check the function deployment and logs.`,
      };
    }

    const analysis = validateAiAnalysis(data);
    if (!analysis) {
      return {
        analysis: null,
        error: "The ai-analyze function returned an unexpected response. Check that the deployed function returns risk, confidence, reasons, red_flags, and advice.",
      };
    }

    return { analysis, error: null };
  } catch (err) {
    const detail = err instanceof Error ? err.message : "";
    return {
      analysis: null,
      error: `Could not reach the Supabase AI function. Check the network/CORS settings, VITE_SUPABASE_URL, and that ai-analyze is deployed.${detail ? ` (${detail})` : ""}`,
    };
  }
}

function validateAiAnalysis(raw: unknown): AiAnalysis | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;

  const riskRaw = String(obj.risk ?? "").toUpperCase();
  if (riskRaw !== "LOW" && riskRaw !== "SUSPICIOUS" && riskRaw !== "HIGH") return null;
  if (typeof obj.confidence !== "number" || !Number.isFinite(obj.confidence)) return null;
  if (!Array.isArray(obj.reasons) || !obj.reasons.every((item) => typeof item === "string")) return null;
  if (!Array.isArray(obj.red_flags) || !obj.red_flags.every((item) => typeof item === "string")) return null;
  if (!Array.isArray(obj.advice) || !obj.advice.every((item) => typeof item === "string")) return null;

  const risk: AiRisk = riskRaw as AiRisk;
  const confidence = Math.max(0, Math.min(100, Math.round(obj.confidence)));
  const reasons = (obj.reasons as string[]).filter(Boolean);
  const red_flags = (obj.red_flags as string[]).filter(Boolean);
  const advice = (obj.advice as string[]).filter(Boolean);

  return { risk, confidence, reasons, red_flags, advice };
}
