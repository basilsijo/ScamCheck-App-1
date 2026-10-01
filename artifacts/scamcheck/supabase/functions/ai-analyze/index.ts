// Edge function: ai-analyze
// Securely calls the OpenAI API to get a contextual analysis of a potentially
// fraudulent message. The OPENAI_API_KEY is read from the edge function's
// environment — it is never exposed to the frontend.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, apikey",
};

// Limits so nobody can send huge requests and run up your OpenAI bill.
const MAX_MESSAGE_CHARS = 3000;
const MAX_FINDINGS = 30;
const MAX_URLS = 10;

const SYSTEM_PROMPT = `You are ScamCheck AI, an assistant that analyzes potentially fraudulent or scam messages.

Your job is to provide a contextual second opinion on top of a rule-based detection system. You do NOT replace the rule-based system — you add context and nuance.

Consider these scam indicators:
- Impersonation of banks, delivery services, government agencies, or well-known companies
- Requests for passwords, OTPs, PINs, CVVs, or banking details
- Requests for money, fees, gift cards, or cryptocurrency
- Account suspension threats or KYC/verification requests
- Fake delivery messages or failed delivery notices
- Fake prizes, lotteries, or winnings
- Urgency, deadlines, and time pressure ("within 30 minutes", "act now")
- Threats of legal action, arrest, or account closure
- Suspicious links and domain/organization mismatches
- Social engineering techniques

IMPORTANT RULES:
1. Do NOT flag a message as a scam just because it contains one suspicious keyword. A message like "Your Amazon package arrives tomorrow" is NOT suspicious.
2. Look for MULTIPLE pieces of contextual evidence that make sense together.
3. A single weak signal (like the word "today") should NOT make a message suspicious.
4. Consider the ENTIRE context of the message — who it claims to be from, what it asks for, and what threats or urgency it creates.
5. NEVER use the word "scam" or "fraud" as a certainty. Use "risk" and "warning signs" instead.
6. NEVER say a message is "100% safe" or "guaranteed scam."
7. Keep your reasons short, clear, and understandable to a non-technical person.
8. Do NOT use cybersecurity jargon.
9. Give practical safe actions: do not click suspicious links; do not provide OTPs, passwords, PINs, CVVs, or payment information; open the organization's official app directly; contact the organization using an official support channel; and verify requests independently.
10. Never provide or invent an official website URL. Verified URLs are supplied separately by the application.

You must respond with ONLY a JSON object in this exact format:
{
  "risk": "LOW" | "SUSPICIOUS" | "HIGH",
  "confidence": <number 0-100>,
  "reasons": ["short reason 1", "short reason 2", ...],
  "red_flags": ["specific red flag 1", "specific red flag 2", ...],
  "advice": ["actionable advice 1", "actionable advice 2", ...]
}

If the message seems completely normal, return LOW with low confidence, empty red_flags, and a note in reasons explaining it appears normal.`;

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(
      JSON.stringify({ error: "Method not allowed" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const apiKey = Deno.env.get("OPENAI_API_KEY");
  if (!apiKey) {
    return new Response(
      JSON.stringify({ error: "AI analysis is not configured. The OPENAI_API_KEY secret has not been set." }),
      { status: 503, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    const body = await req.json();
    const rawMessage: unknown = body?.message;
    const ruleFindings: string[] = (Array.isArray(body?.ruleFindings) ? body.ruleFindings : [])
      .filter((x: unknown) => typeof x === "string")
      .slice(0, MAX_FINDINGS)
      .map((x: string) => x.slice(0, 300));
    const urls: string[] = (Array.isArray(body?.urls) ? body.urls : [])
      .filter((x: unknown) => typeof x === "string")
      .slice(0, MAX_URLS)
      .map((x: string) => x.slice(0, 300));
    const message: string = typeof rawMessage === "string" ? rawMessage : "";

    if (message.length > MAX_MESSAGE_CHARS) {
      return new Response(
        JSON.stringify({ error: `Message is too long. Please paste at most ${MAX_MESSAGE_CHARS} characters.` }),
        { status: 413, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!message || typeof message !== "string") {
      return new Response(
        JSON.stringify({ error: "Missing 'message' field in request body." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const userPrompt = buildUserPrompt(message, ruleFindings, urls);

    const openaiResponse = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: userPrompt },
        ],
        temperature: 0.2,
        max_tokens: 600,
        response_format: { type: "json_object" },
      }),
    });

    if (!openaiResponse.ok) {
      const errText = await openaiResponse.text();
      console.error("OpenAI API error:", openaiResponse.status, errText);
      return new Response(
        JSON.stringify({ error: `OpenAI API returned an error (status ${openaiResponse.status}).` }),
        { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const openaiData = await openaiResponse.json();
    const content = openaiData?.choices?.[0]?.message?.content;

    if (!content) {
      return new Response(
        JSON.stringify({ error: "OpenAI returned an empty response." }),
        { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      return new Response(
        JSON.stringify({ error: "OpenAI returned invalid JSON." }),
        { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const aiResult = validateAiResult(parsed);

    return new Response(
      JSON.stringify(aiResult),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (err) {
    console.error("Edge function error:", err);
    return new Response(
      JSON.stringify({ error: "An unexpected error occurred during AI analysis." }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

function buildUserPrompt(message: string, ruleFindings: string[], urls: string[]): string {
  const parts: string[] = [`Analyze this message for scam risk:\n\n"${message}"`];

  if (urls.length > 0) {
    parts.push(`\nURLs found in the message: ${urls.join(", ")}`);
  }

  if (ruleFindings.length > 0) {
    parts.push(`\nRule-based findings already detected:`);
    for (const f of ruleFindings) {
      parts.push(`- ${f}`);
    }
    parts.push(`\nConsider these findings but also evaluate the overall context. Do not simply agree with every rule-based finding — use your own contextual judgment.`);
  } else {
    parts.push(`\nNo rule-based findings were detected. Evaluate the message on its own merits.`);
  }

  parts.push(`\nReturn ONLY the JSON object as specified in your instructions.`);
  return parts.join("\n");
}

interface AiResult {
  risk: "LOW" | "SUSPICIOUS" | "HIGH";
  confidence: number;
  reasons: string[];
  red_flags: string[];
  advice: string[];
}

function validateAiResult(raw: unknown): AiResult {
  const obj = raw as Record<string, unknown>;
  const riskRaw = String(obj?.risk ?? "LOW").toUpperCase();
  const risk: AiResult["risk"] =
    riskRaw === "HIGH" ? "HIGH" : riskRaw === "SUSPICIOUS" ? "SUSPICIOUS" : "LOW";
  const confidence = Math.max(0, Math.min(100, Math.round(Number(obj?.confidence ?? 0)) || 0));
  const reasons = Array.isArray(obj?.reasons) ? (obj.reasons as unknown[]).map(String).filter(Boolean) : [];
  const red_flags = Array.isArray(obj?.red_flags) ? (obj.red_flags as unknown[]).map(String).filter(Boolean) : [];
  const advice = Array.isArray(obj?.advice) ? (obj.advice as unknown[]).map(String).filter(Boolean) : [];

  return { risk, confidence, reasons, red_flags, advice };
}
