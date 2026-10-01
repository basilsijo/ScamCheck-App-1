# ScamCheck

Check suspicious messages before you click. ScamCheck uses a two-layer system: a rule-based detector for objective warning signs, plus an optional AI contextual analysis for deeper insight.

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Supabase (pre-configured)

The Supabase project is already provisioned. Connection details are in `.env` and do not need to be changed.

### 3. OpenAI API key (for AI Context Analysis)

The AI second-opinion feature uses a Supabase Edge Function that calls the OpenAI API server-side. The API key is never exposed to the frontend.

To enable AI analysis:

1. Create an OpenAI API key at [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys).
2. Set the key as a Supabase Edge Function secret named `OPENAI_API_KEY`:
   - Go to your Supabase project dashboard
   - Navigate to Edge Functions > Secrets
   - Add a new secret with name `OPENAI_API_KEY` and your key as the value
3. The edge function is already deployed. Once the secret is set, AI analysis will work automatically.

If the API key is not configured, the app still works fully — it shows rule-based analysis only and displays "AI analysis unavailable."

### 4. Run the development server

```bash
npm run dev
```

## How it works

1. **Rule-based analysis** — Detects urgency, sensitive information requests, money requests, fake prizes, threats, impersonation, and suspicious URLs (shorteners, lookalike domains, IP addresses, domain mismatches).
2. **AI contextual analysis** — Sends the message and rule-based findings to OpenAI (via a secure server-side edge function) for a contextual second opinion.
3. **Combined result** — Merges both layers conservatively: rule-based evidence is the foundation, AI adds context. False positives are prioritized over aggressive detection.

## Project structure

- `src/lib/scamAnalyzer.ts` — Rule-based detection engine
- `src/lib/urlAnalyzer.ts` — Static URL analysis module
- `src/lib/aiAnalysis.ts` — Frontend client for the AI edge function
- `src/lib/combinedResult.ts` — Merges rule-based and AI results
- `src/App.tsx` — Main UI
- `supabase/functions/ai-analyze/index.ts` — Server-side edge function that calls OpenAI
- `supabase/config.toml` — Supabase edge function configuration
