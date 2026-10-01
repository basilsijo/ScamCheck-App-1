# ScamCheck

Check suspicious messages before you click. ScamCheck uses a two-layer system: a rule-based detector for objective warning signs, plus an optional AI contextual analysis for deeper insight.

## Setup

### Run it

This project is a pnpm workspace, so use **pnpm** (not npm) and run the commands from the project root folder (the one with `pnpm-workspace.yaml`).

```bash
pnpm install --frozen-lockfile
pnpm --filter @workspace/scamcheck run dev
```

On Replit this just works. On your own computer the app opens on http://localhost:5173 (set `PORT` to change it).

To build for deployment:

```bash
pnpm --filter @workspace/scamcheck run build
```

The finished site is created in `artifacts/scamcheck/dist/public`.

### Run the tests

```bash
npx tsx artifacts/scamcheck/tests/runTests.ts
```

### Optional AI context analysis

The rule-based message and URL analysis works without external credentials. AI context analysis is optional and uses the Supabase Edge Function in `supabase/functions/ai-analyze`, which calls OpenAI server-side.

To enable it, configure `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` in the Replit Secrets/environment settings, and deploy the included Edge Function with `OPENAI_API_KEY` configured as a Supabase function secret. Never put the OpenAI key in frontend code.

If those values are missing or the function is unavailable, ScamCheck shows a short "AI unavailable" note and continues to show rule-based results. The technical error detail is only shown while developing.

The edge function accepts messages up to 3,000 characters. Also set a monthly spending limit in your OpenAI account, because the function is public.

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
