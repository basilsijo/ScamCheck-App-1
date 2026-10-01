import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Brain,
  Check,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Copy,
  ExternalLink,
  Info,
  Landmark,
  Link2,
  LockKeyhole,
  Menu,
  Moon,
  Phone,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  Sun,
  Trash2,
  X,
} from "lucide-react";
import {
  analyzeMessage,
  EXAMPLE_MESSAGES,
  type AnalysisResult,
  type RiskLevel,
  type SignalCategory,
} from "@/lib/scamAnalyzer";
import { extractUrls, getUrlDeduplicationKey, getVerifiedAlternatives, type UrlAnalysis, type CheckStatus } from "@/lib/urlAnalyzer";
import { fetchAiAnalysis, type AiAnalysis, type AiRisk } from "@/lib/aiAnalysis";
import { combineResults, type CombinedResult } from "@/lib/combinedResult";

const THEME_KEY = "scamcheck-theme";

function getInitialTheme(): "light" | "dark" {
  if (typeof window === "undefined") return "light";
  try {
    const saved = window.localStorage.getItem(THEME_KEY);
    if (saved === "dark" || saved === "light") return saved;
  } catch {
    // Continue with the system preference when storage is unavailable.
  }
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

const RISK_CONFIG: Record<RiskLevel, { label: string; icon: typeof Shield }> = {
  low: { label: "Low risk", icon: ShieldCheck },
  suspicious: { label: "Suspicious", icon: ShieldAlert },
  high: { label: "High risk", icon: ShieldX },
};

const AI_RISK_CONFIG: Record<AiRisk, { label: string; icon: typeof Shield }> = {
  LOW: { label: "Low risk", icon: ShieldCheck },
  SUSPICIOUS: { label: "Suspicious", icon: ShieldAlert },
  HIGH: { label: "High risk", icon: ShieldX },
};

const STATUS_CONFIG: Record<CheckStatus, { icon: typeof CircleCheck; className: string }> = {
  good: { icon: CircleCheck, className: "check-good" },
  warning: { icon: CircleAlert, className: "check-warning" },
  danger: { icon: ShieldAlert, className: "check-danger" },
};

const CATEGORY_LABELS: Record<SignalCategory, string> = {
  urgency: "Urgency",
  sensitive: "Sensitive information",
  money: "Money",
  prize: "Prize / reward",
  link: "Link risk",
  threat: "Threat / impersonation",
};

function ResultText(
  result: AnalysisResult,
  combined: CombinedResult | null,
  ai: AiAnalysis | null,
  message: string
): string {
  const riskToShow = combined?.combinedRisk ?? result.riskLevel;
  const lines: string[] = [];
  lines.push(`RISK RESULT: ${riskToShow.toUpperCase()}${combined && ai ? ` · ${combined.combinedConfidence}% confidence` : ""}`);
  lines.push(`Rule-based score: ${result.totalScore}`);
  lines.push("");
  lines.push("WHY THIS RESULT");
  lines.push(result.explanation);
  for (const signal of result.signals) {
    lines.push(`- ${signal.label} (${signal.points} points)`);
    if (signal.detail) lines.push(`   ${signal.detail}`);
  }
  if (result.combinations.length > 0) {
    lines.push("Signals appearing together:");
    for (const combination of result.combinations) lines.push(`- ${combination.label}`);
  }
  if (result.categories.length > 0) {
    lines.push("Categories:");
    for (const category of result.categories) lines.push(`- ${CATEGORY_LABELS[category.category]}: ${category.level.toUpperCase()} (${category.points} pts)`);
  }
  for (const linkAnalysis of result.linkAnalyses) {
    lines.push("URL CHECKS");
    lines.push(`Message URL (do not open): ${linkAnalysis.url}`);
    for (const check of linkAnalysis.checks) lines.push(`${check.status.toUpperCase()} ${check.label}: ${check.detail}`);
    lines.push(`Summary: ${linkAnalysis.summary}`);
  }
  if (ai) {
    lines.push("OPTIONAL AI CONTEXT");
    lines.push(`Risk: ${ai.risk}`);
    lines.push(`Confidence: ${ai.confidence}%`);
    if (ai.reasons.length > 0) lines.push(`Reasons:\n${ai.reasons.map((reason) => `- ${reason}`).join("\n")}`);
    if (ai.red_flags.length > 0) lines.push(`Red flags:\n${ai.red_flags.map((flag) => `- ${flag}`).join("\n")}`);
    if (combined?.note) lines.push(`Combined assessment: ${combined.note}`);
  }
  lines.push("");
  lines.push("SAFE ALTERNATIVE");
  const alternatives = getVerifiedAlternatives(message);
  const messageUrls = extractUrls(message);
  if (messageUrls.length > 0) lines.push(`Link found in message — avoid it: ${messageUrls.join(", ")}`);
  if (alternatives.length === 0) {
    lines.push("No verified official link is available. Do not use the message link; open the official app, manually navigate to a known official website, or contact the organization through a trusted channel.");
  } else {
    for (const alternative of alternatives) {
      lines.push(alternative.officialUrl
        ? `${alternative.organization} verified official website: ${alternative.officialUrl}`
        : `No verified official link is available for ${alternative.organization}. Manually navigate to its known official website or app.`);
    }
  }
  lines.push("");
  lines.push("WHAT TO DO NOW");
  if (result.advice.length > 0) {
    result.advice.forEach((advice, index) => lines.push(`${String(index + 1).padStart(2, "0")}. ${advice.text}`));
  } else {
    lines.push("1. Verify unexpected requests through an official app, website, or trusted contact route.");
  }
  if (ai?.advice.length) {
    lines.push("Optional AI suggestions:");
    for (const advice of ai.advice) lines.push(`- ${advice}`);
  }
  if (riskToShow === "high") {
    lines.push("Do not click the suspicious link or share OTPs, passwords, PINs, CVV, or banking details.");
    lines.push("If financial fraud has occurred, contact your bank and call the official cybercrime helpline at 1930 promptly.");
  }
  lines.push("");
  lines.push("REPORTING / HELP — Government of India");
  lines.push("Call 1930 · https://www.cybercrime.gov.in/ · https://cybercrime.gov.in/Webform/cyber_suspect.aspx");
  lines.push("ScamCheck does not submit reports on your behalf.");
  lines.push("");
  lines.push(result.disclaimer);
  return lines.join("\n");
}

function FallbackGuidance({ organization }: { organization?: string }) {
  return (
    <div className="fallback-box">
      <strong>No verified official link available{organization ? ` for ${organization}` : ""}.</strong>
      <ul className="fallback-list">
        <li>Do not use the link in the message.</li>
        <li>Open the organization’s official app if you already have it installed.</li>
        <li>Manually navigate to its official website or use a trusted support channel.</li>
      </ul>
    </div>
  );
}

function SafeAlternativeSection({ message }: { message: string }) {
  const alternatives = getVerifiedAlternatives(message);
  const urls = extractUrls(message);
  return (
    <section className="content-card safe-card" aria-labelledby="safe-alternative-heading" data-testid="section-safe-alternative">
      <div className="card-heading">
        <ShieldCheck size={21} aria-hidden="true" />
        <h2 id="safe-alternative-heading">Safe Alternative</h2>
      </div>
      {urls.length > 0 && (
        <div className="url-warning" data-testid="status-suspicious-links">
          <div className="url-warning-title"><AlertTriangle size={15} aria-hidden="true" /> Link found in the message · suspicious</div>
          <p>Avoid using this link. It is shown as text only and is not clickable.</p>
          {urls.map((url) => <p className="suspicious-url" key={url}>{url}</p>)}
        </div>
      )}
      {alternatives.length > 0 ? (
        <div className="plain-list">
          {alternatives.map((alternative) => (
            <div className="alternative-item" key={alternative.organization}>
              <p className="input-subtitle" style={{ marginBottom: 2 }}>This message appears to involve</p>
              <p className="alternative-org">{alternative.organization}</p>
              {alternative.officialUrl ? (
                <>
                  <div className="safe-tag"><BadgeCheck size={15} aria-hidden="true" /> Verified official alternative</div>
                  <a className="verified-link" href={alternative.officialUrl} target="_blank" rel="noopener noreferrer" data-testid={`link-verified-${alternative.organization.toLowerCase().replace(/\s+/g, "-")}`}>
                    {alternative.organization} official website <ExternalLink size={14} aria-hidden="true" />
                  </a>
                </>
              ) : <FallbackGuidance organization={alternative.organization} />}
            </div>
          ))}
        </div>
      ) : (
        <FallbackGuidance />
      )}
    </section>
  );
}

function LinkAnalysisCard({ analysis }: { analysis: UrlAnalysis }) {
  return (
    <section className="content-card" data-testid="card-link-analysis">
      <div className="card-heading"><Link2 size={21} aria-hidden="true" /><h2>Link analysis</h2></div>
      <div className="link-card-url">
        <small>Detected URL — not opened by ScamCheck</small>
        <p>{analysis.url}</p>
        <span>Root domain: <strong>{analysis.rootDomain}</strong></span>
      </div>
      <div className="plain-list">
        {analysis.checks.map((check) => {
          const config = STATUS_CONFIG[check.status];
          const StatusIcon = config.icon;
          return (
            <div className="check-row" key={check.id}>
              <StatusIcon className={`check-icon ${config.className}`} size={18} aria-hidden="true" />
              <div><strong>{check.label}</strong><p>{check.detail}</p></div>
            </div>
          );
        })}
      </div>
      <div className="info-note"><Info size={15} style={{ verticalAlign: "text-bottom", marginRight: 6 }} aria-hidden="true" />{analysis.summary}</div>
    </section>
  );
}

function AiAnalysisCard({ ai, error, combined, onRetry }: { ai: AiAnalysis | null; error: string | null; combined: CombinedResult | null; onRetry: () => void }) {
  if (error && !ai) {
    return (
      <section className="content-card ai-unavailable" data-testid="status-ai-unavailable">
        <div className="card-heading"><Brain size={21} aria-hidden="true" /><h2>Optional AI context</h2></div>
        <p>AI analysis is temporarily unavailable. Your local rule-based result is complete and remains available.</p>
        {import.meta.env.DEV ? <p className="ai-error-detail" role="status" data-testid="text-ai-error-detail">{error}</p> : null}
        <button className="secondary-button ai-retry" type="button" onClick={onRetry} data-testid="button-retry-ai-context"><RotateCcw size={15} aria-hidden="true" /> Retry AI context</button>
      </section>
    );
  }
  if (!ai) return null;
  const aiConfig = AI_RISK_CONFIG[ai.risk];
  const AssessmentIcon = aiConfig.icon;
  return (
    <section className="content-card" data-testid="card-ai-analysis">
      <div className="card-heading"><Brain size={21} aria-hidden="true" /><h2>AI context analysis</h2></div>
      <div className="ai-banner">
        <div><strong><AssessmentIcon size={16} style={{ verticalAlign: "text-bottom", marginRight: 5 }} aria-hidden="true" />{aiConfig.label}</strong><p>Optional AI assessment</p></div>
        <div className="ai-confidence">{ai.confidence}%<p>Confidence</p></div>
      </div>
      {combined?.note && <div className="info-note"><Info size={15} style={{ verticalAlign: "text-bottom", marginRight: 6 }} aria-hidden="true" />{combined.note}</div>}
      <div className="ai-result-section">
        <h3>Reasons</h3>
        {ai.reasons.length > 0 ? <ul className="sub-list">{ai.reasons.map((reason, index) => <li key={`reason-${index}`}><ChevronRight size={15} />{reason}</li>)}</ul> : <p className="ai-empty-list">No reasons provided.</p>}
      </div>
      <div className="ai-result-section">
        <h3>Red flags</h3>
        {ai.red_flags.length > 0 ? <ul className="sub-list">{ai.red_flags.map((flag, index) => <li className="flag-item" key={`flag-${index}`}><AlertTriangle size={15} />{flag}</li>)}</ul> : <p className="ai-empty-list">No red flags reported.</p>}
      </div>
      <div className="ai-result-section">
        <h3>Advice</h3>
        {ai.advice.length > 0 ? <ul className="sub-list">{ai.advice.map((advice, index) => <li key={`advice-${index}`}><ChevronRight size={15} />{advice}</li>)}</ul> : <p className="ai-empty-list">No specific advice returned.</p>}
      </div>
    </section>
  );
}

function ActionChecklist({ result, risk, aiAdvice }: { result: AnalysisResult; risk: RiskLevel; aiAdvice: string[] }) {
  const actions = result.advice.map((item) => item.text);
  if (actions.length === 0) actions.push("Verify unexpected requests through an official app, website, or trusted contact route.");
  for (const advice of aiAdvice) if (!actions.includes(advice)) actions.push(advice);
  if (risk === "high") {
    actions.unshift("Do not click the suspicious link or reply to the message.");
    actions.push("Do not share an OTP, password, PIN, CVV, or banking details.");
    actions.push("If financial fraud has occurred, contact your bank and call 1930 promptly.");
  }
  return (
    <section className={`content-card action-card${risk === "high" ? " action-card-high" : ""}`} aria-labelledby="what-now-heading" data-testid="section-what-to-do">
      <div className="card-heading"><Check size={20} aria-hidden="true" /><div><div className="section-kicker">A practical next step</div><h2 id="what-now-heading">What to do now</h2></div></div>
      <ol className="action-steps">{actions.map((action, index) => <li key={`${index}-${action}`}><span className="action-number">{String(index + 1).padStart(2, "0")}</span><span>{action}</span></li>)}</ol>
      <p className="action-note">These are suggestions for you to take; ScamCheck cannot perform these actions.</p>
    </section>
  );
}

function HelpSection() {
  return (
    <section className="help-section scroll-reveal" id="help" aria-labelledby="help-heading" data-testid="section-cybercrime-help" data-scroll-reveal>
      <div className="page-wrap">
        <div className="section-heading">
          <div><div className="section-kicker">Support, when you need it</div><h2 id="help-heading">Need help or want to report it?</h2></div>
          <p>Use official Government of India cybercrime channels for guidance and reporting. ScamCheck does not submit a complaint for you.</p>
        </div>
        <div className="help-grid">
          <div className="content-card help-card">
            <div className="help-card-title"><Landmark size={20} aria-hidden="true" /> Official reporting portals</div>
            <p>These Government of India portals can help you report cybercrime or suspicious identifiers, including links and contact details.</p>
            <div className="help-actions">
              <a className="help-link" href="https://www.cybercrime.gov.in/" target="_blank" rel="noopener noreferrer" data-testid="link-report-cybercrime"><ExternalLink size={16} aria-hidden="true" /> Report cybercrime online</a>
              <a className="help-link" href="https://cybercrime.gov.in/Webform/cyber_suspect.aspx" target="_blank" rel="noopener noreferrer" data-testid="link-report-suspicious"><ExternalLink size={16} aria-hidden="true" /> Report a suspicious link</a>
            </div>
            <div className="goi-note"><Landmark size={14} aria-hidden="true" />External links open the official Government of India cybercrime portal in a new tab. ScamCheck does not send or file your report.</div>
          </div>
          <div className="content-card help-card helpline-card">
            <div>
              <div className="help-card-title"><Phone size={20} aria-hidden="true" /> National Cyber Crime Helpline</div>
              <div className="phone-number">1930</div>
              <p>For immediate cyber financial fraud, call 1930 and report the incident promptly.</p>
            </div>
            <a className="help-link" href="tel:1930" data-testid="link-call-1930"><Phone size={16} aria-hidden="true" /> Call 1930</a>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function App() {
  const [text, setText] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<AiAnalysis | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [combined, setCombined] = useState<CombinedResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [showExamples, setShowExamples] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [theme, setTheme] = useState<"light" | "dark">(getInitialTheme);
  // Counts analysis runs so a slow, older AI answer can never overwrite a newer result.
  const requestIdRef = useRef(0);

  useEffect(() => {
    const sections = document.querySelectorAll<HTMLElement>("[data-scroll-reveal]");
    const showAll = () => sections.forEach((section) => section.classList.add("is-visible"));
    if ((typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches) || !("IntersectionObserver" in window)) {
      showAll();
      return;
    }

    const observer = new IntersectionObserver((entries, currentObserver) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          currentObserver.unobserve(entry.target);
        }
      }
    }, { threshold: 0.12, rootMargin: "0px 0px -24px 0px" });

    sections.forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, [result]);

  const toggleTheme = () => {
    const nextTheme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    try {
      window.localStorage.setItem(THEME_KEY, nextTheme);
    } catch {
      // The current session still changes themes if storage is unavailable.
    }
    document.documentElement.classList.toggle("dark", nextTheme === "dark");
    document.documentElement.dataset.theme = nextTheme;
  };

  const runAnalysis = async (messageText: string) => {
    const requestId = ++requestIdRef.current;
    const ruleResult = analyzeMessage(messageText);
    setResult(ruleResult);
    setAiAnalysis(null);
    setAiError(null);
    setCombined(null);
    setAiLoading(true);
    try {
      const { analysis, error } = await fetchAiAnalysis(messageText, ruleResult);
      if (requestId !== requestIdRef.current) return; // a newer analysis started or the form was cleared
      if (analysis) {
        setAiAnalysis(analysis);
        setCombined(combineResults(ruleResult.riskLevel, ruleResult.totalScore, analysis.risk, analysis.confidence));
      } else {
        setAiError(error ?? "The AI function returned no analysis. Your rule-based result is complete.");
      }
    } catch (err) {
      if (requestId !== requestIdRef.current) return;
      setAiError(err instanceof Error ? err.message : "An unexpected error occurred during AI analysis. Your rule-based result is complete.");
    } finally {
      if (requestId === requestIdRef.current) setAiLoading(false);
    }
  };

  const handleCheck = () => {
    if (!text.trim() || aiLoading) return;
    void runAnalysis(text);
  };

  const handleClear = () => {
    requestIdRef.current += 1; // ignore any AI answer that is still on its way
    setAiLoading(false);
    setText("");
    setResult(null);
    setAiAnalysis(null);
    setAiError(null);
    setCombined(null);
    setCopied(false);
  };

  const handleTryAnother = () => {
    requestIdRef.current += 1;
    setAiLoading(false);
    setResult(null);
    setAiAnalysis(null);
    setAiError(null);
    setCombined(null);
    setCopied(false);
    document.getElementById("message-input")?.focus();
    const reduceMotion = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    document.getElementById("analyze")?.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
  };

  const handleCopy = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(ResultText(result, combined, aiAnalysis, text));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2200);
    } catch {
      setCopied(false);
    }
  };

  const handleExample = (exampleText: string) => {
    setText(exampleText);
    setShowExamples(false);
    void runAnalysis(exampleText);
  };

  const displayedRisk: RiskLevel = combined?.combinedRisk ?? result?.riskLevel ?? "low";
  const riskConfig = result ? RISK_CONFIG[displayedRisk] : null;
  const RiskIcon = riskConfig?.icon;
  const messageSignals = result
    ? result.signals.filter((signal) => signal.category !== "link" || !result.linkAnalyses.some((analysis) => analysis.signals.some((urlSignal) => urlSignal.id === signal.id)))
    : [];
  const linkAnalysisCards = result
    ? result.linkAnalyses.filter((analysis, index, analyses) => analyses.findIndex(
      (candidate) => getUrlDeduplicationKey(candidate.url) === getUrlDeduplicationKey(analysis.url)
    ) === index)
    : [];
  const wordCount = text.trim() ? text.trim().split(/\s+/).length : 0;

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="topbar">
        <div className="topbar-inner">
          <a className="brand" href="#top" aria-label="ScamCheck home">
            <span className="brand-mark"><Shield size={22} strokeWidth={2.2} aria-hidden="true" /></span>
            <span><span className="brand-name">ScamCheck</span><span className="brand-caption">A pause before you act</span></span>
          </a>
          <nav id="main-navigation" className={`main-nav${mobileMenuOpen ? " is-open" : ""}`} aria-label="Main navigation">
            <a href="#how-it-works" onClick={() => setMobileMenuOpen(false)} data-testid="nav-how-it-works">How it works</a>
            <a href="#safety" onClick={() => setMobileMenuOpen(false)} data-testid="nav-safety">Safety tips</a>
            <a href="#help" onClick={() => setMobileMenuOpen(false)} data-testid="nav-help">Get help</a>
          </nav>
          <div className="top-actions">
            <button className="icon-button mobile-menu-toggle" type="button" onClick={() => setMobileMenuOpen((open) => !open)} aria-label={mobileMenuOpen ? "Close navigation menu" : "Open navigation menu"} aria-expanded={mobileMenuOpen} aria-controls="main-navigation" data-testid="button-mobile-menu">
              {mobileMenuOpen ? <X size={18} aria-hidden="true" /> : <Menu size={18} aria-hidden="true" />}
            </button>
            <button className="icon-button" type="button" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} data-testid="button-theme-toggle">
              {theme === "dark" ? <Sun size={18} aria-hidden="true" /> : <Moon size={18} aria-hidden="true" />}
            </button>
            <a className="primary-button" href="#analyze" aria-label="Analyze a message" data-testid="nav-analyze"><ShieldCheck size={16} aria-hidden="true" /> Analyze</a>
          </div>
        </div>
      </header>

      <main id="main-content">
        <div id="top" className="page-wrap">
          <section className="hero" aria-labelledby="hero-title">
            <div className="hero-copy">
              <div className="eyebrow"><span className="eyebrow-dot" /> Take a moment. Check first.</div>
              <h1 id="hero-title">Check before <span>you click.</span></h1>
              <p className="hero-lede">Paste an unexpected message, email, or URL. See the evidence, then choose a safer next step.</p>
              <div className="hero-note"><LockKeyhole size={15} aria-hidden="true" /> Your message is analyzed in this session. Don’t include private credentials.</div>
            </div>
            <div className="hero-mark" aria-hidden="true"><span><ShieldCheck size={27} /></span><p>Pause.<br />Check.<br />Choose safely.</p></div>
          </section>

          <section className="analysis-card reveal" id="analyze" aria-labelledby="analysis-heading">
            <div className="section-kicker">Start with the message</div>
            <h2 id="analysis-heading">What would you like to check?</h2>
            <p className="input-subtitle">Paste the message or URL as it appeared. We’ll point out patterns to consider—not make a guarantee.</p>
            <label htmlFor="message-input" className="section-kicker" style={{ display: "block", color: "hsl(var(--muted))", letterSpacing: ".035em", textTransform: "none", marginBottom: 8 }}>Message, email, or link</label>
            <textarea
              id="message-input"
              className="message-input"
              value={text}
              onChange={(event) => setText(event.target.value)}
              onKeyDown={(event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") handleCheck(); }}
              placeholder="Paste the full text here…"
              rows={6}
              maxLength={3000}
              aria-describedby="input-hint"
              data-testid="input-message"
            />
            <div className="input-meta" id="input-hint"><span>Don’t paste OTPs, passwords or card numbers. If AI analysis is on, your text is sent to an AI service (OpenAI). Max 3,000 characters.</span><span>{wordCount} {wordCount === 1 ? "word" : "words"}</span></div>
            <div className="input-actions">
              <button className="primary-button" type="button" onClick={handleCheck} disabled={!text.trim() || aiLoading} data-testid="button-check-message">
                <ShieldCheck size={18} aria-hidden="true" /> Analyze with ScamCheck <ArrowRight size={16} aria-hidden="true" />
              </button>
              <button className="secondary-button" type="button" onClick={() => setShowExamples((visible) => !visible)} aria-expanded={showExamples} aria-controls="example-panel" data-testid="button-toggle-examples">
                <Sparkles size={16} aria-hidden="true" /> {showExamples ? "Hide examples" : "Try an example"}
              </button>
            </div>
            {showExamples && (
              <div className="example-panel" id="example-panel">
                <p className="example-heading">Choose a sample message to explore the result:</p>
                <div className="example-list">
                  {EXAMPLE_MESSAGES.map((example, index) => (
                    <button type="button" key={example.label} className="example-item" onClick={() => handleExample(example.text)} data-testid={`button-example-${index}`}>
                      {example.label}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {aiLoading && (
              <div className="loading-panel" role="status" aria-live="polite" data-testid="status-analysis-loading">
                <div className="loading-orbit"><ShieldCheck size={23} aria-hidden="true" /></div>
                <div><strong>Your local rule-based result is ready</strong><p>Optional AI context is still pending. You can review the available findings below.</p></div>
              </div>
            )}
          </section>

          {result && riskConfig && RiskIcon && (
            <section className={`results risk-${displayedRisk} reveal`} aria-label="Analysis results" data-testid="section-analysis-results">
              <div className="result-banner" role="status" aria-live="polite" data-testid="status-risk-result">
                <div className="risk-mark"><RiskIcon size={29} strokeWidth={2.1} aria-hidden="true" /></div>
                <div>
                  <div className="risk-heading">{riskConfig.label}{aiAnalysis && combined && combined.combinedConfidence > 0 ? <span className="confidence-label"> · {combined.combinedConfidence}% combined confidence</span> : <span className="confidence-label"> · {aiAnalysis ? "Optional AI context included" : "Rule-based assessment"}</span>}</div>
                  <p className="risk-copy">{result.signals.length === 0 ? "No warning signs were detected by the current rules. Still verify unexpected requests through a trusted channel." : `${result.signals.length} warning signal${result.signals.length === 1 ? "" : "s"} found · rule-based score ${result.totalScore}.`}</p>
                  {combined?.aiRisk && <p className="risk-meta">Rule-based: {combined.ruleRisk.toUpperCase()} · AI: {combined.aiRisk} · Combined: {combined.combinedRisk.toUpperCase()}</p>}
                </div>
                <div className="result-actions">
                  <button className="icon-button" type="button" onClick={() => void handleCopy()} aria-label="Copy full analysis report" title="Copy report" data-testid="button-copy-report"><Copy size={17} aria-hidden="true" /></button>
                </div>
              </div>

              <section className="content-card why-card" aria-labelledby="why-heading">
                <div className="card-heading"><Info size={20} aria-hidden="true" /><div><div className="section-kicker">Evidence from this message</div><h2 id="why-heading">Why this result</h2></div></div>
                <p className="explanation-copy">{result.explanation}</p>
                {messageSignals.length > 0 && <div className="why-subsection">
                  <h3>Rule-based signals</h3>
                  <ul className="plain-list">{messageSignals.map((signal) => <li className="signal-row" key={signal.id}><span className="signal-marker"><CircleAlert size={15} aria-hidden="true" /></span><div><strong>{signal.label}</strong><span className="signal-points">{signal.points} {signal.points === 1 ? "point" : "points"}</span>{signal.detail && <p>{signal.detail}</p>}</div></li>)}</ul>
                </div>}
                {result.combinations.length > 0 && <div className="why-subsection">
                  <h3>Signals that appear together</h3>
                  <ul className="plain-list">{result.combinations.map((combination) => <li className="signal-row" key={combination.id}><span className="signal-marker"><AlertTriangle size={15} aria-hidden="true" /></span><div><strong>{combination.label}</strong><p>Combined rule bonus: {combination.bonus} points</p></div></li>)}</ul>
                </div>}
                {result.categories.length > 0 && <div className="why-subsection">
                  <h3>Risk categories</h3>
                  <div className="factor-grid">{result.categories.map((category) => <div className="factor-row" key={category.category}><span>{CATEGORY_LABELS[category.category]} · {category.points} pts</span><span className={`factor-pill factor-${category.level}`}>{category.level}</span></div>)}</div>
                </div>}
                {linkAnalysisCards.map((analysis) => <LinkAnalysisCard key={getUrlDeduplicationKey(analysis.url)} analysis={analysis} />)}
                {aiLoading ? <div className="ai-pending" role="status" aria-live="polite" data-testid="status-ai-loading"><Brain size={17} aria-hidden="true" /><span><strong>Optional AI context pending</strong><small>Your local rule-based result is ready and available above.</small></span></div> : null}
                {!aiLoading && (aiAnalysis || aiError) ? <AiAnalysisCard ai={aiAnalysis} error={aiError} combined={combined} onRetry={() => void runAnalysis(text)} /> : null}
              </section>

              <SafeAlternativeSection message={text} />
              <ActionChecklist result={result} risk={displayedRisk} aiAdvice={aiAnalysis?.advice ?? []} />
              <HelpSection />

              <div className="disclaimer" data-testid="text-analysis-disclaimer">{result.disclaimer} ScamCheck provides informational analysis and does not replace official law-enforcement or financial-institution advice.</div>
              <div className="result-toolbar">
                <div>
                  <button className="secondary-button" type="button" onClick={() => void handleCopy()} data-testid="button-copy-report-full">{copied ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}{copied ? "Report copied" : "Copy full report"}</button>
                  <button className="secondary-button" type="button" onClick={handleTryAnother} data-testid="button-try-another"><RotateCcw size={16} aria-hidden="true" /> Check another</button>
                </div>
                <button className="quiet-button" type="button" onClick={handleClear} data-testid="button-clear"><Trash2 size={15} aria-hidden="true" /> Clear message</button>
              </div>
            </section>
          )}
        </div>

        <section className="how-section page-wrap scroll-reveal" id="how-it-works" aria-labelledby="how-heading" data-scroll-reveal>
              <div className="how-intro">
                <div className="section-kicker">A clear, simple process</div>
                <h2 id="how-heading">Understand the clues. Choose your next step.</h2>
                <p>ScamCheck helps make an unsettling message easier to think through—without making the decision for you.</p>
              </div>
              <div className="steps-list">
                <div className="how-step"><span className="step-number">01</span><div><strong>Paste what arrived</strong><p>Share an SMS, email excerpt or link that you want to look at more carefully.</p></div></div>
                <div className="how-step"><span className="step-number">02</span><div><strong>See the warning signs</strong><p>Rule-based patterns and URL structure are summarized in everyday language.</p></div></div>
                <div className="how-step"><span className="step-number">03</span><div><strong>Verify through a trusted route</strong><p>Use a verified alternative when one is available, or navigate manually to the organization.</p></div></div>
              </div>
        </section>
        <section className="safety-section page-wrap scroll-reveal" id="safety" aria-labelledby="safety-heading" data-scroll-reveal>
              <div className="safety-card">
                <div className="section-kicker">A small pause helps</div>
                <h2 id="safety-heading">Keep control of the conversation.</h2>
                <p>Scammers often create pressure. Take time to verify requests independently, especially before sharing account details or sending money.</p>
                <div className="safety-points">
                  <span className="safety-point"><LockKeyhole size={15} aria-hidden="true" /> Never share OTPs or passwords</span>
                  <span className="safety-point"><Link2 size={15} aria-hidden="true" /> Avoid unexpected message links</span>
                  <span className="safety-point"><Phone size={15} aria-hidden="true" /> Verify through a trusted contact route</span>
                </div>
              </div>
        </section>
        {!result && <HelpSection />}
      </main>

      <footer className="footer">
        <div className="page-wrap">
          <div className="footer-inner scroll-reveal" data-scroll-reveal>
            <div className="footer-brand">
              <a className="brand" href="#top"><span className="brand-mark"><Shield size={19} aria-hidden="true" /></span><span className="brand-name">ScamCheck</span></a>
              <p>Understand suspicious messages before you act.</p>
            </div>
            <div className="footer-group"><h3>Product</h3><div className="footer-links"><a href="#analyze">Analyze</a><a href="#how-it-works">How it works</a><a href="#safety">Safety tips</a></div></div>
            <div className="footer-group"><h3>Help</h3><div className="footer-links"><a href="https://www.cybercrime.gov.in/" target="_blank" rel="noopener noreferrer">Report Cybercrime</a><a href="tel:1930">Cybercrime Helpline: 1930</a><a href="https://cybercrime.gov.in/Webform/cyber_suspect.aspx" target="_blank" rel="noopener noreferrer">Official Reporting Portal</a></div></div>
            <div className="footer-group"><h3>Security</h3><div className="footer-links"><a href="#safety">Safe browsing</a><a href="#safety">Phishing awareness</a><a href="#privacy-note">Privacy & limits</a></div></div>
          </div>
          <div className="footer-note" id="privacy-note"><p>ScamCheck provides informational analysis and does not replace official law-enforcement or financial-institution advice. It cannot guarantee that a message is safe or fraudulent. The rule-based check runs in your browser. When the optional AI analysis is turned on, the message text is sent to OpenAI to produce the second opinion, and ScamCheck does not store it. ScamCheck does not submit complaints on your behalf.</p></div>
        </div>
      </footer>
    </div>
  );
}