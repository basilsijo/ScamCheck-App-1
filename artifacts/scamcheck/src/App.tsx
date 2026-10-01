import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Check,
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
  analyzeUrl,
  extractUrls,
  getUrlDeduplicationKey,
  getVerifiedAlternatives,
  getVerifiedAlternativesForUrl,
  normalizeWebsiteUrlInput,
  type CheckStatus,
  type UrlAnalysis,
} from "@/lib/urlAnalyzer";
import {
  analyzeMessage,
  EXAMPLE_MESSAGES,
  type AnalysisResult,
  type RiskLevel,
  type SignalCategory,
} from "@/lib/scamAnalyzer";
import {
  findUserSubmittedIndianPhoneReport,
  normalizeIndianMobileNumber,
} from "@/lib/phoneNumberAnalyzer";
import {
  SYNTHETIC_PHONE_REPORT_DEMO,
  type UserSubmittedIndianPhoneReport,
} from "@/lib/indiaScamNumbers";

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
  message: string
): string {
  const lines: string[] = [];
  lines.push(`RISK RESULT: ${result.riskLevel.toUpperCase()}`);
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
  if (result.riskLevel === "high") {
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

function SafeAlternativeSection({ message, website = false }: { message: string; website?: boolean }) {
  const alternatives = website
    ? getVerifiedAlternativesForUrl(message)
    : getVerifiedAlternatives(message);
  const urls = extractUrls(message);
  return (
    <section className="content-card safe-card" aria-labelledby="safe-alternative-heading" data-testid="section-safe-alternative">
      <div className="card-heading">
        <ShieldCheck size={21} aria-hidden="true" />
        <h2 id="safe-alternative-heading">Safe Alternative</h2>
      </div>
      {urls.length > 0 && (
        <div className="url-warning" data-testid="status-suspicious-links">
          <div className="url-warning-title"><AlertTriangle size={15} aria-hidden="true" />{website ? "Website address checked locally" : "Link found in the message · suspicious"}</div>
          <p>{website ? "This address is shown as text only. ScamCheck did not open or fetch it." : "Avoid using this link. It is shown as text only and is not clickable."}</p>
          {urls.map((url) => <p className="suspicious-url" key={url}>{url}</p>)}
        </div>
      )}
      {alternatives.length > 0 ? (
        <div className="plain-list">
          {alternatives.map((alternative) => (
            <div className="alternative-item" key={alternative.organization}>
              <p className="input-subtitle" style={{ marginBottom: 2 }}>{website ? "This address appears to involve" : "This message appears to involve"}</p>
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

function ActionChecklist({ result, risk }: { result: AnalysisResult; risk: RiskLevel }) {
  const actions = result.advice.map((item) => item.text);
  if (actions.length === 0) actions.push("Verify unexpected requests through an official app, website, or trusted contact route.");
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

type CheckMode = "phone" | "message" | "website";

function phoneResultText(number: string, matched: UserSubmittedIndianPhoneReport | undefined, invalid: boolean): string {
  if (invalid) return `PHONE NUMBER CHECK\nThe entered value is not a plausible Indian mobile number. No lookup was performed.`;
  if (matched) return `PHONE NUMBER CHECK\nNumber checked: ${number}\nStatus: This number appears in a user-submitted, unverified report list.\nSource: ${matched.source}\nImport date: ${matched.importDate}\nA match is not proof of wrongdoing and does not determine who uses the number.`;
  return `PHONE NUMBER CHECK\nNumber checked: ${number}\nStatus: Not found in the user-submitted, unverified report list.\nAbsence from this list does not mean the number is safe.\nThe number was checked only in this browser and was not transmitted.`;
}

function websiteRisk(analysis: UrlAnalysis): RiskLevel {
  const score = analysis.signals.reduce((total, signal) => total + signal.points, 0);
  return score >= 9 ? "high" : score >= 3 ? "suspicious" : "low";
}

export default function App() {
  const [mode, setMode] = useState<CheckMode>("message");
  const [text, setText] = useState("");
  const [messageResult, setMessageResult] = useState<AnalysisResult | null>(null);
  const [websiteResult, setWebsiteResult] = useState<UrlAnalysis | null>(null);
  const [phoneResult, setPhoneResult] = useState<{ number: string; report?: UserSubmittedIndianPhoneReport; invalid: boolean } | null>(null);
  const [phoneDemo, setPhoneDemo] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showExamples, setShowExamples] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [theme, setTheme] = useState<"light" | "dark">(getInitialTheme);

  useEffect(() => {
    const sections = document.querySelectorAll<HTMLElement>("[data-scroll-reveal]");
    const showAll = () => sections.forEach((section) => section.classList.add("is-visible"));
    if ((typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches) || !("IntersectionObserver" in window)) {
      showAll();
      return;
    }
    const observer = new IntersectionObserver((entries, currentObserver) => {
      for (const entry of entries) if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        currentObserver.unobserve(entry.target);
      }
    }, { threshold: 0.12, rootMargin: "0px 0px -24px 0px" });
    sections.forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, [mode, messageResult, websiteResult, phoneResult]);

  const clearResults = () => {
    setMessageResult(null);
    setWebsiteResult(null);
    setPhoneResult(null);
    setPhoneDemo(false);
    setCopied(false);
  };
  const changeMode = (next: CheckMode) => {
    if (next === mode) return;
    setMode(next);
    setText("");
    setShowExamples(false);
    clearResults();
  };
  const toggleTheme = () => {
    const nextTheme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    try { window.localStorage.setItem(THEME_KEY, nextTheme); } catch { /* Session theme still updates. */ }
    document.documentElement.classList.toggle("dark", nextTheme === "dark");
    document.documentElement.dataset.theme = nextTheme;
  };
  const handleCheck = () => {
    clearResults();
    if (mode === "message") {
      if (text.trim()) setMessageResult(analyzeMessage(text));
      return;
    }
    if (mode === "website") {
      const websiteUrl = normalizeWebsiteUrlInput(text);
      if (websiteUrl) setWebsiteResult(analyzeUrl(websiteUrl, websiteUrl));
      return;
    }
    const normalized = normalizeIndianMobileNumber(text);
    const invalid = normalized === null;
    const report = normalized ? findUserSubmittedIndianPhoneReport(normalized) : undefined;
    setPhoneResult({ number: normalized ?? "", report, invalid });
  };
  const handleClear = () => { setText(""); clearResults(); };
  const handleTryAnother = () => {
    setText("");
    clearResults();
    const inputId = mode === "phone" ? "phone-input" : mode === "website" ? "website-input" : "message-input";
    document.getElementById(inputId)?.focus();
    const reduceMotion = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    document.getElementById("analyze")?.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
  };
  const handleCopy = async () => {
    let report = "";
    if (mode === "message" && messageResult) report = ResultText(messageResult, text);
    if (mode === "website" && websiteResult) {
      const alternatives = getVerifiedAlternativesForUrl(websiteResult.url);
      report = [
        `WEBSITE CHECK\nRisk result: ${websiteRisk(websiteResult).toUpperCase()}`,
        `URL checked (not opened): ${websiteResult.url}`,
        `Summary: ${websiteResult.summary}`,
        ...websiteResult.checks.map((check) => `${check.status.toUpperCase()} ${check.label}: ${check.detail}`),
        "SAFE ALTERNATIVE",
        ...(alternatives.length ? alternatives.map((item) => item.officialUrl
          ? `${item.organization} verified official website: ${item.officialUrl}`
          : `No verified official link is available for ${item.organization}. Use its official app or a trusted channel.`)
          : ["No organization-specific verified alternative was identified. Use the official app or manually navigate to a known official website or trusted support channel."]),
      ].join("\n");
    }
    if (mode === "phone" && phoneResult) report = phoneResultText(phoneResult.number, phoneResult.report, phoneResult.invalid);
    if (mode === "phone" && phoneDemo) {
      report = [
        "PHONE NUMBER CHECK — SYNTHETIC DEMO ONLY",
        `Placeholder: ${SYNTHETIC_PHONE_REPORT_DEMO.number} (invalid as an Indian mobile number)`,
        `Source: ${SYNTHETIC_PHONE_REPORT_DEMO.source}`,
        `Report date: ${SYNTHETIC_PHONE_REPORT_DEMO.reportDate}`,
        "This is not a real report, does not identify a person, and is not in the user-submitted lookup list.",
      ].join("\n");
    }
    if (!report) return;
    try {
      await navigator.clipboard.writeText(report);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2200);
    } catch { setCopied(false); }
  };
  const handleExample = (exampleText: string) => {
    setText(exampleText);
    setShowExamples(false);
    setMessageResult(analyzeMessage(exampleText));
    setWebsiteResult(null);
    setPhoneResult(null);
  };
  const currentRisk = messageResult?.riskLevel ?? (websiteResult ? websiteRisk(websiteResult) : null);
  const riskConfig = currentRisk ? RISK_CONFIG[currentRisk] : null;
  const RiskIcon = riskConfig?.icon;
  const messageSignals = messageResult
    ? messageResult.signals.filter((signal) => signal.category !== "link" || !messageResult.linkAnalyses.some((analysis) => analysis.signals.some((urlSignal) => urlSignal.id === signal.id)))
    : [];
  const linkAnalysisCards = messageResult
    ? messageResult.linkAnalyses.filter((analysis, index, analyses) => analyses.findIndex(
      (candidate) => getUrlDeduplicationKey(candidate.url) === getUrlDeduplicationKey(analysis.url)
    ) === index)
    : [];
  const activeResult = !!messageResult || !!websiteResult || !!phoneResult || phoneDemo;
  const modeTitles: Record<CheckMode, string> = { phone: "Phone Number", message: "SMS / Message", website: "Website" };
  const alternatives = websiteResult ? getVerifiedAlternativesForUrl(websiteResult.url) : [];
  const selectedInputId = `${mode}-input`;
  const wordCount = text.trim() ? text.trim().split(/\s+/).length : 0;

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="topbar">
        <div className="topbar-inner">
          <a className="brand" href="#top" aria-label="ScamCheck home"><span className="brand-mark"><Shield size={22} strokeWidth={2.2} aria-hidden="true" /></span><span><span className="brand-name">ScamCheck</span><span className="brand-caption">A pause before you act</span></span></a>
          <nav id="main-navigation" className={`main-nav${mobileMenuOpen ? " is-open" : ""}`} aria-label="Main navigation">
            <a href="#how-it-works" onClick={() => setMobileMenuOpen(false)} data-testid="nav-how-it-works">How it works</a><a href="#safety" onClick={() => setMobileMenuOpen(false)} data-testid="nav-safety">Safety tips</a><a href="#help" onClick={() => setMobileMenuOpen(false)} data-testid="nav-help">Get help</a>
          </nav>
          <div className="top-actions">
            <button className="icon-button mobile-menu-toggle" type="button" onClick={() => setMobileMenuOpen((open) => !open)} aria-label={mobileMenuOpen ? "Close navigation menu" : "Open navigation menu"} aria-expanded={mobileMenuOpen} aria-controls="main-navigation" data-testid="button-mobile-menu">{mobileMenuOpen ? <X size={18} aria-hidden="true" /> : <Menu size={18} aria-hidden="true" />}</button>
            <button className="icon-button" type="button" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} data-testid="button-theme-toggle">{theme === "dark" ? <Sun size={18} aria-hidden="true" /> : <Moon size={18} aria-hidden="true" />}</button>
            <a className="primary-button" href="#analyze" aria-label="Start a check" data-testid="nav-analyze"><ShieldCheck size={16} aria-hidden="true" /> Check</a>
          </div>
        </div>
      </header>
      <main id="main-content">
        <div id="top" className="page-wrap">
          <section className="hero" aria-labelledby="hero-title">
            <div className="hero-copy">
              <div className="eyebrow"><span className="eyebrow-dot" /> Take a moment. Check first.</div>
              <h1 id="hero-title">Check before <span>you click.</span></h1>
              <p className="hero-lede">Check suspicious phone numbers, messages, and websites with evidence kept on your device.</p>
              <div className="hero-note"><LockKeyhole size={15} aria-hidden="true" /> Phone numbers are checked locally and never sent to an outside service.</div>
            </div>
            <div className="hero-mark" aria-hidden="true"><span><ShieldCheck size={27} /></span><p>Pause.<br />Check.<br />Choose safely.</p></div>
          </section>
          <section className="analysis-card reveal" id="analyze" aria-labelledby="analysis-heading">
            <div className="section-kicker">Local-first checks</div>
            <h2 id="analysis-heading">What would you like to check?</h2>
            <p className="input-subtitle">Choose a check type. Each result stays separate when you switch modes.</p>
            <div className="mode-switch" role="group" aria-label="Check type">
              {(["phone", "message", "website"] as CheckMode[]).map((item) => (
                <button key={item} type="button" className={`mode-button${mode === item ? " is-active" : ""}`} aria-pressed={mode === item} onClick={() => changeMode(item)} data-testid={`button-mode-${item}`}>
                  {item === "phone" ? <Phone size={17} aria-hidden="true" /> : item === "website" ? <Link2 size={17} aria-hidden="true" /> : <ShieldCheck size={17} aria-hidden="true" />}{modeTitles[item]}
                </button>
              ))}
            </div>
            <label htmlFor={selectedInputId} className="section-kicker input-label">
              {mode === "phone" ? "Indian mobile number" : mode === "website" ? "Website address" : "Message or SMS"}
            </label>
            {mode === "phone" ? (
              <input id="phone-input" className="message-input single-line-input" type="tel" inputMode="tel" autoComplete="off" value={text} onChange={(event) => setText(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") handleCheck(); }} placeholder="+91 98765 43210" aria-describedby="input-hint" data-testid="input-phone" />
            ) : mode === "website" ? (
              <input id="website-input" className="message-input single-line-input" type="text" inputMode="url" autoComplete="off" value={text} onChange={(event) => setText(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") handleCheck(); }} placeholder="https://example.com" aria-describedby="input-hint" data-testid="input-website" />
            ) : (
              <textarea id="message-input" className="message-input" value={text} onChange={(event) => setText(event.target.value)} onKeyDown={(event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") handleCheck(); }} placeholder="Paste the full text here…" rows={6} maxLength={3000} aria-describedby="input-hint" data-testid="input-message" />
            )}
            <div className="input-meta" id="input-hint">
              <span>{mode === "phone" ? "Formatting spaces and hyphens are removed. Lookup uses only a verified local list." : mode === "website" ? "The address is analyzed locally and never opened or fetched." : "Don’t paste OTPs, passwords or card numbers. Message analysis runs in this browser. Max 3,000 characters."}</span>
              {mode === "message" && <span>{wordCount} {wordCount === 1 ? "word" : "words"}</span>}
            </div>
            <div className="input-actions">
              <button className="primary-button" type="button" onClick={handleCheck} disabled={!text.trim()} data-testid="button-run-check"><ShieldCheck size={18} aria-hidden="true" /> Check {modeTitles[mode]} <ArrowRight size={16} aria-hidden="true" /></button>
              {mode === "phone" && <button className="secondary-button" type="button" onClick={() => { setText(""); clearResults(); setPhoneDemo(true); }} data-testid="button-phone-demo">View synthetic demo (clears input)</button>}
              {mode === "message" && <button className="secondary-button" type="button" onClick={() => setShowExamples((visible) => !visible)} aria-expanded={showExamples} aria-controls="example-panel" data-testid="button-toggle-examples"><Sparkles size={16} aria-hidden="true" /> {showExamples ? "Hide examples" : "Try an example"}</button>}
            </div>
            {mode === "website" && text.trim() && !normalizeWebsiteUrlInput(text) && <p className="input-validation" role="status" data-testid="status-website-input">Enter one valid web address without spaces. Bare domains such as example.com are accepted.</p>}
            {showExamples && mode === "message" && <div className="example-panel" id="example-panel"><p className="example-heading">Choose a sample message to explore the result:</p><div className="example-list">{EXAMPLE_MESSAGES.map((example, index) => <button type="button" key={example.label} className="example-item" onClick={() => handleExample(example.text)} data-testid={`button-example-${index}`}>{example.label}</button>)}</div></div>}
          </section>

          {messageResult && riskConfig && RiskIcon && (
            <section className={`results risk-${messageResult.riskLevel} reveal`} aria-label="Message analysis results" data-testid="section-analysis-results">
              <div className="result-banner" role="status" aria-live="polite" data-testid="status-risk-result"><div className="risk-mark"><RiskIcon size={29} strokeWidth={2.1} aria-hidden="true" /></div><div><div className="risk-heading">{riskConfig.label}<span className="confidence-label"> · Rule-based assessment</span></div><p className="risk-copy">{messageResult.signals.length === 0 ? "No warning signs were detected by the current rules. Still verify unexpected requests through a trusted channel." : `${messageResult.signals.length} warning signal${messageResult.signals.length === 1 ? "" : "s"} found · rule-based score ${messageResult.totalScore}.`}</p></div><div className="result-actions"><button className="icon-button" type="button" onClick={() => void handleCopy()} aria-label="Copy full analysis report" title="Copy report" data-testid="button-copy-report"><Copy size={17} aria-hidden="true" /></button></div></div>
              <section className="content-card why-card" aria-labelledby="why-heading">
                <div className="card-heading"><Info size={20} aria-hidden="true" /><div><div className="section-kicker">Evidence from this message</div><h2 id="why-heading">Why this result</h2></div></div>
                <p className="explanation-copy" data-testid="text-result-explanation">{messageResult.explanation}</p>
                {messageSignals.length > 0 && <div className="why-subsection"><h3>Rule-based signals</h3><ul className="plain-list">{messageSignals.map((signal) => <li className="signal-row" key={signal.id} data-testid={`item-signal-${signal.id}`}><span className="signal-marker"><CircleAlert size={15} aria-hidden="true" /></span><div><strong>{signal.label}</strong><span className="signal-points">{signal.points} {signal.points === 1 ? "point" : "points"}</span>{signal.detail && <p>{signal.detail}</p>}</div></li>)}</ul></div>}
                {messageResult.combinations.length > 0 && <div className="why-subsection"><h3>Signals that appear together</h3><ul className="plain-list">{messageResult.combinations.map((combination) => <li className="signal-row" key={combination.id}><span className="signal-marker"><AlertTriangle size={15} aria-hidden="true" /></span><div><strong>{combination.label}</strong><p>Combined rule bonus: {combination.bonus} points</p></div></li>)}</ul></div>}
                {messageResult.categories.length > 0 && <div className="why-subsection"><h3>Risk categories</h3><div className="factor-grid">{messageResult.categories.map((category) => <div className="factor-row" key={category.category}><span>{CATEGORY_LABELS[category.category]} · {category.points} pts</span><span className={`factor-pill factor-${category.level}`}>{category.level}</span></div>)}</div></div>}
                {linkAnalysisCards.map((analysis) => <LinkAnalysisCard key={getUrlDeduplicationKey(analysis.url)} analysis={analysis} />)}
              </section>
              <SafeAlternativeSection message={text} />
              <ActionChecklist result={messageResult} risk={messageResult.riskLevel} />
              <div className="disclaimer" data-testid="text-analysis-disclaimer">{messageResult.disclaimer} ScamCheck provides informational analysis and does not replace official law-enforcement or financial-institution advice.</div>
            </section>
          )}

          {websiteResult && riskConfig && RiskIcon && (
            <section className={`results risk-${websiteRisk(websiteResult)} reveal`} aria-label="Website analysis results" data-testid="section-website-results">
              <div className="result-banner" role="status" aria-live="polite" data-testid="status-website-risk"><div className="risk-mark"><RiskIcon size={29} strokeWidth={2.1} aria-hidden="true" /></div><div><div className="risk-heading">{riskConfig.label}<span className="confidence-label"> · Local URL rules</span></div><p className="risk-copy">{websiteResult.signals.length} warning signal{websiteResult.signals.length === 1 ? "" : "s"} found · {websiteResult.summary}</p></div></div>
              <SafeAlternativeSection message={websiteResult.url} website />
              <LinkAnalysisCard analysis={websiteResult} />
              <section className="content-card" aria-labelledby="website-guidance-heading" data-testid="section-website-guidance"><div className="card-heading"><ShieldCheck size={20} aria-hidden="true" /><h2 id="website-guidance-heading">Safe next step</h2></div><p className="explanation-copy">The address was checked as text only. ScamCheck did not visit it. Verify unexpected requests through an official app or a trusted contact route.</p></section>
            </section>
          )}

          {phoneResult && (
            <section className="results reveal" aria-label="Phone number lookup results" data-testid="section-phone-results">
              <section className={`content-card phone-lookup-result${phoneResult.invalid ? " phone-invalid" : ""}`} role="status" aria-live="polite" data-testid="status-phone-lookup">
                <div className="card-heading">{phoneResult.invalid ? <AlertTriangle size={21} aria-hidden="true" /> : phoneResult.report ? <Info size={21} aria-hidden="true" /> : <Phone size={21} aria-hidden="true" />}<h2>{phoneResult.invalid ? "Number format not recognized" : phoneResult.report ? "User-submitted report found" : "No match in user-submitted list"}</h2></div>
                <p className="explanation-copy">{phoneResult.invalid ? "Enter a plausible Indian mobile number with 10 digits, optionally prefixed by +91." : phoneResult.report ? "This number appears in a user-submitted, unverified report list. A match is not proof of wrongdoing and does not determine who uses the number." : "This number was not found in the user-submitted list. Its absence does not mean the number is safe."}</p>
                {!phoneResult.invalid && <p className="phone-privacy-note"><LockKeyhole size={15} aria-hidden="true" /> Checked on this device only. The number was not logged or transmitted.</p>}
                {phoneResult.report && <dl className="report-metadata"><div><dt>Source</dt><dd>{phoneResult.report.source}</dd></div><div><dt>Import date</dt><dd>{phoneResult.report.importDate}</dd></div></dl>}
                {!phoneResult.invalid && !phoneResult.report && <div className="phone-empty-state" data-testid="empty-phone-reports"><strong>User-submitted, unverified data</strong><p>This local lookup checks the imported list only. A match is not proof of wrongdoing; no match does not mean a number is safe.</p></div>}
              </section>
            </section>
          )}
          {phoneDemo && (
            <section className="results reveal" aria-label="Synthetic phone report example" data-testid="section-phone-demo">
              <section className="content-card phone-lookup-result phone-invalid" role="status" aria-live="polite">
                <div className="card-heading"><Info size={21} aria-hidden="true" /><h2>Synthetic demo only — not a real report</h2></div>
                <p className="explanation-copy">This fictional example demonstrates the report fields. Its placeholder is invalid as an Indian mobile number, does not identify a person, and is never searched as a real report.</p>
                <div className="phone-empty-state">
                  <strong>Demo identifier: {SYNTHETIC_PHONE_REPORT_DEMO.number}</strong>
                  <p>Source: {SYNTHETIC_PHONE_REPORT_DEMO.source}<br />Report date: {SYNTHETIC_PHONE_REPORT_DEMO.reportDate}</p>
                </div>
              </section>
            </section>
          )}
          {activeResult && (
            <div className="result-toolbar" data-testid="toolbar-result-actions">
              <div><button className="secondary-button" type="button" onClick={() => void handleCopy()} data-testid="button-copy-report-full">{copied ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}{copied ? "Report copied" : "Copy / export report"}</button><button className="secondary-button" type="button" onClick={handleTryAnother} data-testid="button-try-another"><RotateCcw size={16} aria-hidden="true" /> Check another</button></div>
              <button className="quiet-button" type="button" onClick={handleClear} data-testid="button-clear"><Trash2 size={15} aria-hidden="true" /> Clear {modeTitles[mode]}</button>
            </div>
          )}
        </div>
        <section className="how-section page-wrap scroll-reveal" id="how-it-works" aria-labelledby="how-heading" data-scroll-reveal><div className="how-intro"><div className="section-kicker">A clear, simple process</div><h2 id="how-heading">Understand the clues. Choose your next step.</h2><p>ScamCheck helps make an unsettling message easier to think through—without making the decision for you.</p></div><div className="steps-list"><div className="how-step"><span className="step-number">01</span><div><strong>Choose what arrived</strong><p>Check a phone number, SMS or message, or website address.</p></div></div><div className="how-step"><span className="step-number">02</span><div><strong>See local evidence</strong><p>Rule-based patterns and URL structure are summarized in everyday language.</p></div></div><div className="how-step"><span className="step-number">03</span><div><strong>Verify through a trusted route</strong><p>Use a verified alternative when one is available, or navigate manually to the organization.</p></div></div></div></section>
        <section className="safety-section page-wrap scroll-reveal" id="safety" aria-labelledby="safety-heading" data-scroll-reveal><div className="safety-card"><div className="section-kicker">A small pause helps</div><h2 id="safety-heading">Keep control of the conversation.</h2><p>Scammers often create pressure. Take time to verify requests independently, especially before sharing account details or sending money.</p><div className="safety-points"><span className="safety-point"><LockKeyhole size={15} aria-hidden="true" /> Never share OTPs or passwords</span><span className="safety-point"><Link2 size={15} aria-hidden="true" /> Avoid unexpected message links</span><span className="safety-point"><Phone size={15} aria-hidden="true" /> Verify through a trusted contact route</span></div></div></section>
        <HelpSection />
      </main>
      <footer className="footer"><div className="page-wrap"><div className="footer-inner scroll-reveal" data-scroll-reveal><div className="footer-brand"><a className="brand" href="#top"><span className="brand-mark"><Shield size={19} aria-hidden="true" /></span><span className="brand-name">ScamCheck</span></a><p>Understand suspicious messages before you act.</p></div><div className="footer-group"><h3>Product</h3><div className="footer-links"><a href="#analyze">Analyze</a><a href="#how-it-works">How it works</a><a href="#safety">Safety tips</a></div></div><div className="footer-group"><h3>Help</h3><div className="footer-links"><a href="https://www.cybercrime.gov.in/" target="_blank" rel="noopener noreferrer">Report Cybercrime</a><a href="tel:1930">Cybercrime Helpline: 1930</a><a href="https://cybercrime.gov.in/Webform/cyber_suspect.aspx" target="_blank" rel="noopener noreferrer">Official Reporting Portal</a></div></div><div className="footer-group"><h3>Security</h3><div className="footer-links"><a href="#safety">Safe browsing</a><a href="#safety">Phishing awareness</a><a href="#privacy-note">Privacy & limits</a></div></div></div><div className="footer-note" id="privacy-note"><p>ScamCheck provides informational analysis and does not replace official law-enforcement or financial-institution advice. It cannot guarantee that a message or site is safe or fraudulent. Message and website checks run locally in your browser; phone numbers are checked locally and are not transmitted. ScamCheck does not submit complaints on your behalf.</p></div></div></footer>
    </div>
  );
}