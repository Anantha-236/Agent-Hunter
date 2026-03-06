import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";

// ── DATA ─────────────────────────────────────────────────────────────────────

const PIPELINE_STAGES = [
  { id: "recon", label: "Passive Recon", substeps: ["WHOIS / DNS lookup", "Subdomain enumeration", "Tech fingerprinting", "Certificate transparency"] },
  { id: "active", label: "Active Recon", substeps: ["Port scanning", "Service detection", "WAF detection", "Header analysis"] },
  { id: "fingerprint", label: "Fingerprinting", substeps: ["CMS detection", "Framework version", "Known CVE match", "Config leakage check"] },
  { id: "rl_select", label: "RL Module Selection", substeps: ["State encoding", "Policy inference", "Module priority rank", "Execution queue build"] },
  { id: "scan", label: "Vulnerability Scan", substeps: ["XSS probe", "SQLi test", "SSRF check", "Auth bypass", "IDOR test", "Misconfig audit"] },
  { id: "report", label: "Report Generation", substeps: ["Finding dedup", "CVSS scoring", "PoC generation", "H1 format export"] },
];

const TERMINAL_STREAM = [
  { tag: "info", msg: "Agent-Hunter v2.0 — Autonomous Pentest Agent initialised" },
  { tag: "info", msg: "Target locked: http://testphp.vulnweb.com" },
  { tag: "recon", msg: "Starting passive recon — WHOIS query..." },
  { tag: "recon", msg: "WHOIS: Registrar=GoDaddy, Expiry=2026-03-14, DNSSEC=unsigned" },
  { tag: "recon", msg: "Subdomain enum via crt.sh + SecurityTrails..." },
  { tag: "recon", msg: "Found: testphp.vulnweb.com, testhtml5.vulnweb.com, testaspnet.vulnweb.com [!]" },
  { tag: "warn", msg: "testaspnet.vulnweb.com — OUT OF SCOPE, flagged and skipped" },
  { tag: "recon", msg: "Tech stack: PHP 5.6, Apache/2.4, MySQL 5.1, no WAF detected" },
  { tag: "info", msg: "Active recon starting — SYN scan on target..." },
  { tag: "scan", msg: "Open ports: 80/http, 443/https, 8080/http-alt" },
  { tag: "scan", msg: "WAF detected: Cloudflare — evasion mode engaged" },
  { tag: "scan", msg: "Fingerprinting framework versions..." },
  { tag: "scan", msg: "CVE-2023-44270: PostCSS < 8.4.31 — potential match" },
  { tag: "info", msg: "RL Agent: encoding environment state..." },
  { tag: "info", msg: "RL Agent: policy inference complete — module priority: [xss, auth_bypass, idor, sqli]" },
  { tag: "scan", msg: "XSS scanner activated — probing 47 endpoints..." },
  { tag: "vuln", msg: "⚡ XSS FOUND: /search?q= — reflected, unfiltered, no CSP" },
  { tag: "scan", msg: "Auth bypass module — testing 12 auth endpoints..." },
  { tag: "vuln", msg: "⚡ AUTH BYPASS: /api/v2/user/{id} — IDOR, no ownership check" },
  { tag: "scan", msg: "SSRF module — testing webhook and redirect params..." },
  { tag: "scan", msg: "SSRF: no blind SSRF found via webhook endpoint" },
  { tag: "scan", msg: "SQLi module — 23 injectable params tested..." },
  { tag: "vuln", msg: "⚡ SQLi FOUND: /api/products?filter= — time-based blind" },
  { tag: "scan", msg: "Misconfig audit — checking security headers, CORS, cookies..." },
  { tag: "vuln", msg: "⚡ MISCONFIG: CORS allows wildcard origin on /userinfo.php" },
  { tag: "ok", msg: "Scan complete — 4 findings. Generating report..." },
  { tag: "ok", msg: "Report ready: vulnweb_pentest_2026-03-06.pdf" },
];

const FINDINGS = [
  { title: "Reflected XSS — Search Endpoint", sev: "high", url: "/search.php?test=<script>", desc: "Unfiltered user input reflected in DOM. No CSP header present. Exploitable for session hijack.", module: "xss_scanner" },
  { title: "IDOR — User Info Endpoint", sev: "critical", url: "/userinfo.php?id=1", desc: "Unauthenticated access to arbitrary user profiles by iterating numeric ID. No access control.", module: "auth_bypass" },
  { title: "Time-Based Blind SQLi", sev: "critical", url: "/listproducts.php?cat=1", desc: "Category parameter unsanitised. SLEEP(5) payload causes 5s delay confirming MySQL injection.", module: "injection_sqli" },
  { title: "CORS Wildcard on User Info", sev: "medium", url: "/userinfo.php", desc: "Access-Control-Allow-Origin: * allows any origin to read user data cross-domain.", module: "misconfig_scanner" },
  { title: "Missing Security Headers", sev: "low", url: "http://testphp.vulnweb.com", desc: "X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers absent on all responses.", module: "misconfig_scanner" },
];

const COMPLIANCE_ITEMS = [
  { id: "identity", title: "Identity Verification", desc: "Government-issued ID or corporate email domain verified. Operator identity logged against this session." },
  { id: "noc", title: "No-Objection Certificate (NOC)", desc: "Written NOC from target organisation's security/legal team. Upload signed PDF below." },
  { id: "nda", title: "Non-Disclosure Agreement (NDA)", desc: "Mutual NDA covering findings confidentiality, responsible disclosure timeline, and liability." },
  { id: "scope", title: "Scope Confirmation", desc: "In-scope and out-of-scope assets explicitly defined and locked before any scanning begins." },
  { id: "legal", title: "Legal Disclaimer Acceptance", desc: "Operator accepts full legal responsibility for this engagement. AgentiAI is a tool, not a legal entity." },
];

// ── SHARED COMPONENTS ─────────────────────────────────────────────────────────

function CheckIcon({ size = 12 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 12 12" fill="none">
      <path d="M2 6l3 3 5-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Logo() {
  return (
    <div className="logo">
      <div className="logo-icon">
        <svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M8 1L14 4.5V11.5L8 15L2 11.5V4.5L8 1Z" stroke="#000" strokeWidth="1.5" strokeLinejoin="round" />
          <path d="M8 5L11 6.75V10.25L8 12L5 10.25V6.75L8 5Z" fill="#000" />
        </svg>
      </div>
      Agent-<span>Hunter</span>
    </div>
  );
}

function WizardSteps({ current }) {
  const steps = ["Identity & Auth", "Pre-Engagement", "Mission Config", "Agent Running", "Report"];
  return (
    <div className="wizard-steps">
      {steps.map((s, i) => (
        <div key={s} className="wizard-step">
          <div className={`step-dot ${i < current ? "done" : i === current ? "active" : "pending"}`}>
            {i < current ? <CheckIcon size={11} /> : i + 1}
          </div>
          <span className={`step-label ${i === current ? "active" : ""}`}>{s}</span>
          {i < steps.length - 1 && <div className={`step-line ${i < current ? "done" : ""}`} />}
        </div>
      ))}
    </div>
  );
}

// ── SCREEN 1: AUTH ────────────────────────────────────────────────────────────

function AuthScreen({ onAuth }) {
  const [email, setEmail] = useState("");
  const [org, setOrg] = useState("");
  const [agreed, setAgreed] = useState(false);

  return (
    <div className="auth-screen">
      <div className="auth-grid" />
      <div className="auth-glow" />
      <div className="auth-box">
        <div className="auth-logo">
          <Logo />
          <h1 style={{ marginTop: 16 }}>
            Agent-<span style={{ color: "var(--amber)" }}>Hunter</span>
          </h1>
          <p>Autonomous Vulnerability Intelligence Platform</p>
          <div style={{ marginTop: 10 }}>
            <Link
              to="/blueprint"
              style={{ color: "var(--text3)", textDecoration: "none", fontSize: 10, border: "1px solid var(--border2)", padding: "3px 10px", borderRadius: 20, letterSpacing: 1 }}
            >
              VIEW ARCHITECTURE BLUEPRINT →
            </Link>
          </div>
        </div>

        <div className="auth-warning">
          <strong>⚠ AUTHORISED USE ONLY</strong>
          Only use Agent-Hunter against targets you own or have explicit written
          permission to test. All sessions are logged and audited.
        </div>

        <div className="card">
          <div className="form-row">
            <label className="label">Professional Email</label>
            <input className="input" placeholder="you@organisation.com" value={email} onChange={e => setEmail(e.target.value)} />
          </div>
          <div className="form-row">
            <label className="label">Organisation / Company</label>
            <input className="input" placeholder="ACME Security Ltd." value={org} onChange={e => setOrg(e.target.value)} />
          </div>
          <div
            style={{ display: "flex", alignItems: "flex-start", gap: 10, marginBottom: 20, cursor: "pointer" }}
            onClick={() => setAgreed(!agreed)}
          >
            <div className={`check-box ${agreed ? "checked" : ""}`} style={{ marginTop: 2 }}>
              {agreed && <CheckIcon />}
            </div>
            <span style={{ fontSize: 12, color: "var(--text2)", lineHeight: 1.6 }}>
              I confirm I am a <strong style={{ color: "var(--text)" }}>security professional</strong> and
              will only use Agent-Hunter against systems I am authorised to test.
            </span>
          </div>
          <button
            className="btn btn-primary"
            style={{ width: "100%", justifyContent: "center" }}
            disabled={!email || !org || !agreed}
            onClick={() => onAuth({ email, org })}
          >
            Continue to Pre-Engagement →
          </button>
        </div>
      </div>
    </div>
  );
}

// ── SCREEN 2: PRE-ENGAGEMENT ──────────────────────────────────────────────────

function PreEngagementScreen({ user, onComplete }) {
  const [checked, setChecked] = useState({});
  const [nocFile, setNocFile] = useState(null);
  const [ndaFile, setNdaFile] = useState(null);

  const toggle = (id) => setChecked((p) => ({ ...p, [id]: !p[id] }));
  const allDone = COMPLIANCE_ITEMS.every((i) => checked[i.id]) && nocFile && ndaFile;

  return (
    <div className="screen">
      <div className="header">
        <Logo />
        <div className="header-right">
          <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text2)" }}>{user.email}</span>
          <span className="badge badge-warn">PRE-ENGAGEMENT</span>
        </div>
      </div>

      <WizardSteps current={1} />

      <div className="wizard-body">
        <div className="section-title">Pre-Engagement Compliance</div>
        <div className="section-sub">All checks must be completed before any scanning is permitted.</div>

        {COMPLIANCE_ITEMS.map((item) => (
          <div
            key={item.id}
            className={`compliance-item ${checked[item.id] ? "checked" : ""}`}
            onClick={() => toggle(item.id)}
          >
            <div className="check-box">{checked[item.id] && <CheckIcon />}</div>
            <div>
              <div className="compliance-title">{item.title}</div>
              <div className="compliance-desc">{item.desc}</div>
            </div>
          </div>
        ))}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 20 }}>
          <div>
            <label className="label">Upload NOC (PDF)</label>
            <div className={`upload-zone ${nocFile ? "done" : ""}`} onClick={() => setNocFile("noc_signed.pdf")}>
              <div className="upload-icon">{nocFile ? "✅" : "📄"}</div>
              <div className="upload-text">{nocFile || "Click to upload signed NOC"}</div>
            </div>
          </div>
          <div>
            <label className="label">Upload NDA (PDF)</label>
            <div className={`upload-zone ${ndaFile ? "done" : ""}`} onClick={() => setNdaFile("nda_signed.pdf")}>
              <div className="upload-icon">{ndaFile ? "✅" : "📄"}</div>
              <div className="upload-text">{ndaFile || "Click to upload signed NDA"}</div>
            </div>
          </div>
        </div>
      </div>

      <div className="wizard-footer">
        <div style={{ fontSize: 12, color: "var(--text3)", fontFamily: "var(--mono)" }}>
          {Object.values(checked).filter(Boolean).length}/{COMPLIANCE_ITEMS.length} checks completed
        </div>
        <button className="btn btn-primary" disabled={!allDone} onClick={onComplete}>
          Proceed to Mission Config →
        </button>
      </div>
    </div>
  );
}

// ── SCREEN 3: MISSION CONFIG ──────────────────────────────────────────────────

function MissionScreen({ onLaunch }) {
  const [target, setTarget] = useState("http://testphp.vulnweb.com");
  const [inScope, setInScope] = useState(["testphp.vulnweb.com", "testhtml5.vulnweb.com"]);
  const [outScope, setOutScope] = useState(["testaspnet.vulnweb.com", "testasp.vulnweb.com"]);
  const [inInput, setInInput] = useState("");
  const [outInput, setOutInput] = useState("");
  const [instructions, setInstructions] = useState(
    "Focus on web application endpoints. Test all input parameters for injection flaws. This is a deliberately vulnerable test application — full-intensity scanning is permitted. Document all findings with PoC evidence."
  );
  const [intensity, setIntensity] = useState("normal");

  const addTag = (list, setList, val, setVal) => {
    if (val.trim()) {
      setList([...list, val.trim()]);
      setVal("");
    }
  };

  return (
    <div className="screen">
      <div className="header">
        <Logo />
        <div className="header-right">
          <span className="badge badge-ok">COMPLIANCE ✓</span>
          <span className="badge badge-warn">MISSION CONFIG</span>
        </div>
      </div>

      <WizardSteps current={2} />

      <div className="wizard-body" style={{ maxWidth: 780 }}>
        <div className="section-title">Mission Configuration</div>
        <div className="section-sub">Define the engagement target, scope boundaries, and agent behaviour.</div>

        <div className="form-row">
          <label className="label">Primary Target URL / IP</label>
          <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} />
        </div>

        <div className="form-grid" style={{ marginBottom: 18 }}>
          <div>
            <label className="label">✅ In Scope</label>
            <div className="tag-input-row">
              <input
                className="input"
                placeholder="e.g. api.target.com"
                value={inInput}
                onChange={(e) => setInInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addTag(inScope, setInScope, inInput, setInInput)}
              />
              <button className="btn btn-ghost btn-sm" onClick={() => addTag(inScope, setInScope, inInput, setInInput)}>+</button>
            </div>
            <div className="tag-list">
              {inScope.map((t) => (
                <span key={t} className="tag tag-in">
                  {t} <span className="tag-x" onClick={() => setInScope(inScope.filter((x) => x !== t))}>×</span>
                </span>
              ))}
            </div>
          </div>
          <div>
            <label className="label">🚫 Out of Scope</label>
            <div className="tag-input-row">
              <input
                className="input"
                placeholder="e.g. internal.target.com"
                value={outInput}
                onChange={(e) => setOutInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addTag(outScope, setOutScope, outInput, setOutInput)}
              />
              <button className="btn btn-ghost btn-sm" onClick={() => addTag(outScope, setOutScope, outInput, setOutInput)}>+</button>
            </div>
            <div className="tag-list">
              {outScope.map((t) => (
                <span key={t} className="tag tag-out">
                  {t} <span className="tag-x" onClick={() => setOutScope(outScope.filter((x) => x !== t))}>×</span>
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="form-row">
          <label className="label">Customer Instructions</label>
          <textarea className="input" value={instructions} onChange={(e) => setInstructions(e.target.value)} rows={4} />
        </div>

        <div className="form-row">
          <label className="label">Scan Intensity</label>
          <div style={{ display: "flex", gap: 8 }}>
            {["passive", "normal", "aggressive"].map((i) => (
              <button
                key={i}
                className={`btn ${intensity === i ? "btn-primary" : "btn-ghost"} btn-sm`}
                style={{ textTransform: "capitalize" }}
                onClick={() => setIntensity(i)}
              >
                {i}
              </button>
            ))}
          </div>
        </div>

        <div className="form-row">
          <label className="label">Active AI Models</label>
          <div className="model-row">
            {["Recon-LLM", "Fingerprint-CNN", "RL-Policy", "Exploit-GPT", "Report-Writer"].map((m) => (
              <span key={m} className="model-badge active">
                <span className="model-dot" /> {m}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="wizard-footer">
        <div style={{ fontSize: 12, color: "var(--text3)", fontFamily: "var(--mono)" }}>
          All pre-engagement checks passed · Session ID: AGT-2024-{Math.random().toString(36).slice(2, 8).toUpperCase()}
        </div>
        <button
          className="btn btn-primary"
          disabled={!target || inScope.length === 0}
          onClick={() => onLaunch({ target, inScope, outScope, instructions, intensity })}
        >
          🚀 Launch Agent
        </button>
      </div>
    </div>
  );
}

// ── SCREEN 4: AGENT DASHBOARD ─────────────────────────────────────────────────

function DashboardScreen({ mission }) {
  const [tick, setTick] = useState(0);
  const [logLines, setLogLines] = useState([]);
  const [findings, setFindings] = useState([]);
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0, info: 0, urls: 0 });
  const [done, setDone] = useState(false);
  const termRef = useRef(null);
  const lineRef = useRef(0);
  const findRef = useRef(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setTick((t) => {
        const next = t + 1;
        // Add terminal lines
        if (lineRef.current < TERMINAL_STREAM.length) {
          const line = TERMINAL_STREAM[lineRef.current];
          setLogLines((l) => [...l, { ...line, time: new Date().toLocaleTimeString("en-GB", { hour12: false }) }]);
          lineRef.current++;
        }
        // Add findings progressively
        if (next === 12 && findRef.current < FINDINGS.length) {
          const f = FINDINGS[findRef.current];
          setFindings((arr) => [...arr, f]);
          setStats((s) => ({ ...s, [f.sev]: (s[f.sev] || 0) + 1 }));
          findRef.current++;
        }
        if (next > 14 && findRef.current < FINDINGS.length) {
          const f = FINDINGS[findRef.current];
          setFindings((arr) => [...arr, f]);
          setStats((s) => ({ ...s, [f.sev]: (s[f.sev] || 0) + 1 }));
          findRef.current++;
        }
        setStats((s) => ({ ...s, urls: Math.min(s.urls + 7, 347) }));
        if (next >= 28) {
          setDone(true);
          clearInterval(timer);
        }
        return next;
      });
    }, 600);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [logLines]);

  const getStageState = (idx) => {
    const thresholds = [0, 4, 8, 12, 14, 26];
    if (tick >= thresholds[idx + 1]) return "done";
    if (tick >= thresholds[idx]) return "active";
    return "queued";
  };

  const getProgress = (idx) => {
    const thresholds = [0, 4, 8, 12, 14, 26];
    const start = thresholds[idx],
      end = thresholds[idx + 1];
    if (tick >= end) return 100;
    if (tick < start) return 0;
    return Math.round(((tick - start) / (end - start)) * 100);
  };

  return (
    <div className="screen">
      <div className="header">
        <Logo />
        <div style={{ display: "flex", alignItems: "center", gap: 12, fontFamily: "var(--mono)", fontSize: 11, color: "var(--text2)" }}>
          <span>
            Target: <strong style={{ color: "var(--text)" }}>{mission.target}</strong>
          </span>
        </div>
        <div className="header-right">
          {done ? <span className="badge badge-ok">SCAN COMPLETE</span> : <span className="badge badge-warn">● SCANNING</span>}
          <Link
            to="/blueprint"
            style={{ color: "var(--text3)", textDecoration: "none", fontSize: 10, border: "1px solid var(--border2)", padding: "3px 10px", borderRadius: 20, letterSpacing: 1, transition: "all 0.2s" }}
          >
            BLUEPRINT →
          </Link>
        </div>
      </div>

      <WizardSteps current={3} />

      <div className="stats-bar">
        <div className="stat">
          <div className="stat-val red">{stats.critical}</div>
          <div className="stat-lbl">Critical</div>
        </div>
        <div className="stat">
          <div className="stat-val orange">{stats.high}</div>
          <div className="stat-lbl">High</div>
        </div>
        <div className="stat">
          <div className="stat-val amber">{stats.medium}</div>
          <div className="stat-lbl">Medium</div>
        </div>
        <div className="stat">
          <div className="stat-val green">{stats.low + stats.info}</div>
          <div className="stat-lbl">Low/Info</div>
        </div>
        <div className="stat">
          <div className="stat-val blue">{stats.urls}</div>
          <div className="stat-lbl">URLs Tested</div>
        </div>
      </div>

      <div className="target-bar">
        <div className="target-item">
          🎯 <strong>{mission.target}</strong>
        </div>
        <div className="target-item">
          ✅ In-scope: <strong>{mission.inScope.join(", ")}</strong>
        </div>
        <div className="target-item">
          🚫 Out-scope: <strong>{mission.outScope.join(", ")}</strong>
        </div>
        <div className="target-item" style={{ marginLeft: "auto" }}>
          Intensity: <strong style={{ color: "var(--amber)", textTransform: "capitalize" }}>{mission.intensity}</strong>
        </div>
      </div>

      <div className="dashboard">
        {/* Pipeline */}
        <div className="pipeline-panel">
          <div className="panel-title">Agent Pipeline</div>
          {PIPELINE_STAGES.map((stage, idx) => {
            const state = getStageState(idx);
            const progress = getProgress(idx);
            return (
              <div key={stage.id} className={`pipeline-stage ${state}`}>
                <div className="stage-header">
                  <span className="stage-name">{stage.label}</span>
                  <span className={`stage-status ${state}`}>
                    {state === "done" ? "✓ done" : state === "active" ? "running..." : "queued"}
                  </span>
                </div>
                <div className="stage-progress">
                  <div
                    className={`stage-progress-bar ${state === "done" ? "green" : "amber"}`}
                    style={{ width: `${progress}%` }}
                  />
                </div>
                {state === "active" && (
                  <div className="stage-substeps">
                    {stage.substeps.map((s, si) => {
                      const doneIdx = Math.floor(progress / (100 / stage.substeps.length));
                      return (
                        <div key={s} className={`substep ${si < doneIdx ? "done" : si === doneIdx ? "active" : ""}`}>
                          <div className={`dot-indicator ${si < doneIdx ? "green" : si === doneIdx ? "amber" : "gray"}`} />
                          {s}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Terminal */}
        <div className="terminal-panel">
          <div className="panel-title" style={{ marginBottom: 10 }}>Agent Log</div>
          <div className="terminal">
            <div className="terminal-bar">
              <div className="t-dot" style={{ background: "#ff5f57" }} />
              <div className="t-dot" style={{ background: "#febc2e" }} />
              <div className="t-dot" style={{ background: "#28c840" }} />
              <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text3)", marginLeft: 8 }}>
                agent-hunter — autonomous scan session
              </span>
            </div>
            <div className="terminal-body" ref={termRef}>
              {logLines.map((line, i) => (
                <div key={i} className="t-line">
                  <span className="t-time">{line.time}</span>
                  <span className={`t-tag ${line.tag}`}>{line.tag.toUpperCase()}</span>
                  <span
                    className={`t-msg ${line.tag === "vuln" ? "amber" : line.tag === "ok" ? "green" : line.tag === "warn" ? "red" : ""}`}
                  >
                    {line.msg}
                  </span>
                </div>
              ))}
              {!done && (
                <div className="t-line">
                  <span className="t-time">--:--:--</span>
                  <span className="t-tag info">INFO</span>
                  <span className="t-msg dim">█ scanning...</span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Findings */}
        <div className="findings-panel">
          <div className="panel-title">Live Findings ({findings.length})</div>
          {findings.length === 0 && (
            <div style={{ color: "var(--text3)", fontFamily: "var(--mono)", fontSize: 11, marginTop: 20, textAlign: "center" }}>
              No findings yet...
            </div>
          )}
          {findings.map((f, i) => (
            <div key={i} className="finding-card">
              <div className="finding-header">
                <span className="finding-title">{f.title}</span>
                <span className={`sev sev-${f.sev}`}>{f.sev.toUpperCase()}</span>
              </div>
              <div className="finding-url">{f.url}</div>
              <div className="finding-desc">{f.desc}</div>
              <div className="finding-module">via {f.module}</div>
            </div>
          ))}
          {done && (
            <div style={{ marginTop: 8 }}>
              <button className="btn btn-primary" style={{ width: "100%", justifyContent: "center" }}>
                📄 Export Full Report
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── APP ROOT ──────────────────────────────────────────────────────────────────

export default function App() {
  const [screen, setScreen] = useState("auth");
  const [user, setUser] = useState(null);
  const [mission, setMission] = useState(null);

  return (
    <>
      {screen === "auth" && (
        <AuthScreen
          onAuth={(u) => {
            setUser(u);
            setScreen("preeng");
          }}
        />
      )}
      {screen === "preeng" && <PreEngagementScreen user={user} onComplete={() => setScreen("mission")} />}
      {screen === "mission" && (
        <MissionScreen
          onLaunch={(m) => {
            setMission(m);
            setScreen("dashboard");
          }}
        />
      )}
      {screen === "dashboard" && <DashboardScreen mission={mission} />}
    </>
  );
}
