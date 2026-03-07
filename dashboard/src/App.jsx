import { useState, useEffect, useRef, useCallback } from "react";
import {
  startScan as apiStartScan,
  getScan,
  listScans,
  listModules,
  getSettings,
  saveSettings,
  streamScan,
} from "./api";

/* Deep Void Intelligence UI + real backend wiring */

const PHASE_PROGRESS = {
  init: 5,
  recon: 25,
  strategy: 45,
  scan: 75,
  validate: 90,
  complete: 100,
};

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@300;400;500&family=Outfit:wght@300;400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html,body,#root{height:100%;}
body{font-family:'Outfit',sans-serif;background:#03040a;color:#cbd5e1;overflow:hidden;cursor:default;}
::-webkit-scrollbar{width:3px;height:3px;}::-webkit-scrollbar-track{background:transparent;}::-webkit-scrollbar-thumb{background:rgba(99,235,215,0.2);border-radius:10px;}
.aurora{position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse 80% 50% at 10% 0%,rgba(99,235,215,0.07) 0%,transparent 60%),radial-gradient(ellipse 60% 40% at 90% 0%,rgba(167,139,250,0.07) 0%,transparent 60%),radial-gradient(ellipse 40% 30% at 50% 100%,rgba(99,235,215,0.04) 0%,transparent 50%);} 
.shell{position:relative;z-index:2;display:grid;grid-template-columns:220px 1fr;grid-template-rows:56px 1fr;height:100vh;}
.topbar{grid-column:1/-1;display:flex;align-items:center;padding:0 24px;border-bottom:1px solid rgba(255,255,255,0.07);background:rgba(6,8,16,0.85);backdrop-filter:blur(20px);gap:16px;}
.logo-text{font-family:'Syne',sans-serif;font-weight:800;font-size:15px;letter-spacing:3px;text-transform:uppercase;color:#f1f5f9;}
.logo-sub{font-family:'JetBrains Mono',monospace;font-size:9px;color:#475569;letter-spacing:2px;margin-top:1px;}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:20px;}
.status-pill{display:flex;align-items:center;gap:7px;padding:5px 12px;border-radius:100px;border:1px solid rgba(255,255,255,0.07);background:rgba(255,255,255,0.03);font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:1px;color:#94a3b8;}
.status-pill.active{border-color:rgba(99,235,215,0.3);color:#63ebd7;}
.dot{width:7px;height:7px;border-radius:50%;background:#475569;}
.dot.cyan{background:#63ebd7;box-shadow:0 0 8px #63ebd7;animation:dotPulse 2s infinite;}
@keyframes dotPulse{0%,100%{opacity:1}50%{opacity:0.3}}
.sidebar{border-right:1px solid rgba(255,255,255,0.07);background:rgba(6,8,16,0.6);backdrop-filter:blur(20px);padding:20px 12px;display:flex;flex-direction:column;gap:4px;overflow-y:auto;}
.nav-item{display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:10px;border:1px solid transparent;cursor:pointer;transition:all 0.15s;font-family:'Outfit',sans-serif;font-size:13px;font-weight:400;color:#475569;background:transparent;width:100%;text-align:left;}
.nav-item:hover{color:#cbd5e1;background:rgba(255,255,255,0.03);} .nav-item.active{color:#f1f5f9;background:linear-gradient(135deg,rgba(99,235,215,0.1),rgba(167,139,250,0.08));border-color:rgba(99,235,215,0.15);} .nav-item.active .nav-icon{color:#63ebd7;}
.nav-icon{font-size:15px;width:18px;text-align:center;flex-shrink:0;}
.nav-badge{font-family:'JetBrains Mono',monospace;font-size:10px;padding:1px 7px;border-radius:100px;background:rgba(248,113,113,0.15);color:#f87171;border:1px solid rgba(248,113,113,0.2);}
.sidebar-section{font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:2px;color:#475569;text-transform:uppercase;padding:16px 14px 6px;}
.sidebar-footer{margin-top:auto;padding:12px 14px;border-top:1px solid rgba(255,255,255,0.07);font-family:'JetBrains Mono',monospace;font-size:9px;color:#475569;letter-spacing:1px;}
.main{overflow-y:auto;padding:28px 32px;display:flex;flex-direction:column;gap:24px;}
.card{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:14px;backdrop-filter:blur(10px);overflow:hidden;}
.card-lit{border-color:rgba(99,235,215,0.25);background:rgba(99,235,215,0.03);box-shadow:0 0 40px rgba(99,235,215,0.05),inset 0 1px 0 rgba(99,235,215,0.1);} 
.card-header{padding:16px 22px;border-bottom:1px solid rgba(255,255,255,0.07);display:flex;align-items:center;justify-content:space-between;}
.card-title{font-family:'Syne',sans-serif;font-size:13px;font-weight:600;color:#f1f5f9;letter-spacing:0.5px;} .card-body{padding:20px 22px;}
.page-title{font-family:'Syne',sans-serif;font-size:26px;font-weight:800;color:#f1f5f9;line-height:1.1;} .page-sub{font-family:'JetBrains Mono',monospace;font-size:11px;color:#475569;margin-top:4px;letter-spacing:1px;} .accent{color:#63ebd7;}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;}
.stat-tile{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:12px;padding:18px 20px;position:relative;overflow:hidden;}
.stat-tile::before{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;}
.stat-tile.crit::before{background:linear-gradient(90deg,#f87171,transparent);} .stat-tile.high::before{background:linear-gradient(90deg,#fbbf24,transparent);} .stat-tile.med::before{background:linear-gradient(90deg,#a78bfa,transparent);} .stat-tile.low::before{background:linear-gradient(90deg,#4ade80,transparent);} 
.stat-num{font-family:'Syne',sans-serif;font-size:36px;font-weight:800;line-height:1;margin-bottom:6px;} .stat-label{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:2px;text-transform:uppercase;}
.btn{display:inline-flex;align-items:center;gap:7px;padding:9px 18px;border-radius:8px;font-family:'Outfit',sans-serif;font-size:13px;font-weight:500;cursor:pointer;border:none;transition:all 0.15s;white-space:nowrap;}
.btn-ghost{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);color:#94a3b8;} .btn-ghost:hover{background:rgba(255,255,255,0.06);color:#cbd5e1;}
.btn-solid{background:linear-gradient(135deg,#63ebd7,#2dd4bf);color:#000;font-weight:600;border:none;} .btn-solid:hover{box-shadow:0 0 30px rgba(99,235,215,0.3);}
.btn-danger{background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);color:#f87171;}
.badge{display:inline-flex;align-items:center;padding:3px 9px;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:500;letter-spacing:0.5px;white-space:nowrap;}
.badge-CRITICAL{background:rgba(248,113,113,0.12);color:#f87171;border:1px solid rgba(248,113,113,0.25);} .badge-HIGH{background:rgba(251,191,36,0.12);color:#fbbf24;border:1px solid rgba(251,191,36,0.25);} .badge-MEDIUM{background:rgba(167,139,250,0.12);color:#a78bfa;border:1px solid rgba(167,139,250,0.25);} .badge-LOW,.badge-INFO{background:rgba(74,222,128,0.12);color:#4ade80;border:1px solid rgba(74,222,128,0.25);} 
.chip{display:inline-block;padding:2px 8px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:1px;text-transform:uppercase;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);color:#475569;}
.progress-track{height:4px;border-radius:2px;background:rgba(255,255,255,0.06);overflow:hidden;} .progress-fill{height:100%;border-radius:2px;background:linear-gradient(90deg,#63ebd7,#a78bfa);transition:width 0.4s ease;}
.field{width:100%;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:8px;padding:11px 14px;font-family:'JetBrains Mono',monospace;font-size:13px;color:#cbd5e1;outline:none;} .field::placeholder{color:#475569;}
.field-label{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:#475569;margin-bottom:7px;display:block;}
.toggle-wrap{width:42px;height:24px;position:relative;cursor:pointer;} .toggle-track{width:100%;height:100%;border-radius:12px;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.07);} .toggle-wrap.on .toggle-track{background:rgba(99,235,215,0.2);border-color:rgba(99,235,215,0.4);} .toggle-thumb{position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:#475569;transition:transform 0.2s,background 0.2s;} .toggle-wrap.on .toggle-thumb{transform:translateX(18px);background:#63ebd7;}
.module-card{padding:16px 18px;border-radius:10px;border:1px solid rgba(255,255,255,0.07);background:rgba(255,255,255,0.03);display:flex;align-items:center;gap:14px;cursor:pointer;} .module-card.on{border-color:rgba(99,235,215,0.2);background:rgba(99,235,215,0.04);} 
.finding-row{display:grid;grid-template-columns:90px 1fr 80px 100px;align-items:center;gap:12px;padding:13px 22px;cursor:pointer;border-bottom:1px solid rgba(255,255,255,0.07);} .finding-row:hover{background:rgba(255,255,255,0.03);} .finding-row.selected{background:rgba(99,235,215,0.04);} 
.find-name{font-family:'Outfit',sans-serif;font-size:13px;font-weight:500;color:#f1f5f9;} .find-loc{font-family:'JetBrains Mono',monospace;font-size:10px;color:#475569;margin-top:2px;}
.terminal{background:rgba(3,4,10,0.9);border-radius:10px;overflow:hidden;border:1px solid rgba(255,255,255,0.07);} .terminal-bar{display:flex;align-items:center;gap:6px;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,0.07);background:rgba(255,255,255,0.02);} .t-dot{width:10px;height:10px;border-radius:50%;} .terminal-body{padding:14px 16px;height:280px;overflow-y:auto;font-family:'JetBrains Mono',monospace;font-size:11.5px;line-height:2;} .t-line{display:flex;gap:10px;} .t-ts{color:#475569;flex-shrink:0;}
.tab-filter{display:flex;gap:2px;border-bottom:1px solid rgba(255,255,255,0.07);padding:0 22px;} .tab-btn{padding:10px 14px;font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:#475569;cursor:pointer;border:none;background:transparent;} .tab-btn.active{color:#f1f5f9;border-bottom:2px solid #63ebd7;}
.detail-panel{background:rgba(99,235,215,0.03);border:1px solid rgba(99,235,215,0.15);border-radius:10px;padding:20px 22px;} .detail-title{font-family:'Syne',sans-serif;font-size:16px;font-weight:700;color:#f1f5f9;margin-bottom:8px;} .detail-desc{font-size:13px;color:#cbd5e1;line-height:1.7;}
.setting-row{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid rgba(255,255,255,0.07);} .setting-row:last-child{border-bottom:none;} .setting-name{font-size:13px;color:#cbd5e1;font-weight:500;} .setting-desc{font-size:11px;color:#475569;margin-top:2px;font-family:'JetBrains Mono',monospace;}
.cov-row{margin-bottom:14px;} .cov-label{display:flex;justify-content:space-between;font-family:'JetBrains Mono',monospace;font-size:10px;color:#475569;margin-bottom:6px;letter-spacing:1px;text-transform:uppercase;} .cov-label span:last-child{color:#63ebd7;}
@media (max-width: 980px){.shell{grid-template-columns:1fr;grid-template-rows:56px auto 1fr}.sidebar{border-right:none;border-bottom:1px solid rgba(255,255,255,0.07);padding:10px}.main{padding:18px}.stat-grid{grid-template-columns:1fr 1fr}.finding-row{grid-template-columns:80px 1fr}.finding-row .chip,.finding-row span:last-child{display:none}}
`;

function toHexColor(msg) {
  const m = (msg || "").toLowerCase();
  if (m.includes("critical")) return "#f87171";
  if (m.includes("high")) return "#fbbf24";
  if (m.includes("medium")) return "#a78bfa";
  if (m.includes("complete") || m.includes("started") || m.includes("scan")) return "#63ebd7";
  return "#94a3b8";
}

function normalizeFinding(raw, idx) {
  const sev = (raw.severity || "LOW").toUpperCase();
  const cat = (raw.module || "unknown").toLowerCase();
  return {
    id: raw.id || idx + 1,
    type: raw.title || raw.vuln_type || "Finding",
    loc: raw.url || "",
    sev,
    cat,
    cve: raw.cwe_id || "N/A",
    ts: (raw.discovered_at || "").slice(11, 19) || "--:--:--",
    desc: raw.description || "No description",
  };
}

function Toggle({ on, onChange }) {
  return (
    <div className={`toggle-wrap ${on ? "on" : ""}`} onClick={() => onChange(!on)}>
      <div className="toggle-track" />
      <div className="toggle-thumb" />
    </div>
  );
}

function Badge({ s }) {
  return <span className={`badge badge-${s}`}>{s}</span>;
}

function formatModuleName(moduleId) {
  return moduleId
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function moduleHint(moduleId) {
  const hints = {
    sql_injection: "SQL injection detection",
    ssti: "Server-side template injection",
    crlf_injection: "Header injection and response splitting",
    command_injection: "OS command injection testing",
    xxe_scanner: "XML external entity injection",
    xss_scanner: "Reflected, stored, and DOM XSS",
    ssrf: "Server-side request forgery",
    graphql_scanner: "GraphQL attack surface checks",
    auth_scanner: "Authentication weaknesses",
    idor_scanner: "Object-level authorization checks",
    csrf_scanner: "Cross-site request forgery",
    race_condition: "Concurrent request race checks",
    path_traversal: "File path traversal tests",
    misconfig_scanner: "Security misconfiguration checks",
    host_header: "Host header attack checks",
    open_redirect: "Open redirect tests",
    subdomain_takeover: "Dangling DNS and takeover checks",
  };
  return hints[moduleId] || "Vulnerability scanner module";
}

function Dashboard({ onNavigate, scanning, findings, scanTarget }) {
  const crit = findings.filter((f) => f.sev === "CRITICAL").length;
  const high = findings.filter((f) => f.sev === "HIGH").length;
  const med = findings.filter((f) => f.sev === "MEDIUM").length;
  const low = findings.filter((f) => f.sev === "LOW" || f.sev === "INFO").length;
  const cats = ["web", "network", "sast", "dependency"];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div className="page-title">Threat <span className="accent">Overview</span></div>
          <div className="page-sub">Last scan target · {scanTarget || "N/A"}</div>
        </div>
        <button className="btn btn-solid" onClick={() => onNavigate("scan")}>▶ New Scan</button>
      </div>

      <div className="stat-grid">
        {[
          { n: crit, label: "Critical", cls: "crit", color: "#f87171" },
          { n: high, label: "High", cls: "high", color: "#fbbf24" },
          { n: med, label: "Medium", cls: "med", color: "#a78bfa" },
          { n: low, label: "Low", cls: "low", color: "#4ade80" },
        ].map(({ n, label, cls, color }) => (
          <div key={label} className={`stat-tile ${cls}`}>
            <div className="stat-num" style={{ color }}>{n}</div>
            <div className="stat-label" style={{ color }}>{label}</div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Module Coverage</div>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: "#475569" }}>{findings.length} FINDINGS</span>
        </div>
        <div className="card-body">
          {cats.map((cat) => {
            const n = findings.filter((f) => f.cat.includes(cat)).length;
            const pct = findings.length ? (n / findings.length) * 100 : 0;
            return (
              <div key={cat} className="cov-row">
                <div className="cov-label"><span>{cat}</span><span>{n} findings</span></div>
                <div className="progress-track"><div className="progress-fill" style={{ width: `${pct}%` }} /></div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Critical Findings</div>
          <button className="btn btn-ghost" style={{ padding: "5px 12px", fontSize: 11 }} onClick={() => onNavigate("findings")}>View all →</button>
        </div>
        {findings.filter((f) => f.sev === "CRITICAL").slice(0, 6).map((f) => (
          <div key={f.id} className="finding-row">
            <Badge s={f.sev} />
            <div><div className="find-name">{f.type}</div><div className="find-loc">{f.loc}</div></div>
            <span className="chip">{f.cat}</span>
            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: "#a78bfa" }}>{f.cve}</span>
          </div>
        ))}
        {!findings.length && <div style={{ padding: 22, color: "#475569", fontFamily: "'JetBrains Mono',monospace", fontSize: 11 }}>No findings yet.</div>}
      </div>
    </div>
  );
}

function ScanPage({ onLaunch, availableModules }) {
  const [url, setUrl] = useState("");
  const [selectedModules, setSelectedModules] = useState([]);
  const [depth, setDepth] = useState("medium");
  const [threads, setThreads] = useState("4");

  useEffect(() => {
    if (!Array.isArray(availableModules) || !availableModules.length) return;
    setSelectedModules((prev) => {
      if (!prev.length) return [...availableModules];
      const valid = prev.filter((m) => availableModules.includes(m));
      return valid.length ? valid : [...availableModules];
    });
  }, [availableModules]);

  const toggle = (moduleId) => {
    setSelectedModules((prev) =>
      prev.includes(moduleId)
        ? prev.filter((m) => m !== moduleId)
        : [...prev, moduleId]
    );
  };

  const allSelected =
    availableModules.length > 0 && selectedModules.length === availableModules.length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
      <div><div className="page-title">Configure <span className="accent">Scan</span></div><div className="page-sub">Define target · select modules · set parameters</div></div>
      <div className="card card-lit"><div className="card-body">
        <label className="field-label">Target URL</label>
        <div style={{ display: "flex", gap: 10 }}>
          <input className="field" placeholder="https://target.example.com" value={url} onChange={(e) => setUrl(e.target.value)} />
          <button
            className="btn btn-solid"
            style={{ flexShrink: 0 }}
            onClick={() => {
              if (!url || !selectedModules.length) return;
              onLaunch({ url, modules: selectedModules, depth, threads: Number(threads) });
            }}
          >
            Launch ▶
          </button>
        </div>
      </div></div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Scan Modules ({selectedModules.length}/{availableModules.length})</div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              className="btn btn-ghost"
              style={{ padding: "5px 10px", fontSize: 10 }}
              onClick={() => setSelectedModules([...availableModules])}
            >
              Select All
            </button>
            <button
              className="btn btn-ghost"
              style={{ padding: "5px 10px", fontSize: 10 }}
              onClick={() => setSelectedModules([])}
            >
              Clear
            </button>
          </div>
        </div>
        <div className="card-body" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          {availableModules.map((moduleId) => (
            <div
              key={moduleId}
              className={`module-card ${selectedModules.includes(moduleId) ? "on" : ""}`}
              onClick={() => toggle(moduleId)}
            >
              <div style={{ width: 38, height: 38, borderRadius: 9, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 17, background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.07)", flexShrink: 0 }}>🛡️</div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 500 }}>{formatModuleName(moduleId)}</div>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: "#475569", marginTop: 2 }}>{moduleHint(moduleId)}</div>
              </div>
              <Toggle on={selectedModules.includes(moduleId)} onChange={() => toggle(moduleId)} />
            </div>
          ))}
          {!availableModules.length && (
            <div style={{ color: "#475569", fontFamily: "'JetBrains Mono',monospace", fontSize: 11 }}>
              No modules loaded from API.
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header"><div className="card-title">Parameters</div></div>
        <div className="card-body" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div><label className="field-label">Scan Depth</label><select className="field" value={depth} onChange={(e) => setDepth(e.target.value)}><option value="light">Light</option><option value="medium">Medium</option><option value="deep">Deep</option></select></div>
          <div><label className="field-label">Worker Threads</label><select className="field" value={threads} onChange={(e) => setThreads(e.target.value)}>{["1", "2", "4", "8", "16"].map((t) => <option key={t}>{t}</option>)}</select></div>
        </div>
      </div>
    </div>
  );
}

function LivePage({ running, progress, logs }) {
  const ref = useRef(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [logs]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div><div className="page-title">Live <span className="accent">Scanner</span></div><div className="page-sub">Real-time scan telemetry</div></div>
        <div className={`status-pill ${running ? "active" : ""}`}><div className={`dot ${running ? "cyan" : ""}`} />{running ? "SCANNING" : progress === 100 ? "COMPLETE" : "IDLE"}</div>
      </div>

      <div className={`card ${running || progress > 0 ? "card-lit" : ""}`}><div className="card-body">
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: "#475569" }}>{running ? "Scanning..." : progress === 100 ? "Scan complete" : "Awaiting target"}</span>
          <span style={{ fontFamily: "'Syne',sans-serif", fontSize: 18, fontWeight: 800, color: "#63ebd7" }}>{progress}%</span>
        </div>
        <div className="progress-track" style={{ height: 6, borderRadius: 3 }}><div className="progress-fill" style={{ width: `${progress}%` }} /></div>
      </div></div>

      <div className="terminal">
        <div className="terminal-bar">
          <div className="t-dot" style={{ background: "#ff5f57" }} /><div className="t-dot" style={{ background: "#ffbd2e" }} /><div className="t-dot" style={{ background: "#28ca41" }} />
          <span style={{ marginLeft: 8, fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: "#475569", letterSpacing: 1 }}>agent-hunter · output</span>
        </div>
        <div className="terminal-body" ref={ref}>
          {logs.map((l, i) => <div key={`${l.t}-${i}`} className="t-line"><span className="t-ts">[{l.t}]</span><span style={{ color: l.c }}>{l.m}</span></div>)}
        </div>
      </div>
    </div>
  );
}

function FindingsPage({ findings }) {
  const [catF, setCatF] = useState("all");
  const [sevF, setSevF] = useState("all");
  const [sel, setSel] = useState(null);
  const cats = ["all", "web", "network", "sast", "dependency"];
  const sevs = ["all", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const filtered = findings.filter((f) => (catF === "all" || f.cat.includes(catF)) && (sevF === "all" || f.sev === sevF));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div><div className="page-title">Findings <span className="accent">Report</span></div><div className="page-sub">{filtered.length} of {findings.length} findings shown</div></div>
        <button
          className="btn btn-ghost"
          onClick={() => {
            const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: "application/json" });
            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = "findings.json";
            a.click();
            URL.revokeObjectURL(a.href);
          }}
        >
          ⬇ Export JSON
        </button>
      </div>

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
        <div className="tab-filter" style={{ borderBottom: "none", padding: 0, gap: 4 }}>
          {cats.map((c) => <button key={c} className={`tab-btn ${catF === c ? "active" : ""}`} style={{ padding: "7px 12px" }} onClick={() => setCatF(c)}>{c.toUpperCase()}</button>)}
        </div>
        <div style={{ display: "flex", gap: 4, marginLeft: "auto" }}>
          {sevs.map((s) => <button key={s} className={`btn ${sevF === s ? "btn-solid" : "btn-ghost"}`} style={{ padding: "5px 10px", fontSize: 10 }} onClick={() => setSevF(s)}>{s}</button>)}
        </div>
      </div>

      <div className="card">
        <div style={{ display: "grid", gridTemplateColumns: "90px 1fr 80px 100px", gap: 12, padding: "10px 22px", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
          {["Severity", "Finding", "Category", "CVE / CWE"].map((h) => <span key={h} style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, letterSpacing: 2, textTransform: "uppercase", color: "#475569" }}>{h}</span>)}
        </div>
        {filtered.map((f) => (
          <div key={f.id} className={`finding-row ${sel?.id === f.id ? "selected" : ""}`} onClick={() => setSel(sel?.id === f.id ? null : f)}>
            <Badge s={f.sev} />
            <div><div className="find-name">{f.type}</div><div className="find-loc">{f.loc}</div></div>
            <span className="chip">{f.cat}</span>
            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: "#a78bfa" }}>{f.cve}</span>
          </div>
        ))}
      </div>

      {sel && (
        <div className="detail-panel">
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}><Badge s={sel.sev} /><span className="chip">{sel.cat}</span><span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: "#475569", marginLeft: "auto" }}>{sel.ts}</span></div>
          <div className="detail-title">{sel.type}</div>
          <div className="detail-desc">{sel.desc}</div>
        </div>
      )}
    </div>
  );
}

function SettingsPage({ config, onSave }) {
  const [cfg, setCfg] = useState(config);
  useEffect(() => setCfg(config), [config]);
  const set = (k, v) => setCfg((p) => ({ ...p, [k]: v }));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
      <div><div className="page-title">Agent <span className="accent">Settings</span></div><div className="page-sub">Configure scanner behaviour and preferences</div></div>
      <div className="card">
        <div className="card-header"><div className="card-title">Request Configuration</div></div>
        <div className="card-body" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          {[{ k: "timeout", label: "Timeout (seconds)" }, { k: "rateLimit", label: "Rate limit (req/s)" }, { k: "userAgent", label: "User-Agent string", span: 2 }, { k: "proxy", label: "Proxy URL (optional)", span: 2 }, { k: "outputDir", label: "Output directory", span: 2 }].map(({ k, label, span }) => (
            <div key={k} style={{ gridColumn: span ? `span ${span}` : "span 1" }}><label className="field-label">{label}</label><input className="field" value={cfg[k] ?? ""} onChange={(e) => set(k, e.target.value)} /></div>
          ))}
        </div>
      </div>
      <div className="card">
        <div className="card-header"><div className="card-title">Behaviour</div></div>
        <div className="card-body">
          {[{ k: "autoReport", name: "Auto-generate report", desc: "Save report after every scan" }, { k: "verifySsl", name: "Verify SSL certificates", desc: "Reject invalid TLS certs" }, { k: "followRedirects", name: "Follow redirects", desc: "Auto-follow HTTP 3xx" }, { k: "saveLogs", name: "Persist terminal logs", desc: "Write logs to output directory" }].map(({ k, name, desc }) => (
            <div key={k} className="setting-row"><div><div className="setting-name">{name}</div><div className="setting-desc">{desc}</div></div><Toggle on={!!cfg[k]} onChange={(v) => set(k, v)} /></div>
          ))}
        </div>
      </div>
      <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
        <button className="btn btn-danger" onClick={() => setCfg({ timeout: 30, userAgent: "AgentHunter/2.1", rateLimit: 10, proxy: "", outputDir: "./results", autoReport: true, verifySsl: true, followRedirects: true, saveLogs: true })}>Reset defaults</button>
        <button className="btn btn-solid" onClick={() => onSave(cfg)}>Save settings</button>
      </div>
    </div>
  );
}

export default function AgentHunter() {
  const [page, setPage] = useState("dashboard");
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [scanTarget, setScanTarget] = useState("");
  const [scanId, setScanId] = useState(null);
  const [availableModules, setAvailableModules] = useState([]);
  const [settings, setSettings] = useState({ timeout: 30, userAgent: "AgentHunter/2.1", rateLimit: 10, proxy: "", outputDir: "./results", autoReport: true, verifySsl: true, followRedirects: true, saveLogs: true });
  const sseRef = useRef(null);

  useEffect(() => {
    let mounted = true;
    Promise.all([
      listScans().catch(() => []),
      getSettings().catch(() => settings),
      listModules().catch(() => []),
    ]).then(([scans, cfg, modules]) => {
      if (!mounted) return;
      setSettings((prev) => ({ ...prev, ...cfg }));
      setAvailableModules(Array.isArray(modules) ? modules : []);
      if (Array.isArray(scans) && scans.length) {
        const latest = scans[scans.length - 1];
        setScanTarget(latest.target || "");
      }
    });
    return () => { mounted = false; };
  }, []);

  useEffect(() => () => sseRef.current?.close(), []);

  const launch = useCallback(async ({ url, modules, depth, threads }) => {
    sseRef.current?.close();
    setRunning(true);
    setProgress(0);
    setLogs([]);
    setFindings([]);
    setScanTarget(url);
    setPage("live");

    const started = await apiStartScan({
      url,
      modules,
      depth,
      threads,
      verify_ssl: !!settings.verifySsl,
    });

    setScanId(started.scan_id);

    const es = streamScan(started.scan_id);
    sseRef.current = es;

    es.addEventListener("log", (ev) => {
      const d = JSON.parse(ev.data);
      setLogs((prev) => [...prev, { t: d.ts || new Date().toLocaleTimeString("en-GB", { hour12: false }), c: toHexColor(d.msg), m: d.msg }]);
    });

    es.addEventListener("finding", (ev) => {
      const f = normalizeFinding(JSON.parse(ev.data), findings.length);
      setFindings((prev) => [...prev, f]);
    });

    es.addEventListener("phase", (ev) => {
      const { phase } = JSON.parse(ev.data);
      setProgress(PHASE_PROGRESS[phase] ?? 0);
    });

    es.addEventListener("status", (ev) => {
      const { status } = JSON.parse(ev.data);
      if (status === "complete" || status === "error") setRunning(false);
    });

    es.addEventListener("done", async () => {
      try {
        const finalScan = await getScan(started.scan_id);
        setFindings((finalScan.findings || []).map(normalizeFinding));
      } catch {
        // Best effort sync only.
      }
      setProgress(100);
      setRunning(false);
      es.close();
    });

    es.onerror = () => {
      setRunning(false);
    };
  }, [settings.verifySsl, findings.length]);

  const saveAllSettings = useCallback(async (cfg) => {
    const payload = {
      timeout: Number(cfg.timeout) || 30,
      user_agent: cfg.userAgent,
      rate_limit: Number(cfg.rateLimit) || 10,
      proxy: cfg.proxy || "",
      output_dir: cfg.outputDir || "./results",
      auto_report: !!cfg.autoReport,
      verify_ssl: !!cfg.verifySsl,
      follow_redirects: !!cfg.followRedirects,
      save_logs: !!cfg.saveLogs,
    };
    await saveSettings(payload);
    setSettings((prev) => ({ ...prev, ...cfg }));
  }, []);

  const criticalCount = findings.filter((f) => f.sev === "CRITICAL").length;

  const NAV = [
    { id: "dashboard", icon: "⬡", label: "Dashboard" },
    { id: "scan", icon: "◎", label: "New Scan" },
    { id: "live", icon: "◈", label: "Live Scan", pulse: running },
    { id: "findings", icon: "◇", label: "Findings", count: criticalCount },
    { id: "settings", icon: "◉", label: "Settings" },
  ];

  return (
    <>
      <style>{CSS}</style>
      <div className="aurora" />
      <div className="shell">
        <header className="topbar">
          <svg width="30" height="30" viewBox="0 0 30 30" fill="none" style={{ flexShrink: 0 }}>
            <polygon points="15,2 28,9 28,21 15,28 2,21 2,9" stroke="#63ebd7" strokeWidth="1.5" fill="none" opacity="0.8" />
            <polygon points="15,7 23,11.5 23,20.5 15,24 7,20.5 7,11.5" stroke="#a78bfa" strokeWidth="1" fill="none" opacity="0.5" />
            <circle cx="15" cy="15" r="2.5" fill="#63ebd7" />
          </svg>
          <div><div className="logo-text">Agent-Hunter</div><div className="logo-sub">Vulnerability Scanner</div></div>
          <div className="topbar-right">
            <div className={`status-pill ${running ? "active" : ""}`}><div className={`dot ${running ? "cyan" : ""}`} />{running ? "SCANNING" : "READY"}</div>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: "#475569", letterSpacing: 1 }}>v2.1.0</div>
          </div>
        </header>

        <nav className="sidebar">
          <div className="sidebar-section">Navigation</div>
          {NAV.map(({ id, icon, label, pulse, count }) => (
            <button key={id} className={`nav-item ${page === id ? "active" : ""}`} onClick={() => setPage(id)}>
              <span className="nav-icon">{icon}</span>
              <span style={{ flex: 1 }}>{label}</span>
              {pulse && <span className="nav-badge" style={{ background: "rgba(99,235,215,0.1)", color: "#63ebd7", borderColor: "rgba(99,235,215,0.2)" }}>●</span>}
              {count > 0 && !pulse && <span className="nav-badge">{count}</span>}
            </button>
          ))}
          <div className="sidebar-footer">
            <div>Total findings · {findings.length}</div>
            <div style={{ color: "#f87171", marginTop: 2 }}>Critical · {criticalCount}</div>
          </div>
        </nav>

        <main className="main">
          {page === "dashboard" && <Dashboard onNavigate={setPage} scanning={running} findings={findings} scanTarget={scanTarget} />}
          {page === "scan" && <ScanPage onLaunch={launch} availableModules={availableModules} />}
          {page === "live" && <LivePage running={running} progress={progress} logs={logs} />}
          {page === "findings" && <FindingsPage findings={findings} />}
          {page === "settings" && <SettingsPage config={settings} onSave={saveAllSettings} />}
        </main>
      </div>
    </>
  );
}
