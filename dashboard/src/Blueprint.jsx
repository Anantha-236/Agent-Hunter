import { useState } from "react";
import { Link } from "react-router-dom";
import "./blueprint.css";

const TABS = ["Architecture", "AI Models", "Attack Chains", "Capabilities", "vs Competition", "Roadmap"];

const ATTACK_CHAINS = [
    {
        name: "Full Account Takeover via API Chain",
        color: "var(--cyan)",
        nodes: [
            { type: "active", step: "Step 1 — Recon", title: "API Endpoint Discovery", detail: "GraphQL introspection leak exposes all mutations" },
            { type: "active", step: "Step 2 — Fingerprint", title: "Auth Token Analysis", detail: "JWT with weak secret, no expiry claim" },
            { type: "exploit", step: "Step 3 — Exploit", title: "JWT Forgery", detail: "Forge admin token using alg:none bypass" },
            { type: "pivot", step: "Step 4 — Pivot", title: "IDOR Discovery", detail: "Admin token reveals /users/{id} without ownership check" },
            { type: "impact", step: "Step 5 — Impact", title: "Full Account Takeover", detail: "Read/modify any user account, extract PII at scale" },
        ]
    },
    {
        name: "Cloud Privilege Escalation Chain",
        color: "var(--purple)",
        nodes: [
            { type: "active", step: "Step 1 — Recon", title: "S3 Bucket Enum", detail: "Public bucket found via cert transparency + naming patterns" },
            { type: "active", step: "Step 2 — Extract", title: "Credentials in Bucket", detail: ".env file with AWS_ACCESS_KEY_ID exposed" },
            { type: "exploit", step: "Step 3 — Exploit", title: "IAM Enumeration", detail: "Key has iam:ListPolicies — map all attached permissions" },
            { type: "pivot", step: "Step 4 — Escalate", title: "PrivEsc via PassRole", detail: "iam:PassRole + ec2:RunInstances = full admin escalation" },
            { type: "impact", step: "Step 5 — Impact", title: "Full AWS Account Control", detail: "Create admin user, access all services, exfil data" },
        ]
    },
    {
        name: "XSS → Session Steal → IDOR Chain",
        color: "var(--amber)",
        nodes: [
            { type: "active", step: "Step 1 — Probe", title: "XSS Discovery", detail: "Reflected XSS in search param, no CSP, HttpOnly absent" },
            { type: "exploit", step: "Step 2 — Payload", title: "Cookie Exfil Payload", detail: "JS payload exfils session cookie to attacker endpoint" },
            { type: "pivot", step: "Step 3 — Hijack", title: "Session Takeover", detail: "Replayed session cookie grants victim's account access" },
            { type: "pivot", step: "Step 4 — Escalate", title: "IDOR on Orders API", detail: "Victim is admin — enumerate /api/orders/{id} across users" },
            { type: "impact", step: "Step 5 — Impact", title: "Mass Order Data Breach", detail: "Full PII + payment metadata on 10k+ orders exfiltrated" },
        ]
    }
];

const CAPABILITIES = [
    { domain: "Web Application", cap: "XSS — Reflected, Stored, DOM, Mutation", status: "built", level: 5, color: "var(--cyan)" },
    { domain: "Web Application", cap: "SQL Injection — Error, Blind, Time-based, OOB", status: "built", level: 5, color: "var(--cyan)" },
    { domain: "Web Application", cap: "SSRF — Blind, Semi-blind, Cloud metadata", status: "built", level: 4, color: "var(--cyan)" },
    { domain: "Web Application", cap: "IDOR / Broken Object Level Auth", status: "built", level: 4, color: "var(--cyan)" },
    { domain: "Web Application", cap: "Auth Bypass — JWT, OAuth, SAML, Session fixation", status: "built", level: 4, color: "var(--cyan)" },
    { domain: "API Security", cap: "GraphQL introspection, batching, injection", status: "wip", level: 3, color: "var(--amber)" },
    { domain: "API Security", cap: "REST parameter pollution, mass assignment", status: "wip", level: 3, color: "var(--amber)" },
    { domain: "API Security", cap: "gRPC reflection abuse, proto injection", status: "plan", level: 1, color: "var(--text3)" },
    { domain: "Cloud", cap: "AWS IAM misconfiguration, S3 public buckets", status: "plan", level: 2, color: "var(--text3)" },
    { domain: "Cloud", cap: "Azure AD misconfiguration, storage accounts", status: "plan", level: 1, color: "var(--text3)" },
    { domain: "Cloud", cap: "GCP metadata server, service account abuse", status: "plan", level: 1, color: "var(--text3)" },
    { domain: "Network & Infra", cap: "Port scan, service fingerprint, CVE matching", status: "built", level: 4, color: "var(--cyan)" },
    { domain: "Network & Infra", cap: "SSL/TLS audit — ciphers, cert chain, HSTS", status: "built", level: 4, color: "var(--cyan)" },
    { domain: "Network & Infra", cap: "DNS zone transfer, subdomain takeover", status: "wip", level: 3, color: "var(--amber)" },
    { domain: "Mobile", cap: "APK decompilation, hardcoded secrets", status: "plan", level: 2, color: "var(--text3)" },
    { domain: "Mobile", cap: "iOS IPA analysis, insecure storage", status: "plan", level: 1, color: "var(--text3)" },
    { domain: "Social Eng", cap: "OSINT — LinkedIn, GitHub secret leaks, dorks", status: "wip", level: 3, color: "var(--amber)" },
    { domain: "Social Eng", cap: "Phishing simulation payload generation", status: "plan", level: 1, color: "var(--text3)" },
    { domain: "AI Core", cap: "RL policy — module selection & prioritisation", status: "built", level: 5, color: "var(--green)" },
    { domain: "AI Core", cap: "Chain discovery — multi-step exploit reasoning", status: "wip", level: 3, color: "var(--amber)" },
    { domain: "AI Core", cap: "Self-learning — cross-engagement memory", status: "wip", level: 2, color: "var(--amber)" },
    { domain: "AI Core", cap: "WAF evasion — payload mutation with LLM", status: "wip", level: 3, color: "var(--amber)" },
];

const COMPARE_ROWS = [
    { feat: "Fully autonomous (zero human input)", tenable: false, burp: false, cobalt: false, agent: true },
    { feat: "RL-based scanner selection", tenable: false, burp: false, cobalt: false, agent: true },
    { feat: "Chained exploit discovery", tenable: false, burp: "partial", cobalt: "partial", agent: true },
    { feat: "Self-learning across engagements", tenable: false, burp: false, cobalt: false, agent: true },
    { feat: "WAF evasion (LLM-powered)", tenable: false, burp: "partial", cobalt: "partial", agent: true },
    { feat: "Cloud misconfiguration (AWS/GCP/Azure)", tenable: true, burp: false, cobalt: "partial", agent: true },
    { feat: "API — GraphQL, gRPC", tenable: "partial", burp: true, cobalt: false, agent: true },
    { feat: "Automatic PoC generation", tenable: false, burp: false, cobalt: true, agent: true },
    { feat: "HackerOne-ready report export", tenable: false, burp: false, cobalt: false, agent: true },
    { feat: "Pre-engagement compliance gate", tenable: false, burp: false, cobalt: false, agent: true },
    { feat: "Social engineering + OSINT", tenable: false, burp: false, cobalt: true, agent: true },
    { feat: "Mobile (APK/IPA analysis)", tenable: "partial", burp: "partial", cobalt: false, agent: true },
];

const AI_MODELS = [
    {
        name: "Recon-LLM", role: "Intelligence", color: "var(--cyan)",
        desc: "Passive & active recon reasoning",
        rows: [
            ["Base model", "Fine-tuned GPT-4o / Claude"],
            ["Input", "Target URL, IP, org name"],
            ["Output", "Subdomain list, tech stack, exposure map"],
            ["Tools", "Shodan, crt.sh, SecurityTrails, WHOIS"],
            ["Status", "In design"],
        ]
    },
    {
        name: "RL-Policy", role: "Decision Engine", color: "var(--green)",
        desc: "Decides which scanner module to dispatch",
        rows: [
            ["Algorithm", "PPO + Linear Function Approx"],
            ["State", "EnvironmentState (tech, WAF, ports…)"],
            ["Action space", "9 scanner categories"],
            ["Reward", "ConfidenceAwareReward + shaping"],
            ["Status", "✓ Built & tested (59 tests pass)"],
        ]
    },
    {
        name: "Exploit-GPT", role: "Attack Reasoning", color: "var(--red)",
        desc: "Generates & mutates payloads, reasons about chains",
        rows: [
            ["Base model", "GPT-4o with pentest fine-tune"],
            ["Input", "Vulnerability context + WAF type"],
            ["Output", "Mutated payload, chain hypothesis"],
            ["Memory", "Vector DB of successful payloads"],
            ["Status", "Planned — Phase 2"],
        ]
    },
    {
        name: "Chain-Reasoner", role: "Exploit Chaining", color: "var(--purple)",
        desc: "Builds A→B→C multi-step attack paths",
        rows: [
            ["Approach", "Graph search over vuln graph"],
            ["Input", "All findings from current scan"],
            ["Output", "Ranked attack chains + impact score"],
            ["Novel", "No existing tool does this autonomously"],
            ["Status", "Planned — Phase 2"],
        ]
    },
    {
        name: "WAF-Evader", role: "Evasion Layer", color: "var(--amber)",
        desc: "Mutates blocked payloads using LLM reasoning",
        rows: [
            ["Approach", "LLM + genetic algorithm hybrid"],
            ["Input", "Blocked payload + WAF vendor fingerprint"],
            ["Output", "Evasion payload variants"],
            ["Supports", "Cloudflare, Akamai, AWS WAF, F5"],
            ["Status", "In progress — Phase 1"],
        ]
    },
    {
        name: "Report-Writer", role: "Output Layer", color: "var(--orange)",
        desc: "Produces enterprise-grade pentest reports",
        rows: [
            ["Output formats", "PDF, DOCX, H1 JSON, CVSS sheet"],
            ["Sections", "Exec summary, findings, PoC, remediation"],
            ["CVSS", "Auto-scored v3.1 per finding"],
            ["Integrations", "HackerOne, Jira, Slack"],
            ["Status", "Prototype ready — Phase 1"],
        ]
    },
];

const ARCH_LAYERS = [
    {
        title: "Intelligence Layer", icon: "🧠", color: "var(--cyan)",
        items: [
            { text: "Passive Recon — WHOIS, DNS, crt.sh, Shodan", cls: "hot" },
            { text: "Active Recon — port scan, service detection" },
            { text: "Tech fingerprinting — CMS, framework, version" },
            { text: "OSINT — GitHub, LinkedIn, Google dorks", cls: "" },
            { text: "Threat intel — CVE feeds, exploit-db", cls: "" },
        ]
    },
    {
        title: "Decision Layer (RL Core)", icon: "⚡", color: "var(--green)",
        items: [
            { text: "RL Policy — PPO module selection", cls: "hot" },
            { text: "Chain Reasoner — multi-step exploit graph", cls: "hot" },
            { text: "WAF Evader — payload mutation engine", cls: "warn" },
            { text: "Memory — cross-engagement learning", cls: "warn" },
            { text: "Scope enforcer — bbp_policy compliance", cls: "" },
        ]
    },
    {
        title: "Execution Layer", icon: "🔥", color: "var(--red)",
        items: [
            { text: "Web scanners — XSS, SQLi, SSRF, IDOR, Auth", cls: "hot" },
            { text: "API scanners — REST, GraphQL, gRPC", cls: "warn" },
            { text: "Cloud scanners — AWS, GCP, Azure", cls: "" },
            { text: "Network scanners — ports, SSL, DNS", cls: "hot" },
            { text: "Payload engine — dynamic payload gen", cls: "warn" },
        ]
    },
    {
        title: "Auth & Safety Layer", icon: "🛡", color: "var(--purple)",
        items: [
            { text: "Identity verification + session audit", cls: "crit" },
            { text: "NOC / NDA document gate", cls: "crit" },
            { text: "Scope lock — in/out enforcement at runtime", cls: "crit" },
            { text: "BBP policy engine — rate limiting, PII halt", cls: "" },
            { text: "Legal disclaimer + audit trail", cls: "" },
        ]
    },
    {
        title: "Output Layer", icon: "📋", color: "var(--orange)",
        items: [
            { text: "Auto CVSS v3.1 scoring", cls: "" },
            { text: "Enterprise PDF pentest report", cls: "" },
            { text: "HackerOne submission JSON", cls: "hot" },
            { text: "PoC generation per finding", cls: "warn" },
            { text: "Executive summary + remediation plan", cls: "" },
        ]
    },
    {
        title: "Integration Layer", icon: "🔗", color: "var(--amber)",
        items: [
            { text: "HackerOne / Bugcrowd APIs", cls: "hot" },
            { text: "Shodan, SecurityTrails, VirusTotal", cls: "" },
            { text: "Jira, Slack, PagerDuty alerting", cls: "" },
            { text: "Nmap, Nuclei, SQLmap (wrapped)", cls: "" },
            { text: "AWS / GCP / Azure SDKs", cls: "" },
        ]
    },
];

// ── RENDER HELPERS ──────────────────────────────────────────────────────────────

function Dot({ color, filled }) {
    return <div className="lvl-dot" style={{ background: filled ? color : "var(--bg3)", border: `1px solid ${filled ? color : "var(--border2)"}` }} />;
}

function StatusTag({ status }) {
    const cls = { built: "st-built", wip: "st-wip", plan: "st-plan" }[status];
    const label = { built: "✓ BUILT", wip: "IN PROGRESS", plan: "PLANNED" }[status];
    return <span className={`status-tag ${cls}`}>{label}</span>;
}

function CellVal({ v }) {
    if (v === true) return <span className="c-yes">✓</span>;
    if (v === false) return <span className="c-no">—</span>;
    if (v === "partial") return <span className="c-partial">◐</span>;
    return <span className="c-agent">{v}</span>;
}

// ── BLUEPRINT PAGE ──────────────────────────────────────────────────────────────

export default function Blueprint() {
    const [tab, setTab] = useState(0);

    return (
        <div className="app">
            {/* Header */}
            <div className="hdr">
                <div className="logo">
                    <div className="logo-hex">
                        <svg viewBox="0 0 14 14" fill="none">
                            <path d="M7 1L12 3.5V10.5L7 13L2 10.5V3.5L7 1Z" stroke="#000" strokeWidth="1.5" strokeLinejoin="round" />
                            <circle cx="7" cy="7" r="2" fill="#000" />
                        </svg>
                    </div>
                    AGENT <em>HUNTER</em>
                </div>
                <div className="hdr-right">
                    <Link to="/" style={{ color: "var(--text3)", textDecoration: "none", fontSize: 10, border: "1px solid var(--border2)", padding: "3px 10px", borderRadius: 20, letterSpacing: 1, transition: "all 0.2s" }}>← DASHBOARD</Link>
                    <Link to="/" style={{ color: "var(--bg)", textDecoration: "none", fontSize: 10, background: "var(--cyan)", padding: "3px 10px", borderRadius: 20, letterSpacing: 1, fontWeight: 700, transition: "all 0.2s" }}>🚀 LAUNCH AGENT</Link>
                    <span>ENTERPRISE PENTEST AGENT</span>
                    <span className="hdr-pill cyan">ARCHITECTURE BLUEPRINT</span>
                </div>
            </div>

            {/* Hero */}
            <div className="hero">
                <div className="hero-bg" /><div className="hero-grid" />
                <h1>The World's Most Advanced<br /><span>Autonomous Pentest Agent</span></h1>
                <p className="hero-sub">SELF-LEARNING · CHAIN-EXPLOITING · FULLY AUTONOMOUS · ENTERPRISE-GRADE</p>
                <div className="hero-badges">
                    <span className="hb hb-cyan">RL-POWERED DECISIONS</span>
                    <span className="hb hb-red">CHAINED EXPLOIT DISCOVERY</span>
                    <span className="hb hb-green">SELF-LEARNING MEMORY</span>
                    <span className="hb hb-amber">WAF EVASION AI</span>
                    <span className="hb hb-purple">MULTI-MODEL PIPELINE</span>
                </div>
            </div>

            {/* Tabs */}
            <div className="tabs">
                {TABS.map((t, i) => <div key={t} className={`tab ${tab === i ? "active" : ""}`} onClick={() => setTab(i)}>{t}</div>)}
            </div>

            {/* Content */}
            <div className="content">

                {/* ── TAB 0: ARCHITECTURE ── */}
                {tab === 0 && <>
                    <div className="section-hdr">
                        <h2>System Architecture</h2>
                        <div className="sh-line" />
                        <p>6-layer autonomous agent stack</p>
                    </div>
                    <div className="note">
                        <strong>Core principle:</strong> Agent Hunter doesn't scan — it <em>thinks</em>. Every layer feeds context upward. The RL policy at the centre reasons about the full picture before selecting the next attack vector. Nothing fires without scope enforcement. Everything is logged.
                    </div>
                    <div className="arch-grid">
                        {ARCH_LAYERS.map(l => (
                            <div className="layer-card" key={l.title} style={{ borderColor: l.color + "44" }}>
                                <div className="layer-head" style={{ background: l.color + "0a" }}>
                                    <div className="layer-icon" style={{ background: l.color + "22" }}>{l.icon}</div>
                                    <span className="layer-title" style={{ color: l.color }}>{l.title}</span>
                                </div>
                                <div className="layer-body">
                                    {l.items.map(item => <div key={item.text} className={`layer-item ${item.cls || ""}`}>{item.text}</div>)}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Flow */}
                    <div className="section-hdr" style={{ marginTop: 32 }}>
                        <h2>Engagement Flow</h2><div className="sh-line" />
                    </div>
                    <div className="flow">
                        <div className="flow-row">
                            {[
                                { color: "cyan", label: "INPUT", title: "Mission Config", items: ["Target URL/IP", "In/Out scope", "Customer instructions", "Scan intensity"] },
                                { color: "purple", label: "GATE", title: "Pre-Engagement", items: ["Identity verify", "NOC + NDA upload", "Scope lock", "Legal sign-off"] },
                                { color: "cyan", label: "PHASE 1", title: "Passive Recon", items: ["WHOIS/DNS", "Subdomain enum", "Cert transparency", "OSINT sweep"] },
                                { color: "cyan", label: "PHASE 2", title: "Active Recon", items: ["Port scan", "WAF detect", "Service finger-print", "Header audit"] },
                            ].map(n => (
                                <div key={n.title} className={`flow-node ${n.color}`}>
                                    <div className="fn-label">{n.label}</div>
                                    <div className="fn-title">{n.title}</div>
                                    <div className="fn-items">{n.items.map(i => <span key={i} className="fn-tag">{i}</span>)}</div>
                                </div>
                            ))}
                        </div>
                        <div className="flow-arrow">↓</div>
                        <div className="flow-row">
                            {[
                                { color: "green", label: "RL CORE", title: "Policy Decision", items: ["State encode", "Module rank", "Chain hypothesis", "Execution queue"] },
                                { color: "red", label: "EXECUTE", title: "Attack Modules", items: ["XSS / SQLi / SSRF", "Auth bypass / IDOR", "Cloud misconfig", "API / GraphQL"] },
                                { color: "amber", label: "ADAPT", title: "Evasion + Learn", items: ["WAF mutation", "Payload retry", "Memory update", "Reward signal"] },
                                { color: "orange", label: "OUTPUT", title: "Report + Submit", items: ["CVSS scoring", "PoC generation", "PDF report", "H1 submission"] },
                            ].map(n => (
                                <div key={n.title} className={`flow-node ${n.color}`}>
                                    <div className="fn-label">{n.label}</div>
                                    <div className="fn-title">{n.title}</div>
                                    <div className="fn-items">{n.items.map(i => <span key={i} className="fn-tag">{i}</span>)}</div>
                                </div>
                            ))}
                        </div>
                    </div>
                </>}

                {/* ── TAB 1: AI MODELS ── */}
                {tab === 1 && <>
                    <div className="section-hdr">
                        <h2>Multi-Model AI Pipeline</h2><div className="sh-line" />
                        <p>6 specialised models, each owning a distinct phase</p>
                    </div>
                    <div className="note">
                        <strong>Why multi-model?</strong> No single LLM is best at recon reasoning, RL decision-making, payload mutation, AND report writing simultaneously. Agent Hunter uses a specialised model per phase — each fine-tuned and evaluated independently, then orchestrated by <strong>Hunter_brain.py</strong>.
                    </div>
                    <div className="models-grid">
                        {AI_MODELS.map(m => (
                            <div className="model-card" key={m.name} style={{ borderColor: m.color + "44" }}>
                                <div className="mc-head" style={{ background: m.color + "0a" }}>
                                    <div>
                                        <div className="mc-name" style={{ color: m.color }}>{m.name}</div>
                                        <div style={{ fontSize: 10, color: "var(--text2)", marginTop: 2 }}>{m.desc}</div>
                                    </div>
                                    <span className="mc-role" style={{ background: m.color + "22", color: m.color, border: `1px solid ${m.color}44` }}>{m.role}</span>
                                </div>
                                <div className="mc-body">
                                    {m.rows.map(([k, v]) => (
                                        <div className="mc-row" key={k}>
                                            <span className="mc-key">{k}</span>
                                            <span className="mc-val">{v}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </>}

                {/* ── TAB 2: ATTACK CHAINS ── */}
                {tab === 2 && <>
                    <div className="section-hdr">
                        <h2>Chained Exploit Discovery</h2><div className="sh-line" />
                        <p>A→B→C attack paths — the capability no existing tool has</p>
                    </div>
                    <div className="note">
                        <strong>What makes this different:</strong> Burp and Tenable find individual vulnerabilities. Agent Hunter's <strong>Chain-Reasoner</strong> model builds a graph of all findings and discovers how they connect into multi-step attack paths — the kind of chained exploits that real hackers use but automated tools miss entirely.
                    </div>
                    {ATTACK_CHAINS.map(chain => (
                        <div key={chain.name} style={{ marginBottom: 28 }}>
                            <div style={{ fontSize: 12, fontWeight: 600, color: chain.color, marginBottom: 12, letterSpacing: 0.5 }}>
                                ⛓ {chain.name}
                            </div>
                            <div className="chain">
                                {chain.nodes.map((node, i) => (
                                    <div key={`${chain.name}-node-${i}`} style={{ display: "flex", alignItems: "stretch" }}>
                                        <div className={`chain-node ${node.type}`}>
                                            <div className="cn-step">{node.step}</div>
                                            <div className="cn-title">{node.title}</div>
                                            <div className="cn-detail">{node.detail}</div>
                                        </div>
                                        {i < chain.nodes.length - 1 && <div className="chain-arrow">→</div>}
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </>}

                {/* ── TAB 3: CAPABILITIES ── */}
                {tab === 3 && <>
                    <div className="section-hdr">
                        <h2>Capability Matrix</h2><div className="sh-line" />
                        <p>Current build status across all attack domains</p>
                    </div>
                    <table className="matrix">
                        <thead>
                            <tr>
                                <th>Domain</th><th>Capability</th><th>Maturity</th><th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {CAPABILITIES.map(c => (
                                <tr key={c.cap}>
                                    <td style={{ color: "var(--text3)", fontSize: 10, whiteSpace: "nowrap" }}>{c.domain}</td>
                                    <td><span className="cap-name">{c.cap}</span></td>
                                    <td>
                                        <div className="lvl">
                                            {[1, 2, 3, 4, 5].map(n => <Dot key={n} color={c.color} filled={n <= c.level} />)}
                                        </div>
                                    </td>
                                    <td><StatusTag status={c.status} /></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </>}

                {/* ── TAB 4: COMPETITION ── */}
                {tab === 4 && <>
                    <div className="section-hdr">
                        <h2>vs. Tenable · Burp Suite Pro · Cobalt Strike</h2><div className="sh-line" />
                    </div>
                    <div className="note">
                        <strong>The gap is real:</strong> Every existing tool is either a scanner (passive, signature-based) or a manual framework (requires an expert operator). Agent Hunter is the only system that combines autonomous reasoning, self-learning, and chained exploitation in a single pipeline.
                    </div>
                    <table className="compare">
                        <thead>
                            <tr>
                                <th>Capability</th>
                                <th>Tenable</th>
                                <th>Burp Suite Pro</th>
                                <th>Cobalt Strike</th>
                                <th style={{ color: "var(--cyan)" }}>Agent Hunter</th>
                            </tr>
                        </thead>
                        <tbody>
                            {COMPARE_ROWS.map(r => (
                                <tr key={r.feat}>
                                    <td>{r.feat}</td>
                                    <td><CellVal v={r.tenable} /></td>
                                    <td><CellVal v={r.burp} /></td>
                                    <td><CellVal v={r.cobalt} /></td>
                                    <td><CellVal v={r.agent} /></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    <div style={{ marginTop: 12, fontSize: 10, color: "var(--text3)" }}>
                        ✓ = full support &nbsp;◐ = partial / manual &nbsp;— = not supported
                    </div>
                </>}

                {/* ── TAB 5: ROADMAP ── */}
                {tab === 5 && <>
                    <div className="section-hdr">
                        <h2>Build Roadmap</h2><div className="sh-line" />
                        <p>From current state to world's most advanced pentest agent</p>
                    </div>
                    <div className="roadmap">
                        {[
                            {
                                num: "PHASE 01", title: "Foundation Complete", timeline: "Now → 4 weeks",
                                color: "var(--cyan)",
                                items: [
                                    { strong: "RL Agent v2", text: "59 tests passing, benchmarks saved, CI pipeline live" },
                                    { strong: "Pre-engagement gate", text: "Identity, NOC/NDA, scope lock, legal disclaimer fully enforced" },
                                    { strong: "Web scanner suite", text: "XSS, SQLi, SSRF, IDOR, Auth bypass — all operational" },
                                    { strong: "Report prototype", text: "PDF export, CVSS scoring, H1-ready JSON format" },
                                    { strong: "WAF Evader v1", text: "Basic payload mutation for Cloudflare, AWS WAF" },
                                ]
                            },
                            {
                                num: "PHASE 02", title: "Intelligence Upgrade", timeline: "4 → 12 weeks",
                                color: "var(--amber)",
                                items: [
                                    { strong: "Chain Reasoner", text: "Graph-based multi-step exploit discovery engine" },
                                    { strong: "Exploit-GPT", text: "LLM fine-tuned on CVE + payload data for attack reasoning" },
                                    { strong: "Cross-engagement memory", text: "Vector DB — agent learns from every past scan" },
                                    { strong: "API scanner suite", text: "GraphQL introspection, REST mass assignment, gRPC" },
                                    { strong: "Cloud scanner v1", text: "AWS S3, IAM misconfiguration, exposed metadata" },
                                ]
                            },
                            {
                                num: "PHASE 03", title: "World-Class Agent", timeline: "12 → 24 weeks",
                                color: "var(--green)",
                                items: [
                                    { strong: "Mobile scanner", text: "APK decompilation, IPA analysis, hardcoded secrets" },
                                    { strong: "Full cloud coverage", text: "AWS + GCP + Azure privilege escalation chains" },
                                    { strong: "Social engineering OSINT", text: "LinkedIn, GitHub, Google dork automation + phishing sim" },
                                    { strong: "Enterprise UI", text: "Full React dashboard, real-time WebSocket pipeline feed" },
                                    { strong: "Certifications", text: "SOC2 Type II audit, ISO 27001 alignment, legal framework" },
                                ]
                            }
                        ].map(p => (
                            <div className="phase-card" key={p.num} style={{ borderColor: p.color + "44" }}>
                                <div className="phase-head" style={{ background: p.color + "08" }}>
                                    <div className="phase-num">{p.num}</div>
                                    <div className="phase-title" style={{ color: p.color }}>{p.title}</div>
                                    <div className="phase-timeline">{p.timeline}</div>
                                </div>
                                <div className="phase-body">
                                    {p.items.map(item => (
                                        <div className="phase-item" key={item.strong}>
                                            <span className="pi-num">→</span>
                                            <span className="pi-text"><strong>{item.strong}</strong>{item.text}</span>
                                        </div>
                                    ))}
                                </div>
                                <div style={{ padding: "10px 18px", borderTop: "1px solid var(--border)" }}>
                                    <span className="phase-tag" style={{ background: p.color + "15", color: p.color, border: `1px solid ${p.color}33` }}>
                                        {p.num === "PHASE 01" ? "CURRENT FOCUS" : p.num === "PHASE 02" ? "NEXT SPRINT" : "NORTH STAR"}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </>}

            </div>
        </div>
    );
}
