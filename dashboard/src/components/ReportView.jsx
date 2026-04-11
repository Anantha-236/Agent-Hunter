import { useState, useEffect, useRef } from "react";
import { getScanReport } from "../api";
import SeverityBadge from "./shared/SeverityBadge";
import FindingRow from "./shared/FindingRow";

/**
 * ReportView — Screen 5: Vulnerability Assessment Report.
 *
 * Shows findings organized by multiple views:
 *   - Assessment Summary: overview with risk posture & severity breakdown
 *   - By Category: grouped by scanner assessment workflow stages
 *   - Kill Chain Analysis: maps findings to Cyber Kill Chain stages
 *   - All Findings: flat list
 *   - By Scanner: grouped by scanner module
 *
 * Props:
 *   findings     Object[]
 *   scanTarget   string
 *   scanId       string
 *   scanDuration string
 *   scanDate     string
 *   scannerCount number
 *   onNewScan    () => void
 */

const SEV_COLORS = {
  critical: "var(--color-critical)",
  high: "var(--color-high, #e67e22)",
  medium: "var(--color-medium)",
  low: "var(--color-info, #3b8fe8)",
  info: "var(--color-info, #22c06a)",
};

const RISK_COLORS = {
  critical: "#e74c3c",
  high: "#e67e22",
  elevated: "#e67e22",
  moderate: "#f1c40f",
  low: "#22c06a",
};

/* ── Assessment Workflow Categories (matches ScanConfig) ── */
const ASSESSMENT_CATEGORIES = [
  { id: "reconnaissance",         name: "Reconnaissance",          icon: "🔍", color: "#95a5a6", modules: ["subdomain_takeover", "ssl_tls_scanner"] },
  { id: "discovery",              name: "Discovery",               icon: "📡", color: "#9b59b6", modules: ["misconfig_scanner", "sensitive_data_exposure", "graphql_scanner"] },
  { id: "vulnerability_assessment", name: "Vulnerability Assessment", icon: "🛡️", color: "#e74c3c", modules: ["sql_injection", "xss_scanner", "command_injection", "ssti", "ssrf", "xxe_scanner", "path_traversal", "lfi_rfi_scanner", "crlf_injection"] },
  { id: "authentication_audit",   name: "Authentication Audit",    icon: "🔑", color: "#2ecc71", modules: ["auth_scanner", "jwt_scanner", "csrf_scanner", "rate_limit_scanner"] },
  { id: "authorization_audit",    name: "Authorization Audit",     icon: "🔒", color: "#1abc9c", modules: ["idor_scanner", "broken_access_control"] },
  { id: "configuration_audit",    name: "Configuration Audit",     icon: "⚙️", color: "#3498db", modules: ["cors_scanner", "header_security", "host_header"] },
  { id: "advanced_testing",       name: "Advanced Testing",        icon: "⚡", color: "#f1c40f", modules: ["open_redirect", "race_condition"] },
];

function CountUpNumber({ value, color }) {
  const [displayed, setDisplayed] = useState(0);
  const ref = useRef(null);

  useEffect(() => {
    const duration = 800;
    const start = performance.now();
    const from = 0;
    const to = value;

    const animate = (now) => {
      const elapsed = now - start;
      const t = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplayed(Math.round(from + (to - from) * eased));
      if (t < 1) ref.current = requestAnimationFrame(animate);
    };

    ref.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(ref.current);
  }, [value]);

  return (
    <span style={{
      fontFamily: "var(--font-ui)",
      fontSize: "var(--text-xl)",
      fontWeight: 700,
      color,
      lineHeight: 1,
    }}>
      {displayed}
    </span>
  );
}

function _mapFindingToCategory(finding) {
  const module = (finding.module || finding.scanner || "").toLowerCase();
  for (const cat of ASSESSMENT_CATEGORIES) {
    if (cat.modules.includes(module)) return cat.id;
  }
  return "vulnerability_assessment";
}

export default function ReportView({
  findings,
  scanTarget,
  scanId,
  scanDuration,
  scanDate,
  scannerCount,
  onNewScan,
}) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("category");
  const [expandedStages, setExpandedStages] = useState(new Set());
  const [expandedCategories, setExpandedCategories] = useState(new Set());

  // Fetch kill chain report from backend
  useEffect(() => {
    if (!scanId) {
      setLoading(false);
      return;
    }

    let mounted = true;
    getScanReport(scanId)
      .then((data) => {
        if (mounted) {
          setReport(data);
          // Auto-expand stages with findings
          const withFindings = new Set();
          (data.kill_chain_stages || []).forEach((s) => {
            if (s.finding_count > 0) withFindings.add(s.id);
          });
          setExpandedStages(withFindings);
        }
      })
      .catch((err) => {
        console.warn("Failed to load kill chain report:", err);
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => { mounted = false; };
  }, [scanId]);

  // Auto-expand categories with findings
  useEffect(() => {
    const withFindings = new Set();
    for (const cat of ASSESSMENT_CATEGORIES) {
      const catFindings = findings.filter((f) => _mapFindingToCategory(f) === cat.id);
      if (catFindings.length > 0) withFindings.add(cat.id);
    }
    setExpandedCategories(withFindings);
  }, [findings]);

  const sevCounts = {
    Critical: findings.filter((f) => f.severity === "CRITICAL").length,
    High: findings.filter((f) => f.severity === "HIGH").length,
    Medium: findings.filter((f) => f.severity === "MEDIUM").length,
    Info: findings.filter((f) => ["LOW", "INFO"].includes(f.severity)).length,
  };

  const toggleStage = (stageId) => {
    setExpandedStages((prev) => {
      const next = new Set(prev);
      if (next.has(stageId)) next.delete(stageId);
      else next.add(stageId);
      return next;
    });
  };

  const toggleCategory = (catId) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(catId)) next.delete(catId);
      else next.add(catId);
      return next;
    });
  };

  // Export functions
  const exportJSON = () => {
    const data = report || { findings, scanTarget, scanDate };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `agent-hunter-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const exportMarkdown = () => {
    let md = `# Agent-Hunter — Vulnerability Assessment Report\n\n`;
    md += `**Target:** ${scanTarget}\n**Date:** ${scanDate}\n**Findings:** ${findings.length}\n\n`;

    // By Category section
    md += `## Assessment Results by Category\n\n`;
    for (const cat of ASSESSMENT_CATEGORIES) {
      const catFindings = findings.filter((f) => _mapFindingToCategory(f) === cat.id);
      if (catFindings.length === 0) continue;
      md += `### ${cat.icon} ${cat.name} (${catFindings.length} findings)\n\n`;
      for (const f of catFindings) {
        md += `- **[${(f.severity || "").toUpperCase()}]** ${f.title || f.vuln_type} — \`${f.url || ""}\`\n`;
      }
      md += `\n`;
    }

    // Kill Chain section
    if (report) {
      const es = report.executive_summary || {};
      md += `## Kill Chain Analysis\n\n`;
      md += `**Risk Posture:** ${es.risk_posture || "N/A"}\n`;
      md += `**Kill Chain Coverage:** ${es.kill_chain_coverage || 0}%\n\n`;

      for (const stage of (report.kill_chain_stages || [])) {
        if (stage.finding_count === 0) continue;
        md += `### ${stage.number}. ${stage.icon} ${stage.name} (${stage.finding_count} findings)\n\n`;
        md += `${stage.description}\n\n`;

        if (stage.architecture_locations?.length) {
          md += `**Architecture Locations:**\n`;
          stage.architecture_locations.forEach((loc) => { md += `- ${loc}\n`; });
          md += `\n`;
        }

        for (const f of (stage.findings || [])) {
          md += `- **[${(f.severity || "").toUpperCase()}]** ${f.title || f.vuln_type} — \`${f.url || ""}\`\n`;
        }
        md += `\n`;
      }

      if (report.attack_paths?.length) {
        md += `## Attack Paths\n\n`;
        for (const path of report.attack_paths) {
          md += `### ${path.name}\n\n${path.description}\n\n`;
          for (const step of (path.steps || [])) {
            md += `${step.stage_number}. **${step.stage_name}** → ${step.finding_title} [${step.finding_severity}]\n`;
          }
          md += `\n`;
        }
      }
    }

    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `agent-hunter-report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const [copied, setCopied] = useState(false);
  const copyAll = () => {
    let md = `# Agent-Hunter Vulnerability Assessment Report\n\nTarget: ${scanTarget}\nDate: ${scanDate}\nFindings: ${findings.length}\n\n`;
    if (report?.executive_summary) {
      md += `Risk: ${report.executive_summary.risk_posture}\nCoverage: ${report.executive_summary.kill_chain_coverage}%\n\n`;
    }
    findings.forEach((f) => {
      md += `## ${f.severity} — ${f.title}\nScanner: ${f.scanner}\nAsset: ${f.asset || "—"}\n${f.description}\n\n`;
    });
    navigator.clipboard.writeText(md).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const stages = report?.kill_chain_stages || [];
  const execSummary = report?.executive_summary || {};
  const attackPaths = report?.attack_paths || [];
  const riskPosture = (execSummary.risk_posture || "").split("—")[0].trim().toLowerCase();

  // Build category groupings
  const categoryData = ASSESSMENT_CATEGORIES.map((cat) => {
    const catFindings = findings.filter((f) => _mapFindingToCategory(f) === cat.id);
    const maxSev = catFindings.reduce((max, f) => {
      const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
      return (rank[(f.severity || "").toUpperCase()] || 0) > (rank[max] || 0) ? (f.severity || "").toLowerCase() : max;
    }, "info");
    return { ...cat, findings: catFindings, maxSev };
  });

  const categoriesWithFindings = categoryData.filter((c) => c.findings.length > 0).length;

  return (
    <div className="screen-enter">
      <div className="screen-container">

        {/* ═══ Assessment Summary Header ═══ */}
        <div style={{
          background: "var(--color-base)",
          border: "1px solid var(--color-border)",
          borderRadius: "10px",
          padding: "20px 24px",
          marginBottom: "24px",
        }}>
          <div style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "16px",
            flexWrap: "wrap",
            gap: "12px",
          }}>
            <div>
              <div style={{
                fontFamily: "var(--font-ui)",
                fontSize: "var(--text-lg, 18px)",
                fontWeight: 700,
                color: "var(--color-text-high)",
                marginBottom: "4px",
              }}>
                🛡️ Vulnerability Assessment Report
              </div>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                color: "var(--color-text-low)",
              }}>
                {scanTarget || "—"} · {scanDate}
              </div>
            </div>

            {/* Risk posture badge */}
            {execSummary.risk_posture && (
              <div style={{
                padding: "8px 16px",
                borderRadius: "8px",
                background: `${RISK_COLORS[riskPosture] || "#888"}15`,
                border: `1px solid ${RISK_COLORS[riskPosture] || "#888"}40`,
              }}>
                <div style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "10px",
                  color: "var(--color-text-low)",
                  letterSpacing: "1px",
                  textTransform: "uppercase",
                  marginBottom: "2px",
                }}>
                  Risk Posture
                </div>
                <div style={{
                  fontFamily: "var(--font-ui)",
                  fontSize: "var(--text-sm)",
                  fontWeight: 700,
                  color: RISK_COLORS[riskPosture] || "var(--color-text-high)",
                }}>
                  {execSummary.risk_posture}
                </div>
              </div>
            )}
          </div>

          {/* Stats row */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
            gap: "12px",
          }}>
            {[
              { label: "Total Findings", value: findings.length, color: "var(--color-text-high)" },
              { label: "Scanners Run", value: scannerCount || 25, color: "var(--color-primary)" },
              { label: "Categories Hit", value: `${categoriesWithFindings}/7`, color: "var(--color-accent, #e67e22)" },
              { label: "Kill Chain Coverage", value: `${execSummary.kill_chain_coverage ?? 0}%`, color: "var(--color-text-mid)" },
            ].map((item) => (
              <div key={item.label} style={{
                display: "flex",
                flexDirection: "column",
                gap: "2px",
              }}>
                <span style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "10px",
                  color: "var(--color-text-low)",
                  textTransform: "uppercase",
                  letterSpacing: "0.8px",
                }}>
                  {item.label}
                </span>
                <span style={{
                  fontFamily: "var(--font-ui)",
                  fontSize: "var(--text-lg, 18px)",
                  fontWeight: 700,
                  color: item.color,
                }}>
                  {typeof item.value === "number" ? <CountUpNumber value={item.value} color={item.color} /> : item.value}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* ═══ Severity Breakdown ═══ */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "12px",
          marginBottom: "24px",
        }}>
          {[
            { label: "Critical", color: "var(--color-critical)", count: sevCounts.Critical },
            { label: "High",     color: "var(--color-high, #e67e22)", count: sevCounts.High },
            { label: "Medium",   color: "var(--color-medium)",   count: sevCounts.Medium },
            { label: "Info",     color: "var(--color-info)",     count: sevCounts.Info },
          ].map((item) => (
            <div key={item.label} style={{
              background: "var(--color-base)",
              border: "1px solid var(--color-border)",
              borderLeft: `3px solid ${item.color}`,
              borderRadius: "8px",
              padding: "16px",
              display: "flex",
              flexDirection: "column",
              gap: "4px",
            }}>
              <CountUpNumber value={item.count} color={item.color} />
              <span style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                color: "var(--color-text-mid)",
                textTransform: "uppercase",
                letterSpacing: "1px",
              }}>
                {item.label}
              </span>
            </div>
          ))}
        </div>

        {/* ═══ Tab Switcher ═══ */}
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          borderBottom: "1px solid var(--color-border)",
          marginBottom: "0",
          flexWrap: "wrap",
          gap: "8px",
        }}>
          <div style={{ display: "flex", gap: "0" }}>
            {[
              { key: "category", label: "By Category" },
              { key: "killchain", label: "Kill Chain" },
              { key: "all", label: "All Findings" },
              { key: "byScanner", label: "By Scanner" },
              { key: "byAsset", label: "By Asset" },
            ].map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                style={{
                  padding: "10px 16px",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-xs)",
                  letterSpacing: "0.5px",
                  color: activeTab === tab.key ? "var(--color-primary)" : "var(--color-text-low)",
                  background: "transparent",
                  border: "none",
                  borderBottom: activeTab === tab.key ? "2px solid var(--color-primary)" : "2px solid transparent",
                  cursor: "pointer",
                  transition: "all 150ms ease",
                  textTransform: "uppercase",
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div style={{ display: "flex", gap: "8px" }}>
            <button className="btn btn-outline btn-sm" onClick={exportJSON}>JSON</button>
            <button className="btn btn-outline btn-sm" onClick={exportMarkdown}>Markdown</button>
            <button className="btn btn-outline btn-sm" onClick={copyAll}>
              {copied ? "Copied ✓" : "Copy All"}
            </button>
          </div>
        </div>

        {/* ═══ Tab Content ═══ */}
        <div style={{
          border: "1px solid var(--color-border)",
          borderTop: "none",
          borderRadius: "0 0 8px 8px",
          overflow: "hidden",
          background: "var(--color-base)",
        }}>

          {/* ─── By Category View (DEFAULT) ─── */}
          {activeTab === "category" && (
            <div>
              {/* Category Progress Bar */}
              <div style={{
                padding: "16px 24px",
                borderBottom: "1px solid var(--color-border)",
                background: "var(--color-surface)",
              }}>
                <div style={{
                  display: "flex",
                  gap: "4px",
                  height: "6px",
                  borderRadius: "3px",
                  overflow: "hidden",
                  background: "var(--color-border)",
                }}>
                  {categoryData.map((cat) => (
                    <div key={cat.id} style={{
                      flex: cat.findings.length > 0 ? Math.max(cat.findings.length, 1) : 0.3,
                      background: cat.findings.length > 0 ? cat.color : "transparent",
                      borderRadius: "2px",
                      opacity: cat.findings.length > 0 ? 1 : 0.2,
                      transition: "all 300ms ease",
                    }} title={`${cat.name}: ${cat.findings.length} findings`} />
                  ))}
                </div>
                <div style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "10px",
                  color: "var(--color-text-low)",
                  marginTop: "8px",
                  letterSpacing: "0.5px",
                }}>
                  {categoriesWithFindings} of 7 assessment categories reported findings
                </div>
              </div>

              {/* Category accordion */}
              {categoryData.map((cat, idx) => {
                const isExpanded = expandedCategories.has(cat.id);
                const hasFindings = cat.findings.length > 0;
                const catColor = cat.color;

                return (
                  <div key={cat.id}>
                    {/* Category header */}
                    <div
                      onClick={() => hasFindings && toggleCategory(cat.id)}
                      style={{
                        padding: "14px 24px",
                        display: "flex",
                        alignItems: "center",
                        gap: "12px",
                        cursor: hasFindings ? "pointer" : "default",
                        borderBottom: "1px solid var(--color-border)",
                        background: isExpanded ? "var(--color-surface)" : "transparent",
                        transition: "background 150ms ease",
                        opacity: hasFindings ? 1 : 0.45,
                      }}
                    >
                      <span style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "10px",
                        fontWeight: 700,
                        color: "#fff",
                        background: catColor,
                        width: "22px",
                        height: "22px",
                        borderRadius: "50%",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        flexShrink: 0,
                      }}>
                        {idx + 1}
                      </span>
                      <span style={{ fontSize: "18px" }}>{cat.icon}</span>
                      <div style={{ flex: 1 }}>
                        <div style={{
                          fontFamily: "var(--font-ui)",
                          fontSize: "var(--text-sm)",
                          fontWeight: 600,
                          color: "var(--color-text-high)",
                        }}>
                          {cat.name}
                        </div>
                        <div style={{
                          fontFamily: "var(--font-mono)",
                          fontSize: "11px",
                          color: "var(--color-text-low)",
                          marginTop: "2px",
                        }}>
                          {cat.modules.length} scanners in this category
                        </div>
                      </div>

                      {/* Finding count + severity */}
                      {hasFindings && (
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{
                            padding: "2px 8px",
                            borderRadius: "4px",
                            background: `${SEV_COLORS[cat.maxSev] || catColor}20`,
                            fontFamily: "var(--font-mono)",
                            fontSize: "10px",
                            color: SEV_COLORS[cat.maxSev] || catColor,
                            fontWeight: 700,
                            textTransform: "uppercase",
                          }}>
                            {cat.maxSev}
                          </span>
                          <span style={{
                            fontFamily: "var(--font-mono)",
                            fontSize: "var(--text-xs)",
                            color: "var(--color-text-mid)",
                          }}>
                            {cat.findings.length} finding{cat.findings.length !== 1 ? "s" : ""}
                          </span>
                          <span style={{
                            fontSize: "12px",
                            color: "var(--color-text-low)",
                            transform: isExpanded ? "rotate(180deg)" : "rotate(0)",
                            transition: "transform 200ms ease",
                          }}>
                            ▼
                          </span>
                        </div>
                      )}
                      {!hasFindings && (
                        <span style={{
                          fontFamily: "var(--font-mono)",
                          fontSize: "11px",
                          color: "var(--color-text-low)",
                        }}>
                          ✓ No findings
                        </span>
                      )}
                    </div>

                    {/* Expanded findings */}
                    {isExpanded && hasFindings && (
                      <div style={{ borderBottom: "1px solid var(--color-border)" }}>
                        {cat.findings.map((f) => (
                          <FindingRow key={f.id} finding={f} />
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}

              {findings.length === 0 && (
                <div style={{
                  padding: "48px",
                  textAlign: "center",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-sm)",
                  color: "var(--color-text-low)",
                }}>
                  No findings detected across any assessment category.
                </div>
              )}
            </div>
          )}

          {/* ─── Kill Chain View ─── */}
          {activeTab === "killchain" && (
            <div>
              {/* Kill Chain Timeline */}
              <div style={{
                padding: "20px 24px",
                borderBottom: "1px solid var(--color-border)",
                background: "var(--color-surface)",
              }}>
                <div style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "10px",
                  color: "var(--color-text-low)",
                  letterSpacing: "1px",
                  textTransform: "uppercase",
                  marginBottom: "12px",
                }}>
                  ⚔️ Cyber Kill Chain Mapping — How attackers could exploit these findings
                </div>
                <div style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "0",
                }}>
                  {stages.map((stage, i) => {
                    const hasFindings = stage.finding_count > 0;
                    const riskColor = SEV_COLORS[stage.risk_level] || "var(--color-text-low)";

                    return (
                      <div key={stage.id} style={{
                        display: "flex",
                        alignItems: "center",
                        flex: i < stages.length - 1 ? 1 : 0,
                      }}>
                        <div
                          onClick={() => hasFindings && toggleStage(stage.id)}
                          style={{
                            display: "flex",
                            flexDirection: "column",
                            alignItems: "center",
                            gap: "4px",
                            cursor: hasFindings ? "pointer" : "default",
                            opacity: hasFindings ? 1 : 0.4,
                            transition: "opacity 200ms ease",
                          }}
                        >
                          <div style={{
                            width: "36px",
                            height: "36px",
                            borderRadius: "50%",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: "16px",
                            background: hasFindings ? `${riskColor}15` : "var(--color-surface)",
                            border: `2px solid ${hasFindings ? riskColor : "var(--color-border)"}`,
                            transition: "all 200ms ease",
                          }}>
                            {stage.icon}
                          </div>
                          <span style={{
                            fontFamily: "var(--font-mono)",
                            fontSize: "9px",
                            color: hasFindings ? "var(--color-text-mid)" : "var(--color-text-low)",
                            whiteSpace: "nowrap",
                          }}>
                            {stage.name}
                          </span>
                          {hasFindings && (
                            <span style={{
                              fontFamily: "var(--font-mono)",
                              fontSize: "9px",
                              color: riskColor,
                              fontWeight: 700,
                            }}>
                              {stage.finding_count}
                            </span>
                          )}
                        </div>

                        {i < stages.length - 1 && (
                          <div style={{
                            flex: 1,
                            height: "2px",
                            margin: "0 4px",
                            marginBottom: hasFindings ? "28px" : "18px",
                            background: hasFindings ? riskColor : "var(--color-border)",
                            opacity: hasFindings ? 0.5 : 0.3,
                          }} />
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Attack Paths */}
              {attackPaths.length > 0 && (
                <div style={{
                  padding: "16px 24px",
                  borderBottom: "1px solid var(--color-border)",
                }}>
                  <div style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "11px",
                    color: "var(--color-text-low)",
                    letterSpacing: "1px",
                    textTransform: "uppercase",
                    marginBottom: "12px",
                  }}>
                    ⚡ Attack Paths
                  </div>
                  {attackPaths.map((path, pi) => (
                    <div key={pi} style={{
                      background: "var(--color-surface)",
                      border: "1px solid var(--color-border)",
                      borderRadius: "8px",
                      padding: "14px",
                      marginBottom: "8px",
                    }}>
                      <div style={{
                        fontFamily: "var(--font-ui)",
                        fontSize: "var(--text-sm)",
                        fontWeight: 600,
                        color: "var(--color-text-high)",
                        marginBottom: "4px",
                      }}>
                        {path.name}
                        <span style={{
                          marginLeft: "8px",
                          fontSize: "10px",
                          padding: "2px 8px",
                          borderRadius: "4px",
                          background: `${RISK_COLORS[path.risk] || "#888"}20`,
                          color: RISK_COLORS[path.risk] || "#888",
                          fontFamily: "var(--font-mono)",
                          textTransform: "uppercase",
                          letterSpacing: "0.5px",
                        }}>
                          {path.risk}
                        </span>
                      </div>
                      <div style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "var(--text-xs)",
                        color: "var(--color-text-mid)",
                        marginBottom: "10px",
                      }}>
                        {path.description}
                      </div>
                      <div style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "4px",
                        flexWrap: "wrap",
                      }}>
                        {(path.steps || []).map((step, si) => (
                          <div key={si} style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                            <div style={{
                              padding: "4px 10px",
                              borderRadius: "6px",
                              background: `${SEV_COLORS[(step.finding_severity || "").toLowerCase()] || "var(--color-text-low)"}15`,
                              border: `1px solid ${SEV_COLORS[(step.finding_severity || "").toLowerCase()] || "var(--color-border)"}30`,
                            }}>
                              <div style={{
                                fontFamily: "var(--font-mono)",
                                fontSize: "9px",
                                color: "var(--color-text-low)",
                                marginBottom: "1px",
                              }}>
                                {step.stage_number}. {step.stage_name}
                              </div>
                              <div style={{
                                fontFamily: "var(--font-mono)",
                                fontSize: "10px",
                                color: "var(--color-text-mid)",
                              }}>
                                {step.finding_title}
                              </div>
                            </div>
                            {si < path.steps.length - 1 && (
                              <span style={{
                                color: "var(--color-text-low)",
                                fontSize: "12px",
                              }}>→</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Stage-by-stage findings */}
              {stages.map((stage) => {
                const isExpanded = expandedStages.has(stage.id);
                const hasFindings = stage.finding_count > 0;
                const riskColor = SEV_COLORS[stage.risk_level] || "var(--color-text-low)";

                return (
                  <div key={stage.id}>
                    {/* Stage header */}
                    <div
                      onClick={() => hasFindings && toggleStage(stage.id)}
                      style={{
                        padding: "14px 24px",
                        display: "flex",
                        alignItems: "center",
                        gap: "12px",
                        cursor: hasFindings ? "pointer" : "default",
                        borderBottom: "1px solid var(--color-border)",
                        background: isExpanded ? "var(--color-surface)" : "transparent",
                        transition: "background 150ms ease",
                        opacity: hasFindings ? 1 : 0.5,
                      }}
                    >
                      <span style={{ fontSize: "18px" }}>{stage.icon}</span>
                      <div style={{ flex: 1 }}>
                        <div style={{
                          fontFamily: "var(--font-ui)",
                          fontSize: "var(--text-sm)",
                          fontWeight: 600,
                          color: "var(--color-text-high)",
                        }}>
                          {stage.number}. {stage.name}
                        </div>
                        <div style={{
                          fontFamily: "var(--font-mono)",
                          fontSize: "11px",
                          color: "var(--color-text-low)",
                          marginTop: "2px",
                        }}>
                          {stage.description}
                        </div>
                      </div>

                      {/* Finding count + risk */}
                      {hasFindings && (
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{
                            padding: "2px 8px",
                            borderRadius: "4px",
                            background: `${riskColor}20`,
                            fontFamily: "var(--font-mono)",
                            fontSize: "10px",
                            color: riskColor,
                            fontWeight: 700,
                            textTransform: "uppercase",
                          }}>
                            {stage.risk_level}
                          </span>
                          <span style={{
                            fontFamily: "var(--font-mono)",
                            fontSize: "var(--text-xs)",
                            color: "var(--color-text-mid)",
                          }}>
                            {stage.finding_count} finding{stage.finding_count !== 1 ? "s" : ""}
                          </span>
                          <span style={{
                            fontSize: "12px",
                            color: "var(--color-text-low)",
                            transform: isExpanded ? "rotate(180deg)" : "rotate(0)",
                            transition: "transform 200ms ease",
                          }}>
                            ▼
                          </span>
                        </div>
                      )}
                      {!hasFindings && (
                        <span style={{
                          fontFamily: "var(--font-mono)",
                          fontSize: "11px",
                          color: "var(--color-text-low)",
                        }}>
                          No findings
                        </span>
                      )}
                    </div>

                    {/* Expanded stage content */}
                    {isExpanded && hasFindings && (
                      <div style={{
                        borderBottom: "1px solid var(--color-border)",
                      }}>
                        {/* Architecture locations */}
                        {stage.architecture_locations?.length > 0 && (
                          <div style={{
                            padding: "12px 24px 12px 60px",
                            borderBottom: "1px solid var(--color-border)",
                            background: "rgba(0,0,0,0.15)",
                          }}>
                            <div style={{
                              fontFamily: "var(--font-mono)",
                              fontSize: "10px",
                              color: "var(--color-text-low)",
                              letterSpacing: "0.8px",
                              textTransform: "uppercase",
                              marginBottom: "6px",
                            }}>
                              🏗️ Architecture Vulnerability Locations
                            </div>
                            {stage.architecture_locations.map((loc, li) => (
                              <div key={li} style={{
                                fontFamily: "var(--font-mono)",
                                fontSize: "var(--text-xs)",
                                color: "var(--color-primary)",
                                padding: "3px 0",
                              }}>
                                → {loc}
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Findings in this stage */}
                        {(stage.findings || []).map((f) => (
                          <FindingRow key={f.id} finding={{
                            ...f,
                            id: f.id,
                            title: f.title || f.vuln_type || "Finding",
                            loc: f.url || "",
                            severity: (f.severity || "LOW").toUpperCase(),
                            scanner: (f.module || "unknown").toLowerCase(),
                            asset: f.url || "",
                            cve: f.cwe_id || "N/A",
                            ts: (f.discovered_at || "").slice(11, 19) || "--:--:--",
                            description: f.description || "No description",
                            where: [
                              f.url ? `URL: ${f.url}` : "",
                              f.parameter ? `Parameter: ${f.parameter}` : "",
                              f.module ? `Module: ${f.module}` : "",
                            ].filter(Boolean).join(" | ") || "Location details not available",
                            evidence: [
                              f.method ? `Method: ${f.method}` : "",
                              f.payload ? `Payload: ${String(f.payload).slice(0, 160)}` : "",
                              f.evidence ? `Evidence: ${String(f.evidence).slice(0, 260)}` : "",
                            ].filter(Boolean).join("\n") || "Technical evidence not available",
                            remediation: f.remediation || "No remediation guidance available",
                            confirmed: f.confirmed || false,
                            confidence: f.confidence || 0,
                          }} />
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}

              {findings.length === 0 && (
                <div style={{
                  padding: "48px",
                  textAlign: "center",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-sm)",
                  color: "var(--color-text-low)",
                }}>
                  No findings detected across any kill chain stage.
                </div>
              )}
            </div>
          )}

          {/* ─── All Findings View ─── */}
          {activeTab === "all" && (
            <div>
              {findings.map((f) => (
                <FindingRow key={f.id} finding={f} />
              ))}
              {findings.length === 0 && (
                <div style={{
                  padding: "48px",
                  textAlign: "center",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-sm)",
                  color: "var(--color-text-low)",
                }}>
                  No findings match the current filter.
                </div>
              )}
            </div>
          )}

          {/* ─── By Scanner View ─── */}
          {activeTab === "byScanner" && (() => {
            const map = {};
            findings.forEach((f) => {
              const key = f.scanner || "unknown";
              (map[key] = map[key] || []).push(f);
            });
            const grouped = Object.entries(map);
            return grouped.map(([groupKey, items]) => (
              <div key={groupKey}>
                <div style={{
                  padding: "10px 20px",
                  background: "var(--color-surface)",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-xs)",
                  color: "var(--color-text-mid)",
                  letterSpacing: "0.5px",
                  textTransform: "uppercase",
                  borderBottom: "1px solid var(--color-border)",
                }}>
                  {groupKey} ({items.length})
                </div>
                {items.map((f) => (
                  <FindingRow key={f.id} finding={f} />
                ))}
              </div>
            ));
          })()}

          {/* ─── By Asset View ─── */}
          {activeTab === "byAsset" && (() => {
            const map = {};
            findings.forEach((f) => {
              const key = f.asset || f.loc || "unknown";
              (map[key] = map[key] || []).push(f);
            });
            const grouped = Object.entries(map);
            return grouped.map(([groupKey, items]) => (
              <div key={groupKey}>
                <div style={{
                  padding: "10px 20px",
                  background: "var(--color-surface)",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-xs)",
                  color: "var(--color-text-mid)",
                  letterSpacing: "0.5px",
                  textTransform: "uppercase",
                  borderBottom: "1px solid var(--color-border)",
                }}>
                  {groupKey} ({items.length})
                </div>
                {items.map((f) => (
                  <FindingRow key={f.id} finding={f} />
                ))}
              </div>
            ));
          })()}
        </div>

        {/* New Scan button */}
        <div style={{ marginTop: "32px", display: "flex", justifyContent: "center" }}>
          <button className="btn btn-outline" onClick={onNewScan}>
            Run New Scan
          </button>
        </div>
      </div>
    </div>
  );
}
