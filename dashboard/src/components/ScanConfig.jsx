import { useState, useEffect } from "react";
import ScannerTile from "./shared/ScannerTile";

/**
 * ScanConfig — Screen 3: Choose scanners, see estimate, launch.
 *
 * Props:
 *   selectedAssets   Object[] from Screen 2
 *   availableModules string[] (module IDs from API)
 *   onLaunch         (config) => void
 *   onBack           () => void
 */

const MODULE_META = {
  sql_injection:      { name: "SQL Injection",       description: "SQL injection detection via error-based and time-based techniques", engine: "python", category: "Vulnerability" },
  ssti:               { name: "SSTI",                description: "Server-side template injection testing", engine: "python", category: "Vulnerability" },
  crlf_injection:     { name: "CRLF Injection",      description: "Header injection and HTTP response splitting", engine: "python", category: "Vulnerability" },
  command_injection:   { name: "Command Injection",   description: "OS command injection testing", engine: "python", category: "Vulnerability" },
  xxe_scanner:        { name: "XXE Scanner",         description: "XML external entity injection tests", engine: "python", category: "Vulnerability" },
  xss_scanner:        { name: "XSS Scanner",         description: "Reflected, stored, and DOM-based XSS detection", engine: "python", category: "Web" },
  ssrf:               { name: "SSRF",                description: "Server-side request forgery detection", engine: "python", category: "Web" },
  graphql_scanner:    { name: "GraphQL Scanner",     description: "GraphQL introspection and attack surface checks", engine: "python", category: "Web" },
  auth_scanner:       { name: "Auth Scanner",        description: "Authentication weakness detection", engine: "python", category: "Web" },
  idor_scanner:       { name: "IDOR Scanner",        description: "Insecure direct object reference checks", engine: "python", category: "Web" },
  csrf_scanner:       { name: "CSRF Scanner",        description: "Cross-site request forgery detection", engine: "python", category: "Web" },
  race_condition:     { name: "Race Condition",      description: "Concurrent request race condition testing", engine: "python", category: "Web" },
  path_traversal:     { name: "Path Traversal",      description: "File path traversal and LFI/RFI tests", engine: "python", category: "Vulnerability" },
  misconfig_scanner:  { name: "Misconfiguration",    description: "Security misconfiguration and hardening checks", engine: "python", category: "Enumeration" },
  host_header:        { name: "Host Header",         description: "Host header injection attack checks", engine: "python", category: "Web" },
  open_redirect:      { name: "Open Redirect",       description: "Open redirect vulnerability testing", engine: "python", category: "Web" },
  subdomain_takeover: { name: "Subdomain Takeover",  description: "Dangling DNS and subdomain takeover checks", engine: "python", category: "Enumeration" },
};

const CATEGORIES = ["Enumeration", "Vulnerability", "Web", "Network"];

// Very rough time estimate per scanner (minutes)
const TIME_PER_SCANNER = 2;

export default function ScanConfig({ selectedAssets, availableModules, onLaunch, onBack }) {
  const [enabledIds, setEnabledIds] = useState(new Set(availableModules));
  const [depth, setDepth] = useState("medium");
  const [threads, setThreads] = useState(4);

  useEffect(() => {
    setEnabledIds(new Set(availableModules));
  }, [availableModules]);

  const toggleScanner = (id) => {
    setEnabledIds((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const scanners = availableModules.map((id) => ({
    id,
    ...(MODULE_META[id] || { name: id.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()), description: "Vulnerability scanner module", engine: "python", category: "Vulnerability" }),
  }));

  const groupedScanners = CATEGORIES.map((cat) => ({
    category: cat,
    scanners: scanners.filter((s) => s.category === cat),
  })).filter((g) => g.scanners.length > 0);

  const estimatedMinutes = enabledIds.size * TIME_PER_SCANNER * (depth === "deep" ? 2 : depth === "light" ? 0.5 : 1);

  // Build target summary text
  const assetSummary = selectedAssets.length <= 3
    ? selectedAssets.map((a) => a.host || a.hostname || a.label || a.id).join(", ")
    : `${selectedAssets.slice(0, 3).map((a) => a.host || a.hostname || a.label || a.id).join(", ")}...and ${selectedAssets.length - 3} more`;

  const handleLaunch = () => {
    if (enabledIds.size === 0) return;
    onLaunch({
      modules: [...enabledIds],
      depth,
      threads,
      assets: selectedAssets,
    });
  };

  return (
    <div className="screen-enter" style={{ paddingBottom: "80px" }}>
      <div className="screen-container">
        {/* Asset summary strip */}
        <div style={{
          background: "var(--color-surface)",
          borderRadius: "8px",
          padding: "12px 16px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "24px",
          flexWrap: "wrap",
          gap: "8px",
        }}>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-sm)",
            color: "var(--color-text-mid)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            flex: 1,
          }}>
            Scanning {selectedAssets.length} assets: {assetSummary}
          </span>
          <button
            className="btn btn-outline btn-sm"
            onClick={onBack}
            style={{ flexShrink: 0 }}
          >
            ← Change
          </button>
        </div>

        {/* Scanner groups */}
        <div style={{ display: "flex", flexDirection: "column", gap: "32px" }}>
          {groupedScanners.map((group) => (
            <div key={group.category}>
              <h3 style={{
                fontFamily: "var(--font-ui)",
                fontSize: "var(--text-md)",
                fontWeight: 600,
                color: "var(--color-text-high)",
                marginBottom: "12px",
              }}>
                {group.category}
              </h3>
              <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
                gap: "12px",
              }}>
                {group.scanners.map((scanner) => (
                  <ScannerTile
                    key={scanner.id}
                    scanner={scanner}
                    enabled={enabledIds.has(scanner.id)}
                    onToggle={toggleScanner}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Parameters */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "16px",
          marginTop: "32px",
        }}>
          <div>
            <label style={{
              display: "block",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-xs)",
              letterSpacing: "1px",
              textTransform: "uppercase",
              color: "var(--color-text-low)",
              marginBottom: "6px",
            }}>
              Scan Depth
            </label>
            <select
              className="input-field"
              style={{ height: "42px", fontSize: "var(--text-sm)" }}
              value={depth}
              onChange={(e) => setDepth(e.target.value)}
            >
              <option value="light">Light</option>
              <option value="medium">Medium</option>
              <option value="deep">Deep</option>
            </select>
          </div>
          <div>
            <label style={{
              display: "block",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-xs)",
              letterSpacing: "1px",
              textTransform: "uppercase",
              color: "var(--color-text-low)",
              marginBottom: "6px",
            }}>
              Worker Threads
            </label>
            <select
              className="input-field"
              style={{ height: "42px", fontSize: "var(--text-sm)" }}
              value={threads}
              onChange={(e) => setThreads(Number(e.target.value))}
            >
              {[1, 2, 4, 8, 16].map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Bottom bar */}
      <div className="bottom-bar">
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--text-xs)",
          color: "var(--color-text-mid)",
        }}>
          Estimated time: ~{Math.ceil(estimatedMinutes)} minutes
        </span>
        <button
          className="btn btn-primary"
          disabled={enabledIds.size === 0}
          onClick={handleLaunch}
        >
          Launch Scan ⚡
        </button>
      </div>
    </div>
  );
}
