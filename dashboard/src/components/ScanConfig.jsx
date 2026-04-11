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

const CATEGORY_META = {
  "Injection":         { icon: "💉", color: "#e74c3c", desc: "Server-side code/command execution" },
  "Client-Side":       { icon: "🌐", color: "#e67e22", desc: "Browser-based attack vectors" },
  "File Access":       { icon: "📂", color: "#f39c12", desc: "Unauthorized file system access" },
  "SSRF":              { icon: "🔗", color: "#9b59b6", desc: "Internal network reachability" },
  "Authentication":    { icon: "🔑", color: "#2ecc71", desc: "Auth weakness & credential issues" },
  "Authorization":     { icon: "🛡️", color: "#1abc9c", desc: "Access control bypass" },
  "Misconfiguration":  { icon: "⚙️", color: "#3498db", desc: "Insecure server/app configuration" },
  "Redirect":          { icon: "↪️", color: "#e74c3c", desc: "Unvalidated redirects" },
  "Business Logic":    { icon: "⚡", color: "#f1c40f", desc: "Race conditions & logic flaws" },
  "Reconnaissance":    { icon: "🔍", color: "#95a5a6", desc: "Infrastructure & TLS posture" },
};

const MODULE_META = {
  /* ── Injection (6) ── */
  sql_injection:       { name: "SQL Injection",       description: "Error-based, time-based, boolean, UNION & NoSQL injection", engine: "python", category: "Injection" },
  command_injection:   { name: "Command Injection",   description: "OS command execution via shell operators & encoding bypass", engine: "python", category: "Injection" },
  ssti:                { name: "SSTI",                description: "Server-side template injection across 10+ engines with RCE POCs", engine: "python", category: "Injection" },
  crlf_injection:      { name: "CRLF Injection",      description: "HTTP header injection, response splitting & cache poisoning", engine: "python", category: "Injection" },
  xxe_scanner:         { name: "XXE Scanner",          description: "XML External Entity — file read, SSRF, XInclude, SVG & SOAP", engine: "python", category: "Injection" },
  graphql_scanner:     { name: "GraphQL Scanner",      description: "Introspection, BOLA, batch queries, depth DoS & SQLi via GraphQL", engine: "python", category: "Injection" },

  /* ── Client-Side (1) ── */
  xss_scanner:         { name: "XSS Scanner",          description: "Reflected, stored & DOM-based XSS with context-aware detection", engine: "python", category: "Client-Side" },

  /* ── File Access (2) ── */
  path_traversal:      { name: "Path Traversal",       description: "Directory traversal (Linux + Windows), null bytes & PHP wrappers", engine: "python", category: "File Access" },
  lfi_rfi_scanner:     { name: "LFI / RFI",            description: "Local/Remote File Inclusion via PHP filter wrappers & encoding", engine: "python", category: "File Access" },

  /* ── SSRF (1) ── */
  ssrf:                { name: "SSRF",                 description: "Internal network, cloud metadata (AWS/GCP/Azure/DO), URL schemes", engine: "python", category: "SSRF" },

  /* ── Authentication (4) ── */
  auth_scanner:        { name: "Auth Scanner",         description: "JWT alg:none, default credentials, password reset & OAuth flaws", engine: "python", category: "Authentication" },
  jwt_scanner:         { name: "JWT Scanner",          description: "Weak signing secrets, missing expiration & alg:none bypass", engine: "python", category: "Authentication" },
  csrf_scanner:        { name: "CSRF Scanner",         description: "Missing CSRF tokens on forms & token validation bypass testing", engine: "python", category: "Authentication" },
  rate_limit_scanner:  { name: "Rate Limit Scanner",   description: "Missing rate limiting & X-Forwarded-For header bypass detection", engine: "python", category: "Authentication" },

  /* ── Authorization (2) ── */
  idor_scanner:        { name: "IDOR Scanner",         description: "Insecure Direct Object Reference, write-IDOR, HPP & path IDOR", engine: "python", category: "Authorization" },
  broken_access_control: { name: "Broken Access Control", description: "Unauthenticated admin access, horizontal privesc & method exposure", engine: "python", category: "Authorization" },

  /* ── Misconfiguration (5) ── */
  misconfig_scanner:   { name: "Misconfiguration",     description: "95+ sensitive paths, security headers, CORS, cookies & methods", engine: "python", category: "Misconfiguration" },
  cors_scanner:        { name: "CORS Scanner",         description: "Origin reflection, null origin trust & wildcard+credentials", engine: "python", category: "Misconfiguration" },
  header_security:     { name: "Header Security",      description: "Missing/weak CSP, HSTS, X-Frame-Options & Referrer-Policy", engine: "python", category: "Misconfiguration" },
  sensitive_data_exposure: { name: "Sensitive Data",    description: "Exposed .env, .git, backups, actuator endpoints & leaked secrets", engine: "python", category: "Misconfiguration" },
  host_header:         { name: "Host Header",          description: "Host header injection, password reset poisoning & cache poisoning", engine: "python", category: "Misconfiguration" },

  /* ── Redirect (1) ── */
  open_redirect:       { name: "Open Redirect",        description: "32 payloads including encoding bypass, meta-refresh & JS redirect", engine: "python", category: "Redirect" },

  /* ── Business Logic (1) ── */
  race_condition:      { name: "Race Condition",        description: "TOCTOU via concurrent requests — coupon reuse, double payments", engine: "python", category: "Business Logic" },

  /* ── Reconnaissance (2) ── */
  subdomain_takeover:  { name: "Subdomain Takeover",    description: "Dangling DNS to 20+ services (S3, GitHub, Azure, Heroku, etc.)", engine: "python", category: "Reconnaissance" },
  ssl_tls_scanner:     { name: "SSL/TLS Scanner",       description: "Certificate issues, legacy TLS 1.0/1.1, weak ciphers & expiry", engine: "python", category: "Reconnaissance" },
};

const CATEGORIES = [
  "Injection", "Client-Side", "File Access", "SSRF",
  "Authentication", "Authorization", "Misconfiguration",
  "Redirect", "Business Logic", "Reconnaissance",
];

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
    ...(MODULE_META[id] || { name: id.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()), description: "Vulnerability scanner module", engine: "python", category: "Injection" }),
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
        <div style={{ display: "flex", flexDirection: "column", gap: "28px" }}>
          {groupedScanners.map((group) => {
            const meta = CATEGORY_META[group.category] || {};
            const enabledCount = group.scanners.filter((s) => enabledIds.has(s.id)).length;
            const badgeBg = (meta.color || "#888") + "19";
            return (
              <div key={group.category}>
                <div style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  marginBottom: "12px",
                }}>
                  <span style={{ fontSize: "1.3rem" }}>{meta.icon || "📦"}</span>
                  <h3 style={{
                    fontFamily: "var(--font-ui)",
                    fontSize: "var(--text-md)",
                    fontWeight: 600,
                    color: "var(--color-text-high)",
                    margin: 0,
                  }}>
                    {group.category}
                  </h3>
                  <span style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-xs)",
                    color: meta.color || "var(--color-text-low)",
                    background: badgeBg,
                    padding: "2px 8px",
                    borderRadius: "12px",
                    fontWeight: 600,
                  }}>
                    {enabledCount}/{group.scanners.length}
                  </span>
                  <span style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-xs)",
                    color: "var(--color-text-low)",
                    marginLeft: "auto",
                  }}>
                    {meta.desc || ""}
                  </span>
                </div>
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
            );
          })}
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
