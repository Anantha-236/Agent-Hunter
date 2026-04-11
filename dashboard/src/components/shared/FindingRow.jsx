import { useState } from "react";
import SeverityBadge from "./SeverityBadge";

/**
 * FindingRow — Expandable finding row for the report.
 *
 * Props:
 *   finding { id, severity, title, scanner, asset, description, evidence, remediation, cvss, ts }
 */

export default function FindingRow({ finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="finding-row anim-slide-up stagger-item"
      style={{
        borderBottom: "1px solid var(--color-border)",
        transition: "background 150ms ease",
      }}
    >
      {/* Collapsed row */}
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          padding: "13px 20px",
          cursor: "pointer",
        }}
        onMouseEnter={(e) => e.currentTarget.style.background = "var(--color-surface)"}
        onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
      >
        {/* Severity dot */}
        <SeverityBadge severity={finding.severity} />

        {/* Title */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontFamily: "var(--font-ui)",
            fontSize: "var(--text-sm)",
            fontWeight: 500,
            color: "var(--color-text-high)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}>
            {finding.title}
          </div>
          {finding.asset && (
            <div style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-xs)",
              color: "var(--color-text-low)",
              marginTop: "2px",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}>
              {finding.asset}
            </div>
          )}
        </div>

        {/* Scanner badge */}
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          padding: "2px 8px",
          borderRadius: "4px",
          fontFamily: "var(--font-mono)",
          fontSize: "var(--text-xs)",
          color: "var(--color-primary)",
          border: "1px solid var(--color-border)",
        }}>
          {finding.scanner}
        </span>

        {/* Timestamp */}
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--text-xs)",
          color: "var(--color-text-low)",
          whiteSpace: "nowrap",
          flexShrink: 0,
        }}>
          {finding.ts}
        </span>

        {/* Expand indicator */}
        <span style={{
          fontSize: "12px",
          color: "var(--color-text-low)",
          transition: "transform 150ms ease",
          transform: expanded ? "rotate(180deg)" : "rotate(0)",
          flexShrink: 0,
        }}>
          ▾
        </span>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div style={{
          padding: "0 20px 20px 20px",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
        }}>
          {/* Description */}
          {finding.description && (
            <div>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                letterSpacing: "1px",
                textTransform: "uppercase",
                color: "var(--color-text-low)",
                marginBottom: "4px",
              }}>
                Description
              </div>
              <div style={{
                fontSize: "var(--text-sm)",
                color: "var(--color-text-mid)",
                lineHeight: 1.6,
              }}>
                {finding.description}
              </div>
            </div>
          )}

          {/* Evidence */}
          {finding.evidence && (
            <div>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                letterSpacing: "1px",
                textTransform: "uppercase",
                color: "var(--color-text-low)",
                marginBottom: "4px",
              }}>
                Evidence
              </div>
              <pre style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-sm)",
                color: "var(--color-text-high)",
                background: "var(--color-surface)",
                borderRadius: "6px",
                padding: "12px",
                overflow: "auto",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                lineHeight: 1.6,
              }}>
                {finding.evidence}
              </pre>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div style={{
              borderLeft: "3px solid var(--color-accent)",
              paddingLeft: "12px",
            }}>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                letterSpacing: "1px",
                textTransform: "uppercase",
                color: "var(--color-primary)",
                marginBottom: "4px",
              }}>
                Remediation
              </div>
              <div style={{
                fontSize: "var(--text-sm)",
                color: "var(--color-text-mid)",
                lineHeight: 1.6,
              }}>
                {finding.remediation}
              </div>
            </div>
          )}

          {/* CVSS + provenance row */}
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "12px",
            flexWrap: "wrap",
          }}>
            {finding.cvss && (
              <span style={{
                display: "inline-flex",
                alignItems: "center",
                padding: "3px 10px",
                borderRadius: "6px",
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                fontWeight: 600,
                background: "rgba(224,80,80,0.1)",
                color: "var(--color-critical)",
              }}>
                CVSS {finding.cvss}
              </span>
            )}
            <span style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-xs)",
              color: "var(--color-text-low)",
            }}>
              Scanner: {finding.scanner} · Asset: {finding.asset || "—"}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
