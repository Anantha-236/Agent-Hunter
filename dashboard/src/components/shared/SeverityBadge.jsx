/**
 * SeverityBadge — Small pill showing severity level.
 *
 * Props: severity ("critical" | "high" | "medium" | "info")
 */

const SEVERITY_CONFIG = {
  CRITICAL: { color: "var(--color-critical)", bg: "rgba(224,80,80,0.10)", label: "CRITICAL" },
  HIGH:     { color: "var(--color-high)",     bg: "rgba(240,160,48,0.10)", label: "HIGH" },
  MEDIUM:   { color: "var(--color-medium)",   bg: "rgba(59,143,232,0.10)", label: "MEDIUM" },
  INFO:     { color: "var(--color-info)",      bg: "rgba(34,192,106,0.10)", label: "INFO" },
  LOW:      { color: "var(--color-info)",      bg: "rgba(34,192,106,0.10)", label: "LOW" },
};

export default function SeverityBadge({ severity }) {
  const key = (severity || "INFO").toUpperCase();
  const cfg = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.INFO;

  return (
    <span
      className="severity-badge"
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "2px 8px",
        borderRadius: "6px",
        background: cfg.bg,
        color: cfg.color,
        fontFamily: "var(--font-mono)",
        fontSize: "var(--text-xs)",
        fontWeight: 600,
        letterSpacing: "0.5px",
        textTransform: "uppercase",
        whiteSpace: "nowrap",
        lineHeight: 1.6,
      }}
    >
      {cfg.label}
    </span>
  );
}
