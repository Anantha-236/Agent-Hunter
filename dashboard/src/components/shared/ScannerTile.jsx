/**
 * ScannerTile — Tile for a scanner module.
 *
 * Props:
 *   scanner   { id, name, description, engine, category }
 *   enabled   boolean
 *   onToggle  (scannerId) => void
 */

export default function ScannerTile({ scanner, enabled, onToggle }) {
  return (
    <div
      className="scanner-tile"
      style={{
        background: enabled ? "var(--color-primary-glow)" : "var(--color-base)",
        border: `1px solid ${enabled ? "var(--color-primary)" : "var(--color-border)"}`,
        borderRadius: "8px",
        padding: "16px",
        cursor: "pointer",
        transition: "all 150ms ease",
      }}
      onClick={() => onToggle(scanner.id)}
    >
      {/* Top row: name + toggle */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        marginBottom: "8px",
      }}>
        <span style={{
          fontFamily: "var(--font-ui)",
          fontSize: "var(--text-sm)",
          fontWeight: 600,
          color: "var(--color-text-high)",
        }}>
          {scanner.name}
        </span>

        {/* Toggle switch */}
        <div
          className={`toggle ${enabled ? "on" : ""}`}
          onClick={(e) => { e.stopPropagation(); onToggle(scanner.id); }}
        >
          <div className="toggle-track" />
          <div className="toggle-thumb" />
        </div>
      </div>

      {/* Description */}
      <div style={{
        fontFamily: "var(--font-ui)",
        fontSize: "var(--text-sm)",
        color: "var(--color-text-mid)",
        lineHeight: 1.5,
        display: "-webkit-box",
        WebkitLineClamp: 2,
        WebkitBoxOrient: "vertical",
        overflow: "hidden",
        marginBottom: "8px",
      }}>
        {scanner.description}
      </div>

      {/* Engine badge */}
      {scanner.engine && (
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          padding: "2px 8px",
          borderRadius: "4px",
          fontFamily: "var(--font-mono)",
          fontSize: "var(--text-xs)",
          color: "var(--color-text-low)",
          border: "1px solid var(--color-border)",
          letterSpacing: "0.5px",
        }}>
          {scanner.engine}
        </span>
      )}
    </div>
  );
}
