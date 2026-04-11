/**
 * AssetCard — Card for a discovered asset (subdomain, port, service, tech).
 *
 * Props:
 *   asset    { id, type, host, tech[], url, service, ip, port }
 *   selected boolean
 *   onToggle (assetId) => void
 */

const TYPE_ICONS = {
  subdomain: "🌐",
  port: "🔌",
  service: "⚙",
  tech: "📦",
  default: "◈",
};

export default function AssetCard({ asset, selected, onToggle }) {
  const icon = TYPE_ICONS[asset.type] || TYPE_ICONS.default;

  return (
    <div
      className={`asset-card anim-slide-up stagger-item`}
      onClick={() => onToggle(asset.id)}
      style={{
        background: selected ? "var(--color-primary-glow)" : "var(--color-base)",
        border: `1px solid ${selected ? "var(--color-primary)" : "var(--color-border)"}`,
        borderRadius: "8px",
        padding: "16px",
        display: "flex",
        alignItems: "center",
        gap: "12px",
        cursor: "pointer",
        transition: "all 150ms ease",
      }}
    >
      {/* Type icon */}
      <span style={{
        fontSize: "20px",
        width: "28px",
        textAlign: "center",
        flexShrink: 0,
        filter: "grayscale(100%)",
        opacity: 0.7,
      }}>
        {icon}
      </span>

      {/* Details */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--text-sm)",
          fontWeight: 500,
          color: "var(--color-text-high)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}>
          {asset.host || asset.label || asset.id}
        </div>
        {(asset.tech && asset.tech.length > 0) && (
          <div style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-xs)",
            color: "var(--color-text-mid)",
            marginTop: "2px",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}>
            {asset.tech.join(" · ")}
          </div>
        )}
        {asset.service && asset.service !== "unknown" && asset.service !== "resolved" && (
          <div style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-xs)",
            color: "var(--color-text-low)",
            marginTop: "2px",
          }}>
            {asset.service.toUpperCase()}{asset.port ? ` · :${asset.port}` : ""}{asset.ip ? ` · ${asset.ip}` : ""}
          </div>
        )}
      </div>

      {/* Checkbox */}
      <div style={{
        width: "20px",
        height: "20px",
        borderRadius: "4px",
        border: `2px solid ${selected ? "var(--color-primary)" : "var(--color-border)"}`,
        background: selected ? "var(--color-primary)" : "transparent",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        flexShrink: 0,
        transition: "all 150ms ease",
      }}>
        {selected && (
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2.5 6L5 8.5L9.5 3.5" stroke="#070A10" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        )}
      </div>
    </div>
  );
}
