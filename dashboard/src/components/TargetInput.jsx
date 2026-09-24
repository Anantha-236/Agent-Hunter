import { useState, useCallback } from "react";
import useLocalStorage from "../hooks/useLocalStorage";

/**
 * TargetInput — Screen 1: Enter the target.
 *
 * Props:
 *   onSubmit (target: string) => void
 */

const TARGET_PATTERNS = {
  url:     /^https?:\/\/.+/i,
  domain:  /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/,
  ipv4:    /^(\d{1,3}\.){3}\d{1,3}$/,
  cidr:    /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/,
  ipv6:    /^([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,6}:$/,
};

function validateTarget(input) {
  const trimmed = (input || "").trim();
  if (!trimmed) return null;

  if (TARGET_PATTERNS.url.test(trimmed))    return { type: "URL",     valid: true };
  if (TARGET_PATTERNS.cidr.test(trimmed)) {
    const prefix = parseInt(trimmed.split("/")[1], 10);
    const hosts = Math.pow(2, 32 - prefix);
    return { type: `CIDR · ${hosts.toLocaleString()} hosts`, valid: true };
  }
  if (TARGET_PATTERNS.ipv4.test(trimmed))   return { type: "IPv4",    valid: true };
  if (TARGET_PATTERNS.ipv6.test(trimmed))   return { type: "IPv6",    valid: true };
  if (TARGET_PATTERNS.domain.test(trimmed)) return { type: "Domain",  valid: true };

  // If it could be a partial entry, don't mark invalid yet
  if (trimmed.length < 4) return null;
  return { type: "Invalid format", valid: false };
}

const QUICK_CHIPS = ["localhost", "127.0.0.1", "192.168.1.0/24"];

export default function TargetInput({ onSubmit }) {
  const [target, setTarget] = useState("");
  const [history, setHistory] = useLocalStorage("hunter_target_history", []);
  const [historyOpen, setHistoryOpen] = useState(false);

  const validation = validateTarget(target);
  const isValid = validation?.valid === true;

  const handleSubmit = useCallback(() => {
    if (!isValid) return;
    const trimmed = target.trim();
    // Update history
    const updated = [trimmed, ...history.filter((h) => h !== trimmed)].slice(0, 10);
    setHistory(updated);
    onSubmit(trimmed);
  }, [target, isValid, history, setHistory, onSubmit]);

  const handleKeyDown = (e) => {
    if (e.key === "Enter") handleSubmit();
  };

  const fillTarget = (value) => {
    setTarget(value);
    setHistoryOpen(false);
  };

  return (
    <div className="screen-enter" style={{
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      minHeight: "calc(100vh - 48px)",
      padding: "32px 16px",
    }}>
      {/* Logo + Wordmark */}
      <div style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        marginBottom: "48px",
      }}>
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none" style={{ marginBottom: "16px" }}>
          <polygon points="24,4 44,14 44,34 24,44 4,34 4,14" stroke="var(--color-primary)" strokeWidth="1.5" fill="none" opacity="0.8" />
          <polygon points="24,12 36,18 36,32 24,38 12,32 12,18" stroke="var(--color-text-low)" strokeWidth="1" fill="none" opacity="0.4" />
          <circle cx="24" cy="24" r="3" fill="var(--color-primary)" />
        </svg>
        <div style={{
          fontFamily: "var(--font-ui)",
          fontWeight: 700,
          fontSize: "var(--text-lg)",
          color: "var(--color-text-high)",
          letterSpacing: "1px",
        }}>
          Agent-Hunter
        </div>
        <div style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--text-xs)",
          color: "var(--color-text-low)",
          letterSpacing: "2px",
          marginTop: "4px",
        }}>
          AUTONOMOUS RECONNAISSANCE
        </div>
      </div>

      {/* Input field */}
      <div style={{ width: "100%", maxWidth: "600px" }}>
        <input
          id="target-input"
          className="input-field"
          type="text"
          placeholder="Enter target — domain, IP, or CIDR range"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={handleKeyDown}
          autoFocus
          autoComplete="off"
        />

        {/* Format Validator */}
        <div style={{
          height: "20px",
          marginTop: "6px",
          display: "flex",
          alignItems: "center",
          gap: "6px",
        }}>
          {validation && (
            <>
              <div style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                background: validation.valid ? "var(--color-primary)" : "var(--color-accent)",
                flexShrink: 0,
              }} />
              <span style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                color: "var(--color-text-mid)",
              }}>
                {validation.type}
              </span>
            </>
          )}
        </div>

        {/* Quick Chips */}
        <div style={{
          display: "flex",
          gap: "8px",
          marginTop: "12px",
          flexWrap: "wrap",
        }}>
          {QUICK_CHIPS.map((chip) => (
            <button
              key={chip}
              className="chip"
              onClick={() => fillTarget(chip)}
            >
              {chip}
            </button>
          ))}
        </div>

        {/* History Dropdown */}
        {history.length > 0 && (
          <div style={{ marginTop: "16px", position: "relative" }}>
            <button
              onClick={() => setHistoryOpen(!historyOpen)}
              style={{
                background: "none",
                border: "none",
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                color: "var(--color-text-low)",
                cursor: "pointer",
                padding: "4px 0",
                transition: "color 150ms ease",
              }}
              onMouseEnter={(e) => e.currentTarget.style.color = "var(--color-text-mid)"}
              onMouseLeave={(e) => e.currentTarget.style.color = "var(--color-text-low)"}
            >
              Recent targets {historyOpen ? "▴" : "▾"}
            </button>

            {historyOpen && (
              <div style={{
                position: "absolute",
                top: "100%",
                left: 0,
                right: 0,
                background: "var(--color-base)",
                border: "1px solid var(--color-border)",
                borderRadius: "8px",
                overflow: "hidden",
                zIndex: 20,
                maxHeight: "240px",
                overflowY: "auto",
              }}>
                {history.map((item, i) => (
                  <div
                    key={i}
                    onClick={() => fillTarget(item)}
                    style={{
                      padding: "10px 14px",
                      fontFamily: "var(--font-mono)",
                      fontSize: "var(--text-sm)",
                      color: "var(--color-text-mid)",
                      cursor: "pointer",
                      borderBottom: i < history.length - 1 ? "1px solid var(--color-border)" : "none",
                      transition: "background 150ms ease",
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = "var(--color-surface)"}
                    onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
                  >
                    {item}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* CTA Button */}
        <button
          id="start-recon-btn"
          className="btn btn-primary"
          onClick={handleSubmit}
          disabled={!isValid}
          style={{
            width: "100%",
            height: "48px",
            marginTop: "24px",
          }}
        >
          Start Reconnaissance →
        </button>
      </div>
    </div>
  );
}
