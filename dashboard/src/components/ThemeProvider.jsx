import { useState, useEffect } from "react";
import useLocalStorage from "../hooks/useLocalStorage";

/**
 * ThemeProvider — Settings drawer + CSS variable application.
 *
 * Props:
 *   children   React nodes
 */

const THEME_PRESETS = [
  { id: "void-dark",      name: "Void Dark",      primary: "#00C8A0", accent: "#F0A030" },
  { id: "midnight-blue",  name: "Midnight Blue",  primary: "#3B8FE8", accent: "#22D3EE" },
  { id: "terminal-green", name: "Terminal Green",  primary: "#22C06A", accent: "#F0A030" },
  { id: "light",          name: "Light Mode",      primary: "#00A080", accent: "#D08A20" },
];

const ACCENT_SWATCHES = [
  { color: "#00C8A0", label: "Teal" },
  { color: "#3B8FE8", label: "Blue" },
  { color: "#A060E0", label: "Purple" },
  { color: "#22C06A", label: "Green" },
  { color: "#E86050", label: "Coral" },
  { color: "#F0A030", label: "Orange" },
];

const FONT_SIZES = [
  { label: "S", value: 0.9 },
  { label: "M", value: 1 },
  { label: "L", value: 1.1 },
];

const ANIM_SPEEDS = [
  { label: "Off",    value: 0 },
  { label: "Slow",   value: 0.5 },
  { label: "Normal", value: 1 },
  { label: "Fast",   value: 1.5 },
];

const DEFAULT_CONFIG = {
  theme: "void-dark",
  accentColor: "#00C8A0",
  fontScale: 1,
  animSpeed: 1,
  compact: false,
};

export default function ThemeProvider({ children }) {
  const [config, setConfig] = useLocalStorage("hunter_theme", DEFAULT_CONFIG);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(
    () => window.matchMedia("(prefers-reduced-motion: reduce)").matches,
  );

  // Detect reduced motion preference
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const handler = (e) => setPrefersReducedMotion(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  // Apply config to document
  useEffect(() => {
    const root = document.documentElement;

    // Theme preset
    root.setAttribute("data-theme", config.theme);

    // Custom accent color (override --color-primary)
    if (config.accentColor && config.accentColor !== THEME_PRESETS.find((p) => p.id === config.theme)?.primary) {
      root.style.setProperty("--color-primary", config.accentColor);
      // Compute dim version (darken by reducing lightness)
      root.style.setProperty("--color-primary-dim", config.accentColor);
      // Compute glow version
      const hex = config.accentColor.replace("#", "");
      const r = parseInt(hex.substring(0, 2), 16);
      const g = parseInt(hex.substring(2, 4), 16);
      const b = parseInt(hex.substring(4, 6), 16);
      root.style.setProperty("--color-primary-glow", `rgba(${r},${g},${b},0.12)`);
    } else {
      root.style.removeProperty("--color-primary");
      root.style.removeProperty("--color-primary-dim");
      root.style.removeProperty("--color-primary-glow");
    }

    // Font scale
    root.style.setProperty("--font-scale", String(config.fontScale));

    // Animation speed
    const effectiveSpeed = prefersReducedMotion ? 0 : config.animSpeed;
    root.style.setProperty("--anim-speed", String(effectiveSpeed));

    // Density
    root.setAttribute("data-density", config.compact ? "compact" : "normal");
  }, [config, prefersReducedMotion]);

  const updateConfig = (key, value) => {
    setConfig((prev) => ({ ...prev, [key]: value }));
  };

  const resetDefaults = () => {
    setConfig(DEFAULT_CONFIG);
  };

  return (
    <>
      {children}

      {/* Settings cog trigger */}
      <button
        className="topbar-icon-btn"
        onClick={() => setDrawerOpen(!drawerOpen)}
        style={{
          position: "fixed",
          top: "8px",
          right: "8px",
          zIndex: 200,
          width: "32px",
          height: "32px",
        }}
        title="Theme Settings"
      >
        ⚙
      </button>

      {/* Drawer */}
      <div style={{
        position: "fixed",
        top: 0,
        right: 0,
        width: drawerOpen ? "300px" : "0",
        height: "100vh",
        background: "var(--color-base)",
        borderLeft: drawerOpen ? "1px solid var(--color-border)" : "none",
        zIndex: 150,
        overflow: "hidden",
        transition: "width 250ms cubic-bezier(0.16, 1, 0.3, 1)",
      }}>
        <div style={{
          width: "300px",
          height: "100%",
          overflowY: "auto",
          padding: "20px",
          display: "flex",
          flexDirection: "column",
          gap: "24px",
        }}>
          {/* Header */}
          <div style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}>
            <span style={{
              fontFamily: "var(--font-ui)",
              fontSize: "var(--text-md)",
              fontWeight: 600,
              color: "var(--color-text-high)",
            }}>
              Settings
            </span>
            <button
              onClick={() => setDrawerOpen(false)}
              style={{
                background: "none",
                border: "none",
                color: "var(--color-text-low)",
                cursor: "pointer",
                fontSize: "18px",
                padding: "4px",
              }}
            >
              ✕
            </button>
          </div>

          {/* 1. Color Theme Presets */}
          <div>
            <label style={{
              display: "block",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-xs)",
              letterSpacing: "1px",
              textTransform: "uppercase",
              color: "var(--color-text-low)",
              marginBottom: "8px",
            }}>
              Color Theme
            </label>
            <div style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "8px",
            }}>
              {THEME_PRESETS.map((preset) => (
                <div
                  key={preset.id}
                  onClick={() => {
                    updateConfig("theme", preset.id);
                    updateConfig("accentColor", preset.primary);
                  }}
                  style={{
                    padding: "10px",
                    borderRadius: "8px",
                    border: `1px solid ${config.theme === preset.id ? "var(--color-primary)" : "var(--color-border)"}`,
                    background: config.theme === preset.id ? "var(--color-primary-glow)" : "var(--color-surface)",
                    cursor: "pointer",
                    transition: "all 150ms ease",
                  }}
                >
                  <div style={{ display: "flex", gap: "4px", marginBottom: "6px" }}>
                    <div style={{ width: 12, height: 12, borderRadius: "50%", background: preset.primary }} />
                    <div style={{ width: 12, height: 12, borderRadius: "50%", background: preset.accent }} />
                  </div>
                  <span style={{
                    fontFamily: "var(--font-ui)",
                    fontSize: "var(--text-xs)",
                    color: "var(--color-text-mid)",
                    fontWeight: 500,
                  }}>
                    {preset.name}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* 2. Accent Color */}
          <div>
            <label style={{
              display: "block",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-xs)",
              letterSpacing: "1px",
              textTransform: "uppercase",
              color: "var(--color-text-low)",
              marginBottom: "8px",
            }}>
              Accent Color
            </label>
            <input
              type="color"
              value={config.accentColor}
              onChange={(e) => updateConfig("accentColor", e.target.value)}
              style={{
                width: "100%",
                height: "36px",
                border: "1px solid var(--color-border)",
                borderRadius: "6px",
                background: "var(--color-surface)",
                cursor: "pointer",
                marginBottom: "8px",
              }}
            />
            <div style={{ display: "flex", gap: "8px" }}>
              {ACCENT_SWATCHES.map((swatch) => (
                <button
                  key={swatch.color}
                  onClick={() => updateConfig("accentColor", swatch.color)}
                  title={swatch.label}
                  style={{
                    width: "28px",
                    height: "28px",
                    borderRadius: "50%",
                    border: config.accentColor === swatch.color ? "2px solid var(--color-text-high)" : "2px solid transparent",
                    background: swatch.color,
                    cursor: "pointer",
                    transition: "border 150ms ease",
                  }}
                />
              ))}
            </div>
          </div>

          {/* 3. Font Size */}
          <div>
            <label style={{
              display: "block",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-xs)",
              letterSpacing: "1px",
              textTransform: "uppercase",
              color: "var(--color-text-low)",
              marginBottom: "8px",
            }}>
              Interface Size
            </label>
            <div style={{ display: "flex", gap: "8px" }}>
              {FONT_SIZES.map((size) => (
                <button
                  key={size.label}
                  onClick={() => updateConfig("fontScale", size.value)}
                  className={`btn ${config.fontScale === size.value ? "btn-primary" : "btn-outline"}`}
                  style={{ flex: 1, padding: "8px" }}
                >
                  {size.label}
                </button>
              ))}
            </div>
          </div>

          {/* 4. Animation Speed */}
          <div>
            <label style={{
              display: "block",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-xs)",
              letterSpacing: "1px",
              textTransform: "uppercase",
              color: "var(--color-text-low)",
              marginBottom: "8px",
            }}>
              Animation Speed
            </label>
            <div style={{ display: "flex", gap: "6px" }}>
              {ANIM_SPEEDS.map((speed) => (
                <button
                  key={speed.label}
                  onClick={() => !prefersReducedMotion && updateConfig("animSpeed", speed.value)}
                  className={`btn btn-sm ${config.animSpeed === speed.value ? "btn-primary" : "btn-outline"}`}
                  disabled={prefersReducedMotion}
                  style={{ flex: 1 }}
                >
                  {speed.label}
                </button>
              ))}
            </div>
            {prefersReducedMotion && (
              <span style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                color: "var(--color-text-low)",
                marginTop: "4px",
                display: "block",
              }}>
                Disabled: OS prefers reduced motion
              </span>
            )}
          </div>

          {/* 5. Compact Mode */}
          <div>
            <label style={{
              display: "block",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-xs)",
              letterSpacing: "1px",
              textTransform: "uppercase",
              color: "var(--color-text-low)",
              marginBottom: "8px",
            }}>
              Density
            </label>
            <div style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
            }}>
              <span style={{
                fontFamily: "var(--font-ui)",
                fontSize: "var(--text-sm)",
                color: "var(--color-text-mid)",
              }}>
                Compact mode
              </span>
              <div
                className={`toggle ${config.compact ? "on" : ""}`}
                onClick={() => updateConfig("compact", !config.compact)}
              >
                <div className="toggle-track" />
                <div className="toggle-thumb" />
              </div>
            </div>
          </div>

          {/* Spacer */}
          <div style={{ flex: 1 }} />

          {/* Save + Reset */}
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            <button
              className="btn btn-primary"
              style={{ width: "100%" }}
              onClick={() => setDrawerOpen(false)}
            >
              Save preferences
            </button>
            <button
              onClick={resetDefaults}
              style={{
                background: "none",
                border: "none",
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                color: "var(--color-text-low)",
                cursor: "pointer",
                padding: "4px",
                textAlign: "center",
              }}
            >
              Reset to defaults
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
