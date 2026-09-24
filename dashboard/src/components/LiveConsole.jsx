import { useState } from "react";
import Terminal from "./shared/Terminal";

/**
 * LiveConsole — Screen 4: Watch the scan run in real-time.
 *
 * Updated to show the 7 Cyber Kill Chain stages as the phase stepper.
 *
 * Props:
 *   running    boolean
 *   progress   number (0-100)
 *   phase      string
 *   logs       [{ time, level, scanner, message, color }]
 *   findings   Object[]
 *   scanTarget string
 *   scanId     string
 *   onPause    () => void
 *   onAbort    () => void
 *   onViewReport () => void
 */

// Kill chain phases mapped to backend scan phases
const KILL_CHAIN_PHASES = [
  { key: "recon",      label: "Recon",          icon: "🔍", mapPhases: ["init", "recon"] },
  { key: "weaponize",  label: "Weaponize",      icon: "⚔️", mapPhases: ["strategy"] },
  { key: "deliver",    label: "Deliver",        icon: "📦", mapPhases: ["scan"] },
  { key: "exploit",    label: "Exploit",        icon: "💥", mapPhases: ["scan"] },
  { key: "install",    label: "Install",        icon: "🔧", mapPhases: ["scan"] },
  { key: "c2",         label: "C&C",            icon: "📡", mapPhases: ["validate"] },
  { key: "objective",  label: "Objectives",     icon: "🎯", mapPhases: ["validate", "reflect", "complete"] },
];

// Map backend phase to kill chain step index
function getKillChainIndex(backendPhase, progress) {
  const p = (backendPhase || "init").toLowerCase();
  if (p === "init") return 0;
  if (p === "recon") return 0;
  if (p === "strategy") return 1;
  if (p === "scan") {
    // Distribute scan phase across Deliver(2), Exploit(3), Install(4)
    if (progress < 45) return 2;
    if (progress < 65) return 3;
    return 4;
  }
  if (p === "validate") return 5;
  if (p === "reflect") return 6;
  if (p === "complete") return 7; // all done
  return 0;
}

export default function LiveConsole({
  running,
  progress,
  phase,
  logs,
  findings,
  scanTarget,
  scanId,
  onAbort,
  onViewReport,
  actionError,
}) {
  const [confirmAbort, setConfirmAbort] = useState(false);

  const currentIdx = getKillChainIndex(phase, progress);
  const terminal = ["complete", "error", "aborted", "interrupted"].includes(phase);
  const isComplete = phase === "complete";

  const sevCounts = {
    critical: findings.filter((f) => (f.severity || f.sev) === "CRITICAL").length,
    high: findings.filter((f) => (f.severity || f.sev) === "HIGH").length,
    medium: findings.filter((f) => (f.severity || f.sev) === "MEDIUM").length,
    info: findings.filter((f) => ["LOW", "INFO"].includes((f.severity || f.sev))).length,
  };

  const handleAbort = () => {
    if (!confirmAbort) {
      setConfirmAbort(true);
      setTimeout(() => setConfirmAbort(false), 3000);
      return;
    }
    onAbort?.();
    setConfirmAbort(false);
  };

  // Compute scan duration from logs
  const duration = (() => {
    if (logs.length < 2) return "";
    const first = logs[0]?.time || "";
    const last = logs[logs.length - 1]?.time || "";
    return `${first} → ${last}`;
  })();

  return (
    <div className="screen-enter">
      <div className="screen-container">
        {/* Layout: desktop 70/30, mobile stacked */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "1fr 280px",
          gap: "24px",
        }}>
          {/* Left column */}
          <div style={{ display: "flex", flexDirection: "column", gap: "20px", minWidth: 0 }}>

            {/* Kill Chain stepper */}
            <div style={{
              background: "var(--color-base)",
              border: "1px solid var(--color-border)",
              borderRadius: "10px",
              padding: "16px 20px",
            }}>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: "10px",
                color: "var(--color-text-low)",
                letterSpacing: "1.5px",
                textTransform: "uppercase",
                marginBottom: "12px",
              }}>
                Cyber Kill Chain
              </div>
              <div style={{
                display: "flex",
                alignItems: "center",
                gap: "0",
                justifyContent: "space-between",
              }}>
                {KILL_CHAIN_PHASES.map((kc, i) => {
                  const isDone = i < currentIdx;
                  const isActive = i === currentIdx && running;
                  return (
                    <div key={kc.key} style={{ display: "flex", alignItems: "center", flex: i < KILL_CHAIN_PHASES.length - 1 ? 1 : 0 }}>
                      {/* Node */}
                      <div style={{
                        display: "flex",
                        flexDirection: "column",
                        alignItems: "center",
                        gap: "4px",
                        position: "relative",
                      }}>
                        <div style={{
                          width: "32px",
                          height: "32px",
                          borderRadius: "50%",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontSize: "14px",
                          fontWeight: 600,
                          fontFamily: "var(--font-mono)",
                          flexShrink: 0,
                          background: isDone
                            ? "var(--color-primary-glow)"
                            : isActive
                              ? "var(--color-primary-glow)"
                              : "var(--color-surface)",
                          border: `2px solid ${isDone || isActive ? "var(--color-primary)" : "var(--color-border)"}`,
                          color: isDone || isActive ? "var(--color-primary)" : "var(--color-text-low)",
                          transition: "all 300ms ease",
                        }} className={isActive ? "anim-pulse-ring" : ""}>
                          {isDone ? "✓" : kc.icon}
                        </div>
                        <span style={{
                          fontFamily: "var(--font-mono)",
                          fontSize: "9px",
                          color: isDone || isActive ? "var(--color-text-mid)" : "var(--color-text-low)",
                          whiteSpace: "nowrap",
                          letterSpacing: "0.3px",
                          transition: "color 300ms ease",
                        }}>
                          {kc.label}
                        </span>
                      </div>

                      {/* Connecting line */}
                      {i < KILL_CHAIN_PHASES.length - 1 && (
                        <div style={{
                          flex: 1,
                          height: "2px",
                          marginLeft: "4px",
                          marginRight: "4px",
                          marginBottom: "18px",
                          background: isDone ? "var(--color-primary)" : "var(--color-border)",
                          transition: "background 300ms ease",
                          position: "relative",
                        }}>
                          {isActive && (
                            <div style={{
                              position: "absolute",
                              top: 0,
                              left: 0,
                              height: "100%",
                              width: "50%",
                              background: "var(--color-primary)",
                              borderRadius: "1px",
                              animation: "pulse-width 2s ease-in-out infinite",
                            }} />
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Progress Bar */}
            <div className="progress-bar" style={{ height: "3px" }}>
              <div
                className={`progress-bar-fill ${running ? "anim-progress-shimmer" : ""}`}
                style={{ width: `${progress}%` }}
              />
            </div>

            {/* Controls row */}
            {running && (
              <div style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}>
                <span style={{ color: "var(--color-text-low)", fontFamily: "var(--font-mono)", fontSize: "var(--text-xs)" }}>
                  Pause is unavailable; abort cancels the active task.
                </span>
                <button
                  className="btn btn-danger btn-sm"
                  onClick={handleAbort}
                >
                  {confirmAbort ? "Confirm Abort" : "⬛ Abort"}
                </button>
              </div>
            )}

            {/* Terminal */}
            <Terminal lines={logs} maxLines={2000} />

            {actionError && (
              <div role="alert" style={{ color: "var(--color-critical)", fontFamily: "var(--font-mono)", fontSize: "var(--text-xs)", whiteSpace: "pre-wrap" }}>
                {actionError}
              </div>
            )}

            {/* Scan complete message + CTA */}
            {terminal && (
              <div className="anim-fade-in" style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                <div style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-sm)",
                  color: isComplete ? "var(--color-primary)" : "var(--color-accent)",
                  textAlign: "center",
                  padding: "12px",
                }}>
                  {isComplete ? "Scan complete" : `Scan ${phase}`} · {findings.length} findings · {duration}
                </div>
                <button
                  className="btn btn-primary"
                  onClick={onViewReport}
                  style={{ width: "100%" }}
                >
                  {isComplete ? "View Report →" : "View Partial Results →"}
                </button>
              </div>
            )}
          </div>

          {/* Right column: Severity counters + scan info */}
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {/* Scan info */}
            <div style={{
              background: "var(--color-base)",
              border: "1px solid var(--color-border)",
              borderRadius: "8px",
              padding: "14px",
            }}>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: "10px",
                color: "var(--color-text-low)",
                letterSpacing: "1px",
                textTransform: "uppercase",
                marginBottom: "8px",
              }}>
                Target
              </div>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                color: "var(--color-text-high)",
                wordBreak: "break-all",
              }}>
                {scanTarget || "—"}
              </div>
              {scanId && (
                <div style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "10px",
                  color: "var(--color-text-low)",
                  marginTop: "6px",
                }}>
                  ID: {scanId.slice(0, 8)}...
                </div>
              )}
            </div>

            {/* Severity cards */}
            {[
              { label: "Critical", count: sevCounts.critical, color: "var(--color-critical)", glowColor: "var(--color-critical-glow)" },
              { label: "High",     count: sevCounts.high,     color: "var(--color-high)",     glowColor: "var(--color-accent-glow)" },
              { label: "Medium",   count: sevCounts.medium,   color: "var(--color-medium)",   glowColor: "rgba(59,143,232,0.08)" },
              { label: "Info",     count: sevCounts.info,     color: "var(--color-info)",     glowColor: "rgba(34,192,106,0.08)" },
            ].map((item) => (
              <div key={item.label} style={{
                background: item.count > 0 && item.label === "Critical" ? item.glowColor : "var(--color-base)",
                border: "1px solid var(--color-border)",
                borderLeft: `3px solid ${item.color}`,
                borderRadius: "8px",
                padding: "16px",
                display: "flex",
                flexDirection: "column",
                gap: "4px",
              }}>
                <span style={{
                  fontFamily: "var(--font-ui)",
                  fontSize: "var(--text-xl)",
                  fontWeight: 700,
                  color: item.color,
                  lineHeight: 1,
                }}>
                  {item.count}
                </span>
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
        </div>

        {/* Pulse-width animation */}
        <style>{`
          @keyframes pulse-width {
            0%, 100% { width: 30%; opacity: 0.5; }
            50% { width: 80%; opacity: 1; }
          }
        `}</style>
      </div>
    </div>
  );
}
