import { useRef, useEffect, useState, useCallback } from "react";

/**
 * Terminal — Scrolling log container.
 *
 * Props:
 *   lines     [{ time, level, scanner, message }]
 *   maxLines  number (default 2000)
 */

const TAG_COLORS = {
  PORT: "var(--color-accent)",
  WEB:  "var(--color-medium)",
  SQLI: "var(--color-primary)",
  DIR:  "#A78BFA",
  INFO: "var(--color-text-low)",
  WARN: "var(--color-accent)",
  ERR:  "var(--color-critical)",
  OK:   "var(--color-primary)",
};

export default function Terminal({ lines = [], maxLines = 2000 }) {
  const containerRef = useRef(null);
  const bottomRef = useRef(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [userScrolledUp, setUserScrolledUp] = useState(false);

  // Trim to maxLines
  const visibleLines = lines.length > maxLines ? lines.slice(-maxLines) : lines;

  // Auto-scroll when new lines arrive
  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "auto" });
    }
  }, [visibleLines.length, autoScroll]);

  // Detect manual scroll
  const handleScroll = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    const isAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setAutoScroll(isAtBottom);
    setUserScrolledUp(!isAtBottom);
  }, []);

  const jumpToBottom = () => {
    setAutoScroll(true);
    setUserScrolledUp(false);
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <div style={{ position: "relative" }}>
      {/* Terminal chrome */}
      <div style={{
        background: "var(--color-void)",
        border: "1px solid var(--color-border)",
        borderRadius: "8px",
        overflow: "hidden",
      }}>
        {/* Title bar */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "6px",
          padding: "8px 14px",
          borderBottom: "1px solid var(--color-border)",
          background: "var(--color-base)",
        }}>
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ff5f57" }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ffbd2e" }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#28ca41" }} />
          <span style={{
            marginLeft: "8px",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-xs)",
            color: "var(--color-text-low)",
            letterSpacing: "1px",
          }}>
            agent-hunter · output
          </span>
        </div>

        {/* Log output */}
        <div
          ref={containerRef}
          onScroll={handleScroll}
          style={{
            padding: "12px 16px",
            height: "340px",
            overflowY: "auto",
            fontFamily: "var(--font-mono)",
            fontSize: "13px",
            lineHeight: 1.8,
          }}
        >
          {visibleLines.map((line, i) => (
            <div
              key={i}
              className="anim-terminal-line"
              style={{
                display: "flex",
                gap: "10px",
                animationDelay: `${Math.max(0, i - visibleLines.length + 10) * 50}ms`,
              }}
            >
              <span style={{ color: "var(--color-text-low)", flexShrink: 0 }}>
                [{line.time}]
              </span>
              <span style={{
                color: TAG_COLORS[line.level] || "var(--color-text-low)",
                flexShrink: 0,
                minWidth: "40px",
                fontWeight: 500,
              }}>
                [{line.level}]
              </span>
              <span style={{ color: line.color || "var(--color-text-mid)" }}>
                {line.message}
              </span>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      </div>

      {/* Jump to latest button */}
      {userScrolledUp && (
        <button
          onClick={jumpToBottom}
          style={{
            position: "absolute",
            bottom: "12px",
            right: "12px",
            display: "flex",
            alignItems: "center",
            gap: "4px",
            padding: "6px 12px",
            borderRadius: "6px",
            background: "var(--color-base)",
            border: "1px solid var(--color-border)",
            color: "var(--color-primary)",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-xs)",
            cursor: "pointer",
            transition: "all 150ms ease",
          }}
        >
          ↓ Jump to latest
        </button>
      )}
    </div>
  );
}
