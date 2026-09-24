import { useState, useEffect, useRef, useCallback } from "react";
import { streamScan, getScan } from "../api";
import { phaseForTerminalStatus } from "../workflow";

/**
 * useScanStream — SSE stream logic with auto-reconnect and persistence.
 *
 * Key improvements:
 *   - Persists scanId to localStorage so page reload can recover
 *   - Auto-reconnects SSE on disconnect with exponential backoff
 *   - Hydrates missed logs/findings from backend on reconnect
 *   - Exposes resume() to reattach to an existing scan
 *
 * Returns { logs, findings, progress, phase, running, error, scanId, launch, resume, reset }
 */

const PHASE_PROGRESS = {
  init: 5,
  recon: 15,
  strategy: 25,
  scan: 55,
  validate: 80,
  reflect: 90,
  complete: 100,
};

const STORAGE_KEY = "agent_hunter_active_scan";

function persistScan(scanId, target) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ scanId, target, ts: Date.now() }));
  } catch { /* quota exceeded or private mode */ }
}

function clearPersistedScan() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch { /* ignore */ }
}

export function getPersistedScan() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const data = JSON.parse(raw);
    // Expire after 2 hours
    if (Date.now() - data.ts > 2 * 60 * 60 * 1000) {
      clearPersistedScan();
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

function normalizeFinding(raw, idx) {
  const sev = (raw.severity || "LOW").toUpperCase();
  const cat = (raw.module || "unknown").toLowerCase();
  const where = [
    raw.url ? `URL: ${raw.url}` : "",
    raw.parameter ? `Parameter: ${raw.parameter}` : "",
    raw.module ? `Module: ${raw.module}` : "",
  ].filter(Boolean).join(" | ");
  const how = [
    raw.method ? `Method: ${raw.method}` : "",
    raw.payload ? `Payload: ${String(raw.payload).slice(0, 160)}` : "",
    raw.evidence ? `Evidence: ${String(raw.evidence).slice(0, 260)}` : "",
  ].filter(Boolean).join("\n");

  return {
    id: raw.id || idx + 1,
    title: raw.title || raw.vuln_type || "Finding",
    loc: raw.url || "",
    severity: sev,
    scanner: cat,
    asset: raw.url || "",
    cve: raw.cwe_id || "N/A",
    ts: (raw.discovered_at || "").slice(11, 19) || "--:--:--",
    description: raw.description || "No description",
    where: where || "Location details not available",
    evidence: how || "Technical evidence not available",
    remediation: raw.remediation || "No remediation guidance available",
    cvss: raw.cvss || null,
    confirmed: raw.confirmed || false,
    confidence: raw.confidence || 0,
    // Kill chain fields (may be present in report data)
    kill_chain_stage: raw.kill_chain_stage || null,
    vuln_type: raw.vuln_type || "",
    module: raw.module || cat,
  };
}

function toLogColor(msg) {
  const m = (msg || "").toLowerCase();
  if (m.includes("critical") || m.includes("error") || m.includes("err")) return "var(--color-critical)";
  if (m.includes("warning") || m.includes("warn")) return "var(--color-accent)";
  if (m.includes("high")) return "var(--color-accent)";
  if (m.includes("medium")) return "var(--color-medium)";
  if (m.includes("complete") || m.includes("ok") || m.includes("success")) return "var(--color-primary)";
  if (m.includes("scan") || m.includes("started")) return "var(--color-primary)";
  return "var(--color-text-mid)";
}

function parseTag(msg) {
  const m = (msg || "").toLowerCase();
  if (m.includes("port")) return "PORT";
  if (m.includes("web") || m.includes("http")) return "WEB";
  if (m.includes("sql")) return "SQLI";
  if (m.includes("dir") || m.includes("path")) return "DIR";
  if (m.includes("warn")) return "WARN";
  if (m.includes("err") || m.includes("fail")) return "ERR";
  if (m.includes("ok") || m.includes("complete") || m.includes("success")) return "OK";
  return "INFO";
}

export default function useScanStream() {
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState("init");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [stats, setStats] = useState({});
  const sseRef = useRef(null);
  const pollRef = useRef(null);
  const reconnectRef = useRef(null);
  const connectSSERef = useRef(null);
  const retriesRef = useRef(0);
  const maxRetries = 8;

  // Cleanup on unmount
  useEffect(() => () => {
    sseRef.current?.close();
    if (pollRef.current) clearInterval(pollRef.current);
    if (reconnectRef.current) clearTimeout(reconnectRef.current);
  }, []);

  const ts = () => new Date().toLocaleTimeString("en-GB", { hour12: false });

  /**
   * Hydrate state from the backend — fetches all logs/findings/phase
   * that may have been accumulated while the frontend was disconnected.
   */
  const hydrateFromBackend = useCallback(async (sid) => {
    try {
      const snapshot = await getScan(sid);
      if (Array.isArray(snapshot.logs)) {
        setLogs(snapshot.logs.map((l) => ({
          time: l.ts || "",
          level: parseTag(l.msg),
          scanner: l.scanner || "",
          message: l.msg,
          color: toLogColor(l.msg),
        })));
      }
      if (Array.isArray(snapshot.findings)) {
        setFindings(snapshot.findings.map(normalizeFinding));
      }
      setStats(snapshot.stats || {});
      if (snapshot.phase) {
        setPhase(snapshot.phase);
        setProgress(PHASE_PROGRESS[snapshot.phase] ?? 0);
      }
      if (["complete", "error", "aborted", "interrupted"].includes(snapshot.status)) {
        setPhase(phaseForTerminalStatus(snapshot.status, snapshot.phase));
        if (snapshot.status === "complete") setProgress(100);
        setRunning(false);
        clearPersistedScan();
        return false; // scan is done
      }
      return true; // scan still running
    } catch {
      return true; // assume still running if we can't reach backend
    }
  }, []);

  /**
   * Connect (or reconnect) the SSE stream for a given scan ID.
   */
  const connectSSE = useCallback((sid) => {
    sseRef.current?.close();
    if (pollRef.current) clearInterval(pollRef.current);

    const es = streamScan(sid);
    sseRef.current = es;

    // Fallback polling (catches anything SSE might miss)
    pollRef.current = setInterval(async () => {
      try {
        const snapshot = await getScan(sid);
        if (Array.isArray(snapshot.findings)) {
          setFindings(snapshot.findings.map(normalizeFinding));
        }
        setStats(snapshot.stats || {});
        if (snapshot.phase) {
          setProgress(PHASE_PROGRESS[snapshot.phase] ?? 0);
          setPhase(snapshot.phase);
        }
        if (["complete", "error", "aborted", "interrupted"].includes(snapshot.status)) {
          setPhase(phaseForTerminalStatus(snapshot.status, snapshot.phase));
          if (snapshot.status === "complete") setProgress(100);
          setRunning(false);
          clearInterval(pollRef.current);
          es.close();
          clearPersistedScan();
        }
      } catch {
        /* best effort */
      }
    }, 3000);

    es.addEventListener("log", (ev) => {
      try {
        const d = JSON.parse(ev.data);
        setLogs((prev) => [...prev, {
          time: d.ts || ts(),
          level: parseTag(d.msg),
          scanner: d.scanner || "",
          message: d.msg,
          color: toLogColor(d.msg),
        }]);
      } catch { /* skip malformed */ }
    });

    es.addEventListener("finding", (ev) => {
      try {
        const f = normalizeFinding(JSON.parse(ev.data), 0);
        setFindings((prev) => [...prev, f]);
      } catch { /* skip */ }
    });

    es.addEventListener("phase", (ev) => {
      try {
        const { phase: p } = JSON.parse(ev.data);
        setPhase(p);
        setProgress(PHASE_PROGRESS[p] ?? 0);
      } catch { /* skip */ }
    });

    es.addEventListener("stats", (ev) => {
      try {
        setStats(JSON.parse(ev.data));
      } catch { /* skip malformed */ }
    });

    es.addEventListener("status", (ev) => {
      try {
        const { status } = JSON.parse(ev.data);
        if (["complete", "error", "aborted", "interrupted"].includes(status)) {
          setPhase(phaseForTerminalStatus(status, "init"));
          setRunning(false);
          clearPersistedScan();
        }
      } catch { /* skip */ }
    });

    es.addEventListener("scan_error", (ev) => {
      try {
        const d = JSON.parse(ev.data);
        const errors = Array.isArray(d.errors) ? d.errors : [d.error || d.msg || "Scan error"];
        setLogs((prev) => [
          ...prev,
          ...errors.filter(Boolean).map((msg) => ({
            time: ts(),
            level: "ERR",
            scanner: "",
            message: msg,
            color: "var(--color-critical)",
          })),
        ]);
        setRunning(false);
        clearInterval(pollRef.current);
        clearPersistedScan();
      } catch { /* skip */ }
    });

    es.addEventListener("done", async (ev) => {
      let terminalStatus = "complete";
      try {
        terminalStatus = JSON.parse(ev.data).status || "complete";
      } catch { /* use complete fallback */ }
      try {
        const finalScan = await getScan(sid);
        setFindings((finalScan.findings || []).map(normalizeFinding));
        setStats(finalScan.stats || {});
      } catch { /* best effort */ }
      if (terminalStatus === "complete") setProgress(100);
      setPhase(phaseForTerminalStatus(terminalStatus, "init"));
      setRunning(false);
      clearInterval(pollRef.current);
      es.close();
      clearPersistedScan();
    });

    // Auto-reconnect on SSE disconnect with exponential backoff
    es.onerror = () => {
      es.close();
      retriesRef.current += 1;

      if (retriesRef.current > maxRetries) {
        setError("Scan stream disconnected — max retries exceeded. The scan is still running on the server.");
        // Keep polling to track completion
        return;
      }

      const delay = Math.min(1000 * Math.pow(2, retriesRef.current - 1), 30000);
      setError(`Stream disconnected — reconnecting in ${Math.round(delay / 1000)}s (attempt ${retriesRef.current}/${maxRetries})`);

      reconnectRef.current = setTimeout(async () => {
        setError(null);
        // Re-hydrate from backend before reconnecting SSE
        const stillRunning = await hydrateFromBackend(sid);
        if (stillRunning) {
          connectSSERef.current?.(sid);
        }
      }, delay);
    };

    // Reset retry counter on successful connection
    es.onopen = () => {
      retriesRef.current = 0;
      setError(null);
    };
  }, [hydrateFromBackend]);
  useEffect(() => {
    connectSSERef.current = connectSSE;
  }, [connectSSE]);

  /**
   * Launch a new scan stream (called after POST /api/scan).
   */
  const launch = useCallback(async (startedScanId, target) => {
    // Cleanup any previous stream
    sseRef.current?.close();
    if (pollRef.current) clearInterval(pollRef.current);
    if (reconnectRef.current) clearTimeout(reconnectRef.current);

    setRunning(true);
    setProgress(0);
    setPhase("init");
    setLogs([]);
    setFindings([]);
    setStats({});
    setError(null);
    setScanId(startedScanId);
    retriesRef.current = 0;

    // Persist to localStorage for reload recovery
    persistScan(startedScanId, target || "");

    connectSSE(startedScanId);
  }, [connectSSE]);

  /**
   * Resume an existing scan (reconnect after page reload).
   * Hydrates all state from backend, then opens SSE if still running.
   */
  const resume = useCallback(async (existingScanId) => {
    sseRef.current?.close();
    if (pollRef.current) clearInterval(pollRef.current);
    if (reconnectRef.current) clearTimeout(reconnectRef.current);

    setScanId(existingScanId);
    setRunning(true);
    setError(null);
    retriesRef.current = 0;

    // Hydrate everything from the backend
    const stillRunning = await hydrateFromBackend(existingScanId);

    if (stillRunning) {
      // Reconnect SSE for live updates
      connectSSE(existingScanId);
    } else {
      // Scan already done — just show the results
      clearPersistedScan();
    }
  }, [hydrateFromBackend, connectSSE]);

  const reset = useCallback(() => {
    sseRef.current?.close();
    if (pollRef.current) clearInterval(pollRef.current);
    if (reconnectRef.current) clearTimeout(reconnectRef.current);
    setLogs([]);
    setFindings([]);
    setStats({});
    setProgress(0);
    setPhase("init");
    setRunning(false);
    setError(null);
    setScanId(null);
    clearPersistedScan();
  }, []);

  return {
    logs,
    findings,
    progress,
    phase,
    running,
    error,
    scanId,
    stats,
    launch,
    resume,
    reset,
    normalizeFinding,
  };
}

export { normalizeFinding, PHASE_PROGRESS };
