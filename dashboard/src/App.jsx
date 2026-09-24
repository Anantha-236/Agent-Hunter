import { useState, useCallback, useEffect } from "react";
import {
  startScan as apiStartScan,
  listScans,
  listModules,
  getSettings,
  getActiveScan,
  getScan,
  abortScan as apiAbortScan,
} from "./api";
import { buildScanRequest } from "./workflow";

import TargetInput from "./components/TargetInput";
import AssetDiscovery from "./components/AssetDiscovery";
import ScanConfig from "./components/ScanConfig";
import LiveConsole from "./components/LiveConsole";
import ReportView from "./components/ReportView";
import useScanStream from "./hooks/useScanStream";
import { getPersistedScan } from "./hooks/useScanStream";

import "./index.css";
import "./theme.css";
import "./animations.css";

/* ── Constants ── */
const DEFAULT_SETTINGS = {
  timeout: 30,
  userAgent: "AgentHunter/2.1",
  rateLimit: 10,
  proxy: "",
  outputDir: "./results",
  autoReport: true,
  verifySsl: true,
  followRedirects: true,
  saveLogs: true,
};

function toUiSettings(raw = {}) {
  return {
    timeout: raw.timeout ?? DEFAULT_SETTINGS.timeout,
    userAgent: raw.userAgent ?? raw.user_agent ?? DEFAULT_SETTINGS.userAgent,
    rateLimit: raw.rateLimit ?? raw.rate_limit ?? DEFAULT_SETTINGS.rateLimit,
    proxy: raw.proxy ?? DEFAULT_SETTINGS.proxy,
    outputDir: raw.outputDir ?? raw.output_dir ?? DEFAULT_SETTINGS.outputDir,
    autoReport: raw.autoReport ?? raw.auto_report ?? DEFAULT_SETTINGS.autoReport,
    verifySsl: raw.verifySsl ?? raw.verify_ssl ?? DEFAULT_SETTINGS.verifySsl,
    followRedirects: raw.followRedirects ?? raw.follow_redirects ?? DEFAULT_SETTINGS.followRedirects,
    saveLogs: raw.saveLogs ?? raw.save_logs ?? DEFAULT_SETTINGS.saveLogs,
  };
}

/* ── Screen enum ── */
const SCREEN = {
  TARGET:      "target",
  ASSETS:      "assets",
  CONFIG:      "config",
  LIVE:        "live",
  REPORT:      "report",
};

const SCREEN_LABELS = {
  [SCREEN.TARGET]: "Target Input",
  [SCREEN.ASSETS]: "Asset Discovery",
  [SCREEN.CONFIG]: "Scanner Config",
  [SCREEN.LIVE]:   "Live Console",
  [SCREEN.REPORT]: "Report",
};

export default function App() {
  /* ── Navigation ── */
  const [screen, setScreen] = useState(SCREEN.TARGET);
  const [initializing, setInitializing] = useState(true);

  /* ── App state ── */
  const [scanTarget, setScanTarget] = useState("");
  const [selectedAssets, setSelectedAssets] = useState([]);
  const [availableModules, setAvailableModules] = useState([]);
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [launchError, setLaunchError] = useState("");
  const [launching, setLaunching] = useState(false);
  const [scanActionError, setScanActionError] = useState("");

  /* ── Scan stream hook ── */
  const {
    logs,
    findings,
    progress,
    phase,
    running,
    error: streamError,
    scanId,
    stats,
    launch: launchStream,
    resume: resumeStream,
    reset: resetStream,
  } = useScanStream();

  /* ── Initial data fetch + auto-reconnect ── */
  useEffect(() => {
    let mounted = true;

    async function init() {
      // 1. Load basic app data
      const [scans, cfg, modules] = await Promise.all([
        listScans().catch(() => []),
        getSettings().catch(() => DEFAULT_SETTINGS),
        listModules().catch(() => []),
      ]);

      if (!mounted) return;
      setSettings(toUiSettings(cfg));
      setAvailableModules(Array.isArray(modules) ? modules : []);

      // 2. Check for active/recent scans to auto-reconnect
      try {
        const activeScan = await getActiveScan();

        if (!mounted) return;

        if (activeScan.active) {
          // There's a running scan — reconnect to it
          setScanTarget(activeScan.target || "");
          setScreen(SCREEN.LIVE);
          resumeStream(activeScan.scan_id);
          setInitializing(false);
          return;
        }

        if (activeScan.recent && activeScan.status === "complete") {
          // Recently completed scan — jump to report
          setScanTarget(activeScan.target || "");
          // Hydrate findings from the completed scan
          try {
            const scanData = await getScan(activeScan.scan_id);
            if (scanData && Array.isArray(scanData.findings)) {
              // Resume will hydrate all findings
              resumeStream(activeScan.scan_id);
              setScreen(SCREEN.REPORT);
              setInitializing(false);
              return;
            }
          } catch { /* fall through */ }
        }
      } catch {
        // Backend might not be running yet — check localStorage fallback
        const persisted = getPersistedScan();
        if (persisted && persisted.scanId) {
          if (!mounted) return;
          setScanTarget(persisted.target || "");
          setScreen(SCREEN.LIVE);
          resumeStream(persisted.scanId);
          setInitializing(false);
          return;
        }
      }

      // 3. No active scan — normal startup
      if (Array.isArray(scans) && scans.length) {
        setScanTarget(scans[scans.length - 1].target || "");
      }
      setInitializing(false);
    }

    init();
    return () => { mounted = false; };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /* ── Flow handlers ── */
  const handleTargetSubmit = useCallback((target) => {
    setScanTarget(target);
    setScreen(SCREEN.ASSETS);
  }, []);

  const handleAssetsSelected = useCallback((assets) => {
    setSelectedAssets(assets);
    setScreen(SCREEN.CONFIG);
  }, []);

  const handleLaunchScan = useCallback(async ({ modules, depth, threads, assets, authorizationAcknowledged }) => {
    setLaunchError("");
    setLaunching(true);
    try {
      const request = buildScanRequest({
        target: scanTarget,
        assets,
        modules,
        depth,
        threads,
        verifySsl: settings.verifySsl,
        authorizationAcknowledged,
      });
      const started = await apiStartScan(request);
      launchStream(started.scan_id, request.url);
      setScreen(SCREEN.LIVE);
    } catch (err) {
      setLaunchError(err?.message || "Unknown API error");
    } finally {
      setLaunching(false);
    }
  }, [scanTarget, settings.verifySsl, launchStream]);

  const handleNewScan = useCallback(() => {
    resetStream();
    setScanTarget("");
    setSelectedAssets([]);
    setScreen(SCREEN.TARGET);
  }, [resetStream]);

  const handleViewReport = useCallback(() => {
    setScreen(SCREEN.REPORT);
  }, []);

  const handleAbort = useCallback(async () => {
    if (!scanId) return;
    setScanActionError("");
    try {
      await apiAbortScan(scanId);
    } catch (err) {
      setScanActionError(err?.message || "Abort request failed");
    }
  }, [scanId]);

  // Show loading indicator while checking for active scans
  if (initializing) {
    return (
      <div className="app-shell">
        <header className="topbar">
          <div className="topbar-brand">
            <svg width="24" height="24" viewBox="0 0 30 30" fill="none">
              <polygon points="15,2 28,9 28,21 15,28 2,21 2,9" stroke="var(--color-primary)" strokeWidth="1.5" fill="none" opacity="0.8" />
              <polygon points="15,7 23,11.5 23,20.5 15,24 7,20.5 7,11.5" stroke="var(--color-text-low)" strokeWidth="1" fill="none" opacity="0.4" />
              <circle cx="15" cy="15" r="2.5" fill="var(--color-primary)" />
            </svg>
            <span className="topbar-wordmark">Agent-Hunter</span>
          </div>
        </header>
        <div className="main-content" style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "60vh",
        }}>
          <div className="anim-pulse-ring" style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: "16px",
          }}>
            <div style={{
              width: "48px",
              height: "48px",
              borderRadius: "50%",
              border: "3px solid var(--color-border)",
              borderTopColor: "var(--color-primary)",
              animation: "spin 0.8s linear infinite",
            }} />
            <span style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-sm)",
              color: "var(--color-text-low)",
              letterSpacing: "0.5px",
            }}>
              Checking for active scans...
            </span>
          </div>
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  return (
    <div className="app-shell">
      {/* ── Top Nav Bar ── */}
      <header className="topbar">
        <div className="topbar-brand">
          <svg width="24" height="24" viewBox="0 0 30 30" fill="none">
            <polygon points="15,2 28,9 28,21 15,28 2,21 2,9" stroke="var(--color-primary)" strokeWidth="1.5" fill="none" opacity="0.8" />
            <polygon points="15,7 23,11.5 23,20.5 15,24 7,20.5 7,11.5" stroke="var(--color-text-low)" strokeWidth="1" fill="none" opacity="0.4" />
            <circle cx="15" cy="15" r="2.5" fill="var(--color-primary)" />
          </svg>
          <span className="topbar-wordmark">Agent-Hunter</span>
        </div>

        {screen !== SCREEN.TARGET && (
          <span className="topbar-breadcrumb">{SCREEN_LABELS[screen]}</span>
        )}

        <div className="topbar-right">
          {running && (
            <div style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              padding: "4px 12px",
              borderRadius: "100px",
              border: "1px solid var(--color-primary)",
              background: "var(--color-primary-glow)",
            }}>
              <div className="anim-pulse-ring" style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                background: "var(--color-primary)",
              }} />
              <span style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                color: "var(--color-primary)",
                letterSpacing: "0.5px",
              }}>
                SCANNING
              </span>
            </div>
          )}
          {streamError && (
            <div style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              padding: "4px 12px",
              borderRadius: "100px",
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent-glow, rgba(255,160,0,0.08))",
              marginLeft: "8px",
            }}>
              <span style={{
                fontFamily: "var(--font-mono)",
                fontSize: "10px",
                color: "var(--color-accent)",
                letterSpacing: "0.3px",
              }}>
                RECONNECTING...
              </span>
            </div>
          )}
        </div>
      </header>

      {/* ── Main Content ── */}
      <div className="main-content">
        {screen === SCREEN.TARGET && (
          <TargetInput onSubmit={handleTargetSubmit} />
        )}
        {screen === SCREEN.ASSETS && (
          <AssetDiscovery
            target={scanTarget}
            onContinue={handleAssetsSelected}
            onBack={() => setScreen(SCREEN.TARGET)}
          />
        )}
        {screen === SCREEN.CONFIG && (
          <ScanConfig
            selectedAssets={selectedAssets}
            availableModules={availableModules}
            onLaunch={handleLaunchScan}
            onBack={() => setScreen(SCREEN.ASSETS)}
            launchError={launchError}
            launching={launching}
          />
        )}
        {screen === SCREEN.LIVE && (
          <LiveConsole
            running={running}
            progress={progress}
            phase={phase}
            logs={logs}
            findings={findings}
            scanTarget={scanTarget}
            scanId={scanId}
            onAbort={handleAbort}
            onViewReport={handleViewReport}
            actionError={scanActionError || streamError}
          />
        )}
        {screen === SCREEN.REPORT && (
          <ReportView
            findings={findings}
            scanTarget={scanTarget}
            scanId={scanId}
            scanDate={new Date().toLocaleDateString()}
            scannerCount={stats.modules_run ?? 0}
            onNewScan={handleNewScan}
          />
        )}
      </div>
    </div>
  );
}
