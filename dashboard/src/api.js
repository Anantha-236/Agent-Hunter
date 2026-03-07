/**
 * api.js — Thin client for the Agent-Hunter FastAPI backend.
 *
 * Base URL defaults to the Vite proxy (/api) in dev, or can be overridden
 * via the VITE_API_BASE environment variable.
 */

const BASE = import.meta.env.VITE_API_BASE || "/api";

async function request(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...opts.headers },
    ...opts,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json();
}

/** Launch a new scan. Returns { scan_id, status, target, started_at }. */
export function startScan(payload) {
  return request("/scan", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/** Fetch full scan state (findings, logs, stats, phase). */
export function getScan(scanId) {
  return request(`/scan/${scanId}`);
}

/** Fetch findings for a scan. */
export function getFindings(scanId) {
  return request(`/scan/${scanId}/findings`);
}

/** List all past scans (summary). */
export function listScans() {
  return request("/scans");
}

/** List available scanner module IDs. */
export function listModules() {
  return request("/modules");
}

/** Get agent settings. */
export function getSettings() {
  return request("/settings");
}

/** Save agent settings. */
export function saveSettings(payload) {
  return request("/settings", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

/**
 * Open an SSE stream for a running scan.
 * Returns an EventSource. Attach listeners for:
 *   "log", "finding", "phase", "status", "stats", "error", "done"
 */
export function streamScan(scanId) {
  return new EventSource(`${BASE}/scan/${scanId}/stream`);
}
