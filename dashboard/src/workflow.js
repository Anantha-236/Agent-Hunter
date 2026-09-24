export const DEFAULT_SAFE_MODULES = [
  "ssl_tls_scanner",
  "header_security",
  "session_cookie_scanner",
];

const WEB_SERVICES = new Set([
  "http",
  "https",
  "http-alt",
  "http-proxy",
  "https-alt",
  "http-alt2",
  "dev-server",
  "web-console",
]);

function parseTarget(target) {
  try {
    return new URL(target);
  } catch {
    return new URL(`https://${target}`);
  }
}

export function buildReconRequest(target) {
  const parsed = parseTarget(target);
  return {
    url: target,
    in_scope: [parsed.hostname],
    out_scope: [],
  };
}

export function phaseForTerminalStatus(status, currentPhase) {
  return ["complete", "error", "aborted", "interrupted"].includes(status)
    ? status
    : currentPhase;
}

export function normalizeReconAsset(asset, originalTarget) {
  const original = parseTarget(originalTarget);
  const type = asset.type || "unknown";

  if (type === "target") {
    const url = asset.url || original.href;
    const parsed = parseTarget(url);
    return {
      id: `target-${url}`,
      type: "target",
      host: parsed.hostname,
      label: url,
      url,
      selectable: true,
      selectionReason: "Exact operator-provided target",
    };
  }

  if (type === "subdomain") {
    const host = asset.hostname || asset.host || "";
    const url = host ? `${original.protocol}//${host}/` : "";
    return {
      ...asset,
      id: asset.id || `sub-${host}`,
      type,
      host,
      label: host,
      url,
      selectable: Boolean(url),
      selectionReason: "Recon discovery; select only if independently authorized",
    };
  }

  if (type === "port") {
    const host = asset.host || asset.hostname || "";
    const service = String(asset.service || "").toLowerCase();
    const isWeb = WEB_SERVICES.has(service);
    const protocol = service.includes("https") || Number(asset.port) === 443 || Number(asset.port) === 8443
      ? "https:"
      : "http:";
    const defaultPort = (protocol === "https:" && Number(asset.port) === 443)
      || (protocol === "http:" && Number(asset.port) === 80);
    const portPart = defaultPort ? "" : `:${asset.port}`;
    const url = isWeb && host ? `${protocol}//${host}${portPart}/` : "";
    return {
      ...asset,
      id: asset.id || `port-${host}:${asset.port}`,
      type,
      host,
      label: host ? `${host}:${asset.port}` : `Port ${asset.port}`,
      url,
      selectable: Boolean(url),
      selectionReason: isWeb
        ? "Discovered web service; select only if independently authorized"
        : "Non-web ports are observations, not web scan targets",
    };
  }

  return {
    ...asset,
    id: asset.id || `${type}-${asset.tech || asset.label || "observation"}`,
    type,
    host: asset.host || "",
    label: asset.tech || asset.label || type,
    url: "",
    selectable: false,
    selectionReason: "Observation only",
  };
}

export function buildScanRequest({
  target,
  assets,
  modules,
  depth,
  threads,
  verifySsl,
  authorizationAcknowledged,
}) {
  const selectedUrls = [...new Set(
    assets.filter((asset) => asset.selectable && asset.url).map((asset) => asset.url),
  )];
  const effectiveUrls = selectedUrls.length ? selectedUrls : [target];
  const scopeHosts = [...new Set(effectiveUrls.map((url) => parseTarget(url).hostname).filter(Boolean))];

  return {
    url: effectiveUrls[0],
    modules,
    depth,
    threads,
    in_scope: scopeHosts,
    out_scope: [],
    instructions: "",
    selected_assets: effectiveUrls,
    verify_ssl: Boolean(verifySsl),
    authorization_acknowledged: Boolean(authorizationAcknowledged),
  };
}
