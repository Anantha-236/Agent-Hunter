import { useState, useEffect, useRef } from "react";
import { startRecon, streamRecon } from "../api";
import AssetCard from "./shared/AssetCard";

/**
 * AssetDiscovery — Screen 2: Show discovered assets, let user select.
 *
 * Props:
 *   target      string
 *   onContinue  (selectedAssets: Object[]) => void
 *   onBack      () => void
 */

export default function AssetDiscovery({ target, onContinue, onBack }) {
  const [status, setStatus] = useState("idle");
  const [subdomains, setSubdomains] = useState([]);
  const [ports, setPorts] = useState([]);
  const [services, setServices] = useState([]);
  const [technologies, setTechnologies] = useState([]);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const sseRef = useRef(null);

  // Start discovery on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      setStatus("scanning");
      try {
        const { recon_id } = await startRecon({ url: target });
        const es = streamRecon(recon_id);
        sseRef.current = es;

        es.addEventListener("subdomain", (e) => {
          if (cancelled) return;
          const d = JSON.parse(e.data);
          setSubdomains((p) => [...p, { ...d, type: "subdomain", id: `sub-${d.hostname}` }]);
        });
        es.addEventListener("port", (e) => {
          if (cancelled) return;
          const d = JSON.parse(e.data);
          setPorts((p) => [...p, { ...d, type: "port", id: `port-${d.host}:${d.port}` }]);
        });
        es.addEventListener("technology", (e) => {
          if (cancelled) return;
          const d = JSON.parse(e.data);
          setTechnologies((p) => p.some((t) => t.tech === d.tech) ? p : [...p, { ...d, type: "tech", id: `tech-${d.tech}` }]);
        });
        es.addEventListener("service", (e) => {
          if (cancelled) return;
          const d = JSON.parse(e.data);
          setServices((p) => [...p, { ...d, type: "service", id: `svc-${d.name || d.service}` }]);
        });
        es.addEventListener("done", () => {
          if (!cancelled) setStatus("complete");
          es.close();
        });
        es.onerror = () => {
          if (!cancelled) setStatus("error");
        };
      } catch (err) {
        if (!cancelled) setStatus("error");
      }
    })();

    return () => {
      cancelled = true;
      sseRef.current?.close();
    };
  }, [target]);

  // Build combined asset list
  const allAssets = [...subdomains, ...ports, ...services, ...technologies];
  const totalByGroup = {
    subdomains: subdomains.length,
    ports: ports.length,
    services: services.length,
    technologies: technologies.length,
  };

  const toggleAsset = (id) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const selectAll = () => setSelectedIds(new Set(allAssets.map((a) => a.id)));
  const selectNone = () => setSelectedIds(new Set());

  // Auto-select all when complete
  useEffect(() => {
    if (status === "complete" && selectedIds.size === 0 && allAssets.length > 0) {
      selectAll();
    }
  }, [status]);

  const handleContinue = () => {
    const selected = allAssets.filter((a) => selectedIds.has(a.id));
    onContinue(selected);
  };

  const assetSections = [
    { key: "subdomains", label: "Subdomains", items: subdomains },
    { key: "ports", label: "Open Ports", items: ports },
    { key: "services", label: "Services", items: services },
    { key: "technologies", label: "Technologies", items: technologies },
  ].filter((s) => s.items.length > 0);

  return (
    <div className="screen-enter" style={{ paddingBottom: "80px" }}>
      <div className="screen-container">
        {/* Top bar: target + status */}
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "24px",
          flexWrap: "wrap",
          gap: "12px",
        }}>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-base)",
            color: "var(--color-text-high)",
          }}>
            {target}
          </span>

          <div style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            padding: "6px 14px",
            borderRadius: "100px",
            background: status === "scanning" ? "var(--color-accent-glow)" : status === "complete" ? "var(--color-primary-glow)" : "var(--color-surface)",
            border: `1px solid ${status === "scanning" ? "var(--color-accent)" : status === "complete" ? "var(--color-primary)" : "var(--color-border)"}`,
          }}>
            <div className={status === "scanning" ? "anim-pulse-ring" : ""} style={{
              width: "8px",
              height: "8px",
              borderRadius: "50%",
              background: status === "scanning" ? "var(--color-accent)" : status === "complete" ? "var(--color-primary)" : "var(--color-text-low)",
            }} />
            <span style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-xs)",
              color: status === "scanning" ? "var(--color-accent)" : status === "complete" ? "var(--color-primary)" : "var(--color-text-low)",
              letterSpacing: "0.5px",
            }}>
              {status === "scanning" ? "Discovering assets..." : status === "complete" ? `${allAssets.length} assets found` : status === "error" ? "Discovery failed" : "Idle"}
            </span>
          </div>
        </div>

        {/* Asset groups */}
        <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
          {assetSections.map((section) => (
            <div key={section.key}>
              {/* Section header */}
              <div style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "12px",
              }}>
                <h3 style={{
                  fontFamily: "var(--font-ui)",
                  fontSize: "var(--text-md)",
                  fontWeight: 600,
                  color: "var(--color-text-high)",
                }}>
                  {section.label}
                  <span style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-xs)",
                    color: "var(--color-text-low)",
                    marginLeft: "8px",
                    fontWeight: 400,
                  }}>
                    {section.items.length}
                  </span>
                </h3>
                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    className="btn btn-outline btn-sm"
                    onClick={() => {
                      const ids = section.items.map((a) => a.id);
                      setSelectedIds((prev) => {
                        const next = new Set(prev);
                        ids.forEach((id) => next.add(id));
                        return next;
                      });
                    }}
                  >
                    Select All
                  </button>
                  <button
                    className="btn btn-outline btn-sm"
                    onClick={() => {
                      const ids = new Set(section.items.map((a) => a.id));
                      setSelectedIds((prev) => {
                        const next = new Set(prev);
                        ids.forEach((id) => next.delete(id));
                        return next;
                      });
                    }}
                  >
                    None
                  </button>
                </div>
              </div>

              {/* Cards grid */}
              <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
                gap: "12px",
              }}>
                {section.items.map((asset) => (
                  <AssetCard
                    key={asset.id}
                    asset={asset}
                    selected={selectedIds.has(asset.id)}
                    onToggle={toggleAsset}
                  />
                ))}
              </div>
            </div>
          ))}

          {allAssets.length === 0 && status !== "scanning" && (
            <div style={{
              textAlign: "center",
              padding: "48px",
              color: "var(--color-text-low)",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-sm)",
            }}>
              No assets discovered. Try a different target.
            </div>
          )}
        </div>
      </div>

      {/* Bottom bar */}
      <div className="bottom-bar">
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <button className="btn btn-outline btn-sm" onClick={onBack}>← Back</button>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-xs)",
            color: "var(--color-text-mid)",
          }}>
            {selectedIds.size} assets selected across {assetSections.filter((s) => s.items.some((a) => selectedIds.has(a.id))).length} groups
          </span>
        </div>
        <button
          className="btn btn-primary"
          disabled={selectedIds.size === 0}
          onClick={handleContinue}
        >
          Configure Scanners →
        </button>
      </div>
    </div>
  );
}
