/* eslint-disable @typescript-eslint/no-explicit-any */
// Storage node dashboard panels — inverted design
// Per spec: nodes are equal index-only mirrors. No primaries, no failover.

import React, { useEffect, useState, useCallback } from "react";
import type { DiagnosticsBundle } from "../../types/storage";
import { displayOnlyNumberToNumber } from "../../types/storage";
import { storageStore, useStorageStore } from "../../stores/storageStore";

function fmtBytes(n: number): string {
  if (n <= 0) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function fmtCount(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}K`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

function extractHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function dton(v: any): number {
  return typeof v === "number" ? v : displayOnlyNumberToNumber(v ?? (0 as any)) || 0;
}

// ═══════════════════════════════════════════════════════════════════════
// NodeHealthPanel — inverted dark panels
// ═══════════════════════════════════════════════════════════════════════
export const NodeHealthPanel: React.FC = () => {
  const storage = useStorageStore();
  const [expanded, setExpanded] = useState<string | null>(null);

  const [addError, setAddError] = useState<string | null>(null);
  const [addLoading, setAddLoading] = useState(false);
  const [assignedUrl, setAssignedUrl] = useState<string | null>(null);

  const [removeTarget, setRemoveTarget] = useState<string | null>(null);
  const [removeLoading, setRemoveLoading] = useState(false);

  const loadData = useCallback(async (isRefresh = false) => {
    await storageStore.initialize();
    await storageStore.refreshNodeHealth(isRefresh);
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleRequestNode = async () => {
    setAddLoading(true);
    setAddError(null);
    setAssignedUrl(null);
    const r = await storageStore.addNode();
    setAddLoading(false);
    if (!r.success) {
      setAddError(r.error || "Failed");
      return;
    }
    setAssignedUrl(r.assignedUrl ?? null);
  };

  const handleRemove = async (url: string) => {
    setRemoveLoading(true);
    await storageStore.removeNode(url);
    setRemoveLoading(false);
    setRemoveTarget(null);
  };

  const online = storage.nodeHealth.filter((h) => h.status === "healthy").length;
  const degraded = storage.nodeHealth.filter((h) => h.status === "degraded").length;
  const offline = storage.nodeHealth.filter((h) => h.status === "down").length;
  const regions = new Set(storage.nodeHealth.map((h) => h.region).filter(Boolean)).size;
  const totalPut = storage.nodeHealth.reduce((s, h) => s + dton(h.objectsPutTotal), 0);
  const totalGet = storage.nodeHealth.reduce((s, h) => s + dton(h.objectsGetTotal), 0);
  const totalW = storage.nodeHealth.reduce((s, h) => s + dton(h.bytesWrittenTotal), 0);
  const totalR = storage.nodeHealth.reduce((s, h) => s + dton(h.bytesReadTotal), 0);
  const totalObj = totalPut + totalGet;

  if (storage.nodeHealthLoading)
    return <div className="storage-loading">Checking node health...</div>;

  return (
    <div className="snd-stack">
      {/* Stat grid */}
      <div className="snd-card">
        <div className="snd-stat-grid">
          <div className="snd-stat-cell">
            <div className="snd-stat-val">{storage.nodeHealth.length}</div>
            <div className="snd-stat-label">Nodes</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val">{online}</div>
            <div className="snd-stat-label">Online</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val">
              {offline}
              {degraded > 0 ? `/${degraded}` : ""}
            </div>
            <div className="snd-stat-label">{degraded > 0 ? "Off/Warn" : "Offline"}</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val">{regions}</div>
            <div className="snd-stat-label">Regions</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val">{totalObj > 0 ? fmtCount(totalObj) : "\u2014"}</div>
            <div className="snd-stat-label">Objects</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val">{totalW > 0 ? fmtBytes(totalW) : "\u2014"}</div>
            <div className="snd-stat-label">Written</div>
          </div>
        </div>
        {(totalPut > 0 || totalGet > 0) && (
          <div className="snd-throughput">
            <span>PUT {fmtCount(totalPut)}</span>
            <span>GET {fmtCount(totalGet)}</span>
            <span>W {fmtBytes(totalW)}</span>
            <span>R {fmtBytes(totalR)}</span>
          </div>
        )}
      </div>

      {/* Node table */}
      <div className="snd-card snd-table">
        <div className="snd-table-header">
          <span />
          <span>Node</span>
          <span>Region</span>
          <span>Ms</span>
        </div>
        {storage.nodeHealth.map((h) => {
          const lat = dton(h.latencyMs);
          const isExp = expanded === h.url;
          const cls =
            h.status === "down"
              ? "snd-row snd-row-off"
              : h.status === "degraded"
                ? "snd-row snd-row-warn"
                : "snd-row";
          return (
            <React.Fragment key={h.url}>
              <div
                className={`${cls}${isExp ? " snd-row-exp" : ""}`}
                onClick={() => setExpanded(isExp ? null : h.url)}
              >
                <span
                  className={`snd-dot${h.status === "healthy" ? " snd-dot-on" : h.status === "degraded" ? " snd-dot-warn" : ""}`}
                />
                <span className="snd-name">{h.name || extractHost(h.url)}</span>
                <span className="snd-region">{h.region || "\u2014"}</span>
                <span className="snd-ms">
                  {h.status === "down" ? "\u2014" : lat > 0 ? String(lat) : ".."}
                </span>
              </div>
              {isExp && (
                <div className="snd-detail">
                  <div className="snd-detail-url">{h.url}</div>
                  {h.status !== "down" && h.objectsPutTotal !== undefined && (
                    <div className="snd-detail-stats">
                      <span>PUT {fmtCount(dton(h.objectsPutTotal))}</span>
                      <span>GET {fmtCount(dton(h.objectsGetTotal))}</span>
                      <span>W {fmtBytes(dton(h.bytesWrittenTotal))}</span>
                      <span>R {fmtBytes(dton(h.bytesReadTotal))}</span>
                    </div>
                  )}
                  {h.lastError && <div className="snd-detail-err">{h.lastError}</div>}
                  {removeTarget === h.url ? (
                    <div className="snd-detail-confirm">
                      <span>REMOVE?</span>
                      <button
                        className="snd-btn-sm"
                        disabled={removeLoading}
                        onClick={(e) => {
                          e.stopPropagation();
                          void handleRemove(h.url);
                        }}
                      >
                        {removeLoading ? ".." : "YES"}
                      </button>
                      <button
                        className="snd-btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          setRemoveTarget(null);
                        }}
                      >
                        NO
                      </button>
                    </div>
                  ) : (
                    <button
                      className="snd-detail-remove"
                      onClick={(e) => {
                        e.stopPropagation();
                        setRemoveTarget(h.url);
                      }}
                    >
                      REMOVE NODE
                    </button>
                  )}
                </div>
              )}
            </React.Fragment>
          );
        })}
        {storage.nodeHealth.length === 0 && (
          <div className="snd-row storage-row-empty">No nodes configured</div>
        )}
      </div>

      {/* Actions — node is selected by keyed Fisher-Yates; the user cannot choose which node is added */}
      <div className="snd-actions">
        <button
          className="snd-btn"
          disabled={addLoading}
          onClick={() => void handleRequestNode()}
        >
          {addLoading ? "Requesting..." : "+ Request Node"}
        </button>
        <button
          className="snd-btn"
          onClick={() => void loadData(true)}
          disabled={storage.nodeHealthRefreshing}
        >
          {storage.nodeHealthRefreshing ? "Refreshing..." : "Refresh"}
        </button>
      </div>
      {assignedUrl && (
        <div className="snd-detail-url storage-top-gap-sm">Assigned: {assignedUrl}</div>
      )}
      {addError && (
        <div className="snd-detail-err storage-top-gap-sm">{addError}</div>
      )}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════
// DiagnosticsPanel — inverted dark panels
// ═══════════════════════════════════════════════════════════════════════
export const DiagnosticsPanel: React.FC = () => {
  const storage = useStorageStore();
  const bundle: DiagnosticsBundle | null = storage.diagnostics;
  const collecting = storage.diagnosticsCollecting;

  async function collect() {
    await storageStore.initialize();
    await storageStore.collectDiagnostics();
  }

  function download() {
    if (!bundle) return;
    const data = storageStore.exportDiagnostics(bundle);
    const blob = new Blob([new Uint8Array(data)], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `dsm-diag-${bundle.nodeHealth.length}.bin`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const hc = bundle?.nodeHealth.filter((h) => h.status === "healthy").length ?? 0;
  const dc = bundle?.nodeHealth.filter((h) => h.status === "degraded").length ?? 0;
  const xc = bundle?.nodeHealth.filter((h) => h.status === "down").length ?? 0;

  return (
    <div className="snd-stack">
      <div className="storage-section-title">Diagnostics</div>
      {!bundle ? (
        <button className="snd-btn" onClick={collect} disabled={collecting}>
          {collecting ? "Collecting\u2026" : "Run Diagnostics"}
        </button>
      ) : (
        <>
          {/* Summary card */}
          <div className="snd-card">
            <div className="snd-diag-row">
              <span className="snd-diag-label">Nodes</span>
              <span className="snd-diag-val">{bundle.nodeHealth.length}</span>
            </div>
            <div className="snd-diag-row">
              <span className="snd-diag-label">Online / Warn / Offline</span>
              <span className="snd-diag-val">
                {hc} / {dc} / {xc}
              </span>
            </div>
            <div className="snd-diag-row">
              <span className="snd-diag-label">Platform</span>
              <span className="snd-diag-val snd-trunc">{bundle.systemInfo.platform}</span>
            </div>
          </div>

          {/* Node health table */}
          {bundle.nodeHealth.length > 0 && (
            <div className="snd-card snd-table">
              <div className="snd-table-header" style={{ gridTemplateColumns: "14px 1fr 60px" }}>
                <span />
                <span>Node</span>
                <span>Status</span>
              </div>
              {bundle.nodeHealth.map((h) => (
                <div
                  key={h.url}
                  className={`snd-row${h.status === "down" ? " snd-row-off" : h.status === "degraded" ? " snd-row-warn" : ""}`}
                  style={{ gridTemplateColumns: "14px 1fr 60px" }}
                >
                  <span
                    className={`snd-dot${h.status === "healthy" ? " snd-dot-on" : h.status === "degraded" ? " snd-dot-warn" : ""}`}
                  />
                  <span className="snd-name">{h.name || extractHost(h.url)}</span>
                  <span className="snd-region" style={{ fontWeight: 700 }}>
                    {h.status === "healthy"
                      ? "ONLINE"
                      : h.status === "degraded"
                        ? "WARN"
                        : "OFFLINE"}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Recent errors */}
          {bundle.recentErrors.length > 0 && (
            <div className="snd-card snd-scroll-box">
              <div className="snd-section-label">Errors ({bundle.recentErrors.length})</div>
              {bundle.recentErrors.slice(-20).map((e, i) => (
                <div key={i}>{e}</div>
              ))}
            </div>
          )}

          {/* Actions */}
          <div className="snd-actions">
            <button className="snd-btn" onClick={download}>
              Export
            </button>
            <button className="snd-btn" onClick={collect} disabled={collecting}>
              {collecting ? "Refreshing\u2026" : "Refresh"}
            </button>
            <button className="snd-btn" onClick={() => storageStore.clearDiagnostics()}>
              Clear
            </button>
          </div>
        </>
      )}
    </div>
  );
};
