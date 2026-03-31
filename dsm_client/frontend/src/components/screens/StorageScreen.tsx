/* eslint-disable @typescript-eslint/no-explicit-any */
// src/components/screens/StorageScreen.tsx
// Per spec: storage nodes are index-only mirrors. No failover semantics.
import React, { useEffect, useState, useMemo } from "react";
import type { DlvIndexEntry } from "../../dsm/index";
import { NodeHealthPanel, DiagnosticsPanel } from "../storage/StorageNodePanels";
import { ObjectBrowserPanel } from "../storage/ObjectBrowser";
import { DisplayOnlyNumber, displayOnlyNumberToNumber } from "../../types/storage";
import { useDpadNav } from "../../hooks/useDpadNav";
import {
  storageStore,
  useStorageStore,
  type DlvPresenceNode,
  type DlvPresenceSummary,
} from "../../stores/storageStore";
import "./StorageScreen.css";

type StorageStatus = {
  totalNodes: number;
  connectedNodes: number;
  lastSync: DisplayOnlyNumber; // UI-only deterministic sync marker
  dataSize: string; // e.g. "12.3 MB"
  backupStatus: string;
};

const StorageScreen: React.FC = () => {
  const storage = useStorageStore();
  const [backupPassword, setBackupPassword] = useState("");
  const [expandedDlv, setExpandedDlv] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<
    "overview" | "dlvs" | "nodes" | "diagnostics" | "objects"
  >("overview");

  useEffect(() => {
    void storageStore.initialize();
    void storageStore.refreshOverview();
    void storageStore.refreshDlvsAndPresence();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function createBackup() {
    const result = await storageStore.createBackup(backupPassword || undefined);
    if (!result?.success) {
      return;
    }
    alert("Backup created successfully.");
    void storageStore.refreshOverview();
  }

  function formatLastSync(ts: DisplayOnlyNumber): string {
    if (!displayOnlyNumberToNumber(ts)) return "\u2014";
    return `Sync #${displayOnlyNumberToNumber(ts)}`;
  }

  // --- D-pad navigation ---
  const tabList = storage.showObjectsTab
    ? (["overview", "dlvs", "nodes", "diagnostics", "objects"] as const)
    : (["overview", "dlvs", "nodes", "diagnostics"] as const);

  const navActions = useMemo(() => {
    const actions: Array<() => void> = [];
    for (const tab of tabList) {
      actions.push(() => setActiveTab(tab));
    }
    return actions;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storage.showObjectsTab]);

  const { focusedIndex } = useDpadNav({
    itemCount: tabList.length,
    onSelect: (idx) => navActions[idx]?.(),
  });

  return (
    <div className="storage-screen-shell">
      <div className="storage-screen-header">
        {/* Header */}
        <div className="storage-toolbar">
          <h2>Storage Nodes</h2>
        </div>

        {/* Tab Navigation — inverted: inactive = dark, active = light */}
        <div className="storage-tab-nav">
          {tabList.map((tab, tIdx) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`storage-tab-button ${activeTab === tab ? "active" : ""}${tIdx === focusedIndex ? " focused" : ""}`}
            >
              {tab === "dlvs"
                ? "DLVs"
                : tab === "diagnostics"
                  ? "Diag"
                  : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="storage-screen-stage">
        {/* Tab Content */}
        {activeTab === "overview" && (
          <OverviewTab
            loading={storage.overviewLoading}
            error={storage.overviewError}
            storageInfo={storage.storageInfo}
            backupPassword={backupPassword}
            setBackupPassword={setBackupPassword}
            onRetry={() => void storageStore.refreshOverview()}
            onCreateBackup={createBackup}
            formatLastSync={formatLastSync}
          />
        )}

        {activeTab === "dlvs" && (
          <DlvTab
            dlvLoading={storage.dlvLoading}
            dlvs={storage.dlvs}
            presence={storage.presence}
            expandedDlv={expandedDlv}
            setExpandedDlv={setExpandedDlv}
          />
        )}

        {activeTab === "nodes" &&
          (storage.nodesConfig.nodes.length === 0 ? (
            <div className="snd-card storage-card-body">
              <div className="snd-stat-label storage-card-title">NO NODES CONFIGURED</div>
              <div className="storage-card-copy storage-card-copy-muted">
                Add your storage node endpoints to <code>dsm_network_config.json</code> under
                <code>production_nodes[]</code>.
              </div>
            </div>
          ) : (
            <NodeHealthPanel />
          ))}
        {activeTab === "diagnostics" && <DiagnosticsPanel />}
        {activeTab === "objects" && storage.showObjectsTab && <ObjectBrowserPanel />}
      </div>

      <div className="storage-navigation-hint">Press B to go back</div>
    </div>
  );
};

export default StorageScreen;

// ═══════════════════════════════════════════════════════════════════════
// Overview Tab — inverted panels
// ═══════════════════════════════════════════════════════════════════════
const OverviewTab: React.FC<{
  loading: boolean;
  error: string | null;
  storageInfo: StorageStatus | null;
  backupPassword: string;
  setBackupPassword: (v: string) => void;
  onRetry: () => void;
  onCreateBackup: () => void;
  formatLastSync: (ts: DisplayOnlyNumber) => string;
}> = ({
  loading,
  error,
  storageInfo,
  backupPassword,
  setBackupPassword,
  onRetry,
  onCreateBackup,
  formatLastSync,
}) => {
  if (loading) return <div className="storage-loading">Loading storage info...</div>;

  if (error) {
    return (
      <div className="snd-stack">
        <div className="snd-card storage-card-body">
          <div className="snd-stat-label storage-card-title">ERROR</div>
          <div className="storage-card-copy">{error}</div>
          <div className="storage-top-gap-sm">
            <button className="snd-btn" onClick={onRetry}>
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!storageInfo) {
    return <div className="storage-empty">Storage info unavailable.</div>;
  }

  return (
    <div className="snd-stack">
      {/* Stat summary */}
      <div className="snd-card">
        <div className="snd-stat-grid-2">
          <div className="snd-stat-cell">
            <div className="snd-stat-val">
              {storageInfo.connectedNodes}/{storageInfo.totalNodes}
            </div>
            <div className="snd-stat-label">Connected</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val-sm">{storageInfo.dataSize}</div>
            <div className="snd-stat-label">Data Size</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val-sm">{formatLastSync(storageInfo.lastSync)}</div>
            <div className="snd-stat-label">Last Sync</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val-sm">
              {storageInfo.backupStatus === "current" ? "OK" : storageInfo.backupStatus}
            </div>
            <div className="snd-stat-label">Backup</div>
          </div>
        </div>
      </div>

      {/* Detail rows */}
      <div className="snd-card">
        <div className="snd-info-row">
          <span className="snd-info-label">Storage Nodes</span>
          <span className="snd-info-val">
            {storageInfo.connectedNodes}/{storageInfo.totalNodes} connected
          </span>
        </div>
        <div className="snd-info-row">
          <span className="snd-info-label">Data Size</span>
          <span className="snd-info-val">{storageInfo.dataSize}</span>
        </div>
        <div className="snd-info-row">
          <span className="snd-info-label">Last Sync</span>
          <span className="snd-info-val">{formatLastSync(storageInfo.lastSync)}</span>
        </div>
        <div className="snd-info-row">
          <span className="snd-info-label">Backup Status</span>
          <span className="snd-info-val">{storageInfo.backupStatus}</span>
        </div>
      </div>

      {/* Create backup */}
      <div className="snd-card storage-card-body">
        <div className="snd-stat-label storage-card-title">CREATE BACKUP</div>
        <input
          type="password"
          placeholder="Backup password (optional)"
          value={backupPassword}
          onChange={(e) => setBackupPassword(e.target.value)}
          className="snd-input"
        />
        <div className="storage-top-gap-sm">
          <button className="snd-btn" onClick={onCreateBackup}>
            Create Backup
          </button>
        </div>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════
// DLV Tab — inverted panels
// ═══════════════════════════════════════════════════════════════════════
const DlvTab: React.FC<{
  dlvLoading: boolean;
  dlvs: DlvIndexEntry[];
  presence: Record<string, DlvPresenceSummary>;
  expandedDlv: string | null;
  setExpandedDlv: (v: string | null) => void;
}> = ({ dlvLoading, dlvs, presence, expandedDlv, setExpandedDlv }) => {
  if (dlvLoading) return <div className="storage-loading">Scanning active DLVs...</div>;

  if (dlvs.length === 0) {
    return <div className="storage-empty">No DLVs found for this device.</div>;
  }

  const active = dlvs.filter((d) => ["LOCKED", "UNLOCKABLE", "LIVE"].includes(d.status)).length;
  const hist = dlvs.length - active;
  const fullyReplicated = dlvs.filter((d) => {
    const s = presence[d.cptaAnchorHex];
    return s && d.expectedReplication > 0 && s.observed >= d.expectedReplication;
  }).length;

  return (
    <div className="snd-stack">
      {/* Summary stats */}
      <div className="snd-card">
        <div className="snd-stat-grid">
          <div className="snd-stat-cell">
            <div className="snd-stat-val">{active}</div>
            <div className="snd-stat-label">Active</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val">{hist}</div>
            <div className="snd-stat-label">Historical</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val">
              {fullyReplicated}/{active}
            </div>
            <div className="snd-stat-label">Replicated</div>
          </div>
        </div>
      </div>

      {/* Vault list */}
      <div className="snd-card">
        {dlvs.map((d) => {
          const s = presence[d.cptaAnchorHex];
          const observed = s?.observed ?? 0;
          const expected = d.expectedReplication ?? 0;
          const replicationText = expected > 0 ? `${observed}/${expected}` : `${observed}`;
          const isSpent = d.status === "SPENT" || d.status === "EXPIRED";
          const isExp = expandedDlv === d.cptaAnchorHex;

          return (
            <div
              key={d.cptaAnchorHex}
              className={`snd-dlv-item${isSpent ? " snd-dlv-item-spent" : ""}${isExp ? " snd-dlv-item-exp" : ""}`}
              onClick={() => setExpandedDlv(isExp ? null : d.cptaAnchorHex)}
              style={{ cursor: "pointer" }}
            >
              <div className="snd-dlv-header">
                <div>
                  <div className="snd-dlv-name">{d.localLabel || "DLV"}</div>
                  <div className="snd-dlv-kind">
                    {d.kind} &bull; {shortHex(d.cptaAnchorHex)}
                  </div>
                </div>
                <div>
                  <div className="snd-dlv-status">{d.status}</div>
                  <div className="snd-dlv-repl">storage: {replicationText}</div>
                </div>
              </div>
              {isExp && s?.nodes?.length ? (
                <div className="snd-dlv-nodes">
                  {s.nodes.map((n: DlvPresenceNode, idx: number) => (
                    <div key={idx} className="snd-dlv-node-row">
                      <span>{n.node}</span>
                      <span>
                        {n.reachable ? "up" : "down"} &bull; desc: {fmtTri(n.hasDescriptor)} &bull;
                        state: {fmtTri(n.hasState)}
                      </span>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          );
        })}
      </div>
    </div>
  );
};

function shortHex(h: string, len = 10): string {
  const s = (h || "").toLowerCase();
  if (s.length <= len) return s;
  return `${s.slice(0, Math.max(4, Math.floor(len / 2)))}\u2026${s.slice(-Math.max(4, Math.floor(len / 2)))}`;
}

function fmtTri(v: boolean | "unknown"): string {
  if (v === true) return "yes";
  if (v === false) return "no";
  return "\u2014";
}
