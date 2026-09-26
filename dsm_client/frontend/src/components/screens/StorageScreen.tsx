// SPDX-License-Identifier: MIT OR Apache-2.0

// src/components/screens/StorageScreen.tsx
// The storage set this device's traffic uses and what each member answered
// (SDK storage.status). Rendering only.
import React, { useEffect, useState, useMemo } from "react";
import { StorageMembersPanel, StorageSetPanel } from "../storage/StorageNodePanels";
import type { StorageStatus } from "../../dsm/types";
import { useDpadNav } from "../../hooks/useDpadNav";
import {
  storageStore,
  useStorageStore,
} from "../../stores/storageStore";
import { formatBtc, type VaultSummary } from "../../services/bitcoinTap";
import "./StorageScreen.css";

const TABS = ["set", "members", "dlvs"] as const;
type StorageTab = (typeof TABS)[number];

const TAB_LABELS: Record<StorageTab, string> = {
  set: "Set",
  members: "Members",
  dlvs: "DLVs",
};

const StorageScreen: React.FC = () => {
  const storage = useStorageStore();
  const [expandedDlv, setExpandedDlv] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<StorageTab>("set");

  useEffect(() => {
    void storageStore.refreshStatus();
    void storageStore.refreshDlvsAndPresence();
  }, []);

  // --- D-pad navigation ---
  const navActions = useMemo(() => TABS.map((tab) => () => setActiveTab(tab)), []);

  const { focusedIndex } = useDpadNav({
    itemCount: TABS.length,
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
          {TABS.map((tab, tIdx) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`storage-tab-button ${activeTab === tab ? "active" : ""}${tIdx === focusedIndex ? " focused" : ""}`}
            >
              {TAB_LABELS[tab]}
            </button>
          ))}
        </div>
      </div>

      <div className="storage-screen-stage">
        {(activeTab === "set" || activeTab === "members") && (
          <StatusTab
            tab={activeTab}
            loading={storage.statusLoading}
            error={storage.statusError}
            status={storage.status}
            onRefresh={() => void storageStore.refreshStatus()}
          />
        )}

        {activeTab === "dlvs" && (
          <DlvTab
            dlvLoading={storage.dlvLoading}
            dlvs={storage.dlvs}
            expandedDlv={expandedDlv}
            setExpandedDlv={setExpandedDlv}
          />
        )}
      </div>

      <div className="storage-navigation-hint">Press B to go back</div>
    </div>
  );
};

export default StorageScreen;

// ═══════════════════════════════════════════════════════════════════════
// Set / Members tabs — what storage.status reports
// ═══════════════════════════════════════════════════════════════════════
const StatusTab: React.FC<{
  tab: "set" | "members";
  loading: boolean;
  error: string | null;
  status: StorageStatus | null;
  onRefresh: () => void;
}> = ({ tab, loading, error, status, onRefresh }) => {
  if (loading) return <div className="storage-loading">Asking the storage set...</div>;

  if (error || !status) {
    return (
      <div className="snd-stack">
        <div className="snd-card storage-card-body">
          <div className="snd-stat-label storage-card-title">ERROR</div>
          <div className="storage-card-copy">{error ?? "No storage status."}</div>
          <div className="storage-top-gap-sm">
            <button className="snd-btn" onClick={onRefresh}>
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="snd-stack">
      {tab === "set" ? (
        <StorageSetPanel status={status} />
      ) : (
        <StorageMembersPanel members={status.members} />
      )}
      <div className="snd-actions">
        <button className="snd-btn" onClick={onRefresh}>
          Refresh
        </button>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════
// DLV Tab — real vault data from bitcoin.vault.list
// ═══════════════════════════════════════════════════════════════════════

const STATE_LABELS: Record<string, string> = {
  limbo: "Limbo",
  active: "Active",
  unlocked: "Unlocked",
  claimed: "Claimed",
  invalidated: "Invalidated",
};

const DIRECTION_LABELS: Record<string, string> = {
  btc_to_dbtc: "BTC \u2192 dBTC",
  dbtc_to_btc: "dBTC \u2192 BTC",
};

function stateLabel(s: string): string {
  return STATE_LABELS[s] ?? s;
}

function directionLabel(d: string): string {
  return DIRECTION_LABELS[d] ?? d;
}

function shortId(id: string, len = 12): string {
  if (!id || id.length <= len) return id || "\u2014";
  return `${id.slice(0, len)}\u2026`;
}

const DlvTab: React.FC<{
  dlvLoading: boolean;
  dlvs: VaultSummary[];
  expandedDlv: string | null;
  setExpandedDlv: (v: string | null) => void;
}> = ({ dlvLoading, dlvs, expandedDlv, setExpandedDlv }) => {
  if (dlvLoading) return <div className="storage-loading">Scanning DLVs...</div>;

  if (dlvs.length === 0) {
    return <div className="storage-empty">No DLVs found for this device.</div>;
  }

  const active = dlvs.filter((d) => d.state === "active" || d.state === "limbo").length;
  const hist = dlvs.length - active;
  const totalLockedSats = dlvs
    .filter((d) => d.state === "active" || d.state === "limbo")
    .reduce((sum, d) => sum + d.amountSats, 0n);

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
            <div className="snd-stat-val-sm">{formatBtc(totalLockedSats)}</div>
            <div className="snd-stat-label">Locked dBTC</div>
          </div>
        </div>
      </div>

      {/* Vault list */}
      <div className="snd-card">
        {dlvs.map((d) => {
          const isSpent = d.state === "claimed" || d.state === "invalidated";
          const isExp = expandedDlv === d.vaultId;

          return (
            <div
              key={d.vaultId}
              className={`snd-dlv-item${isSpent ? " snd-dlv-item-spent" : ""}${isExp ? " snd-dlv-item-exp" : ""}`}
              onClick={() => setExpandedDlv(isExp ? null : d.vaultId)}
              style={{ cursor: "pointer" }}
            >
              <div className="snd-dlv-header">
                <div>
                  <div className="snd-dlv-name">{directionLabel(d.direction)}</div>
                  <div className="snd-dlv-kind">
                    {shortId(d.vaultId)}
                  </div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div className="snd-dlv-status">{stateLabel(d.state)}</div>
                  <div className="snd-dlv-repl">{formatBtc(d.amountSats)} dBTC</div>
                </div>
              </div>
              {isExp && (
                <div className="snd-dlv-nodes">
                  <div className="snd-dlv-node-row">
                    <span>Vault ID</span>
                    <span style={{ wordBreak: "break-all", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 9 }}>
                      {d.vaultId}
                    </span>
                  </div>
                  <div className="snd-dlv-node-row">
                    <span>State</span>
                    <span>{stateLabel(d.state)}</span>
                  </div>
                  <div className="snd-dlv-node-row">
                    <span>Amount</span>
                    <span>{formatBtc(d.amountSats)} dBTC</span>
                  </div>
                  <div className="snd-dlv-node-row">
                    <span>Direction</span>
                    <span>{directionLabel(d.direction)}</span>
                  </div>
                  {d.htlcAddress && (
                    <div className="snd-dlv-node-row">
                      <span>HTLC</span>
                      <span style={{ wordBreak: "break-all", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 9 }}>
                        {d.htlcAddress}
                      </span>
                    </div>
                  )}
                  {d.entryHeader.length > 0 && (
                    <div className="snd-dlv-node-row">
                      <span>Entry Header</span>
                      <span>{d.entryHeader.length} bytes</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
