// SPDX-License-Identifier: MIT OR Apache-2.0

// src/components/screens/StorageScreen.tsx
// The storage set this device's traffic uses and what each member answered
// (SDK storage.status). Rendering only.
import React, { useEffect, useState, useMemo, useCallback } from "react";
import { StorageMembersPanel, StorageSetPanel } from "../storage/StorageNodePanels";
import type { StorageStatus } from "../../dsm/types";
import { useDpadNav } from "../../hooks/useDpadNav";
import {
  storageStore,
  useStorageStore,
  type SofiVaultsView,
} from "../../stores/storageStore";
import { encodeBase32Crockford } from "../../utils/textId";
import { formatBtc, type VaultSummary } from "../../services/bitcoinTap";
import { Notice, ScreenFrame, ScreenTabs } from "../common/ScreenFrame";
import { InfoTip } from "../common/InfoTip";

type StorageTab = "set" | "members" | "dlvs";

const TABS: ReadonlyArray<{ id: StorageTab; label: string }> = [
  { id: "set", label: "Set" },
  { id: "members", label: "Members" },
  { id: "dlvs", label: "DLVs" },
];

const StorageScreen: React.FC = () => {
  const storage = useStorageStore();
  const [expandedDlv, setExpandedDlv] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<StorageTab>("set");

  useEffect(() => {
    void storageStore.refreshStatus();
    void storageStore.refreshDlvsAndPresence();
    storageStore.refreshSofiVaults();
  }, []);

  // --- D-pad navigation: the tabs ---
  const navActions = useMemo(() => TABS.map((tab) => () => setActiveTab(tab.id)), []);

  const { focusedIndex } = useDpadNav({
    itemCount: TABS.length,
    onSelect: (idx) => navActions[idx]?.(),
  });

  const refresh = useCallback(() => {
    void storageStore.refreshStatus();
    if (activeTab === "dlvs") void storageStore.refreshDlvsAndPresence();
    if (activeTab === "dlvs") storageStore.refreshSofiVaults();
  }, [activeTab]);

  const busy = activeTab === "dlvs"
    ? storage.dlvLoading || storage.sofiVaults.state === "loading"
    : storage.statusLoading;

  return (
    <ScreenFrame
      title="Storage Nodes"
      className="storage-screen"
      info={(
        <InfoTip title="Storage nodes">
          <p>The storage set is pinned for this device&apos;s network. Its members keep what you publish so others can reach you while you are away. They hold bytes and decide nothing.</p>
          <p>Each member&apos;s latest ByteCommit is shown as that member states it. A member that did not answer has not failed, and nothing a member answers is a verdict.</p>
          <p><b>Syncs</b> counts the inbox syncs that ran to their end on this device.</p>
        </InfoTip>
      )}
      actions={(
        <button
          type="button"
          onClick={refresh}
          className={`sb-icon-btn${busy ? " spinning" : ""}`}
          disabled={busy}
          title="Refresh"
          aria-label="Refresh"
        >
          <img src="images/icons/icon_refresh.svg" alt="" />
        </button>
      )}
      tabs={(
        <ScreenTabs
          tabs={TABS}
          active={activeTab}
          onChange={setActiveTab}
          ariaLabel="Storage sections"
          focusedIndex={focusedIndex}
        />
      )}
    >
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
        <>
          <div data-tour="liquidity-vaults">
            <SofiVaultsSection
              view={storage.sofiVaults}
              onRetry={storageStore.refreshSofiVaults}
            />
          </div>
          <DlvTab
            dlvLoading={storage.dlvLoading}
            dlvs={storage.dlvs}
            expandedDlv={expandedDlv}
            setExpandedDlv={setExpandedDlv}
          />
        </>
      )}
    </ScreenFrame>
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
  if (loading) return <div className="sb-empty">Asking the storage set…</div>;

  if (error || !status) {
    return (
      <>
        <Notice kind="error">{error ?? "No storage status."}</Notice>
        <div className="sb-actions">
          <button type="button" className="sb-btn sb-btn--primary" onClick={onRefresh}>
            Try Again
          </button>
        </div>
      </>
    );
  }

  return tab === "set"
    ? <StorageSetPanel status={status} />
    : <StorageMembersPanel members={status.members} />;
};

// ═══════════════════════════════════════════════════════════════════════
// dBTC vaults — real vault data from bitcoin.vault.list
// ═══════════════════════════════════════════════════════════════════════

function shortVault(id: string): string {
  return id.length <= 12 ? id : `${id.slice(0, 12)}…`;
}

/**
 * The owner's liquidity vaults (sofi.vaults), each walked to its head: the
 * live reserves without closing.
 */
const SofiVaultsSection: React.FC<{
  view: SofiVaultsView;
  onRetry: () => void;
}> = ({ view, onRetry }) => {
  if (view.state === "loading") {
    return <div className="sb-empty">Walking your liquidity vaults…</div>;
  }
  if (view.state === "error") {
    return (
      <>
        <Notice kind="error">{view.message}</Notice>
        <div className="sb-actions">
          <button type="button" className="sb-btn sb-btn--primary" onClick={onRetry}>
            Try Again
          </button>
        </div>
      </>
    );
  }
  if (view.vaults.length === 0) {
    return <div className="sb-empty">You have created no liquidity vaults.</div>;
  }
  return (
    <section className="sb-card" aria-label="Liquidity vaults">
      <div className="sb-card__title">
        <span>Liquidity vaults</span>
        <span>{view.vaults.length}</span>
      </div>
      {view.vaults.map((v) => {
        const id = encodeBase32Crockford(v.vaultId);
        const open = v.status === "active";
        return (
          <div className="sb-row" key={id} style={open ? undefined : { opacity: 0.6 }}>
            <div className="sb-row__main">
              <div className="sb-row__title">{v.symbolA} / {v.symbolB}</div>
              <div className="sb-row__sub sb-mono">
                {shortVault(id)} · {v.feeBps} bps · generation {v.generation.toString()}
              </div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div><span className={`sb-tag${open ? " sb-tag--solid" : " sb-tag--dim"}`}>{open ? "Active" : "Closed"}</span></div>
              <div className="sb-row__amount">{v.reserveADisplay} {v.symbolA}</div>
              <div className="sb-row__amount">{v.reserveBDisplay} {v.symbolB}</div>
            </div>
          </div>
        );
      })}
    </section>
  );
};

const STATE_LABELS: Record<string, string> = {
  limbo: "Limbo",
  active: "Active",
  unlocked: "Unlocked",
  claimed: "Claimed",
  invalidated: "Invalidated",
};

const DIRECTION_LABELS: Record<string, string> = {
  btc_to_dbtc: "BTC → dBTC",
  dbtc_to_btc: "dBTC → BTC",
};

function stateLabel(s: string): string {
  return STATE_LABELS[s] ?? s;
}

function directionLabel(d: string): string {
  return DIRECTION_LABELS[d] ?? d;
}

function shortId(id: string, len = 12): string {
  if (!id || id.length <= len) return id || "—";
  return `${id.slice(0, len)}…`;
}

const DlvTab: React.FC<{
  dlvLoading: boolean;
  dlvs: VaultSummary[];
  expandedDlv: string | null;
  setExpandedDlv: (v: string | null) => void;
}> = ({ dlvLoading, dlvs, expandedDlv, setExpandedDlv }) => {
  if (dlvLoading) return <div className="sb-empty">Scanning dBTC vaults…</div>;

  if (dlvs.length === 0) {
    return <div className="sb-empty">No dBTC vaults on this device.</div>;
  }

  const live = dlvs.filter((d) => d.state === "active" || d.state === "limbo");
  const active = live.length;
  const hist = dlvs.length - active;
  const totalLockedSats = live.reduce((sum, d) => sum + d.amountSats, 0n);

  return (
    <>
      <section className="sb-card sb-card--dark" aria-label="DLV summary">
        <div className="sb-stats">
          <div className="sb-stats__cell">
            <div className="sb-stats__val">{active}</div>
            <div className="sb-stats__label">Active</div>
          </div>
          <div className="sb-stats__cell">
            <div className="sb-stats__val">{hist}</div>
            <div className="sb-stats__label">Historical</div>
          </div>
          <div className="sb-stats__cell">
            <div className="sb-stats__val sb-stats__val--sm">{formatBtc(totalLockedSats)}</div>
            <div className="sb-stats__label">Locked dBTC</div>
          </div>
        </div>
      </section>

      <section className="sb-card">
        {dlvs.map((d) => {
          const isSpent = d.state === "claimed" || d.state === "invalidated";
          const isExp = expandedDlv === d.vaultId;
          const toggle = () => setExpandedDlv(isExp ? null : d.vaultId);

          return (
            <React.Fragment key={d.vaultId}>
              <div
                className={`sb-row sb-row--tap${isExp ? " is-open" : ""}`}
                role="button"
                tabIndex={0}
                aria-expanded={isExp}
                onClick={toggle}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    toggle();
                  }
                }}
                style={isSpent ? { opacity: 0.6 } : undefined}
              >
                <div className="sb-row__main">
                  <div className="sb-row__title">{directionLabel(d.direction)}</div>
                  <div className="sb-row__sub sb-mono">{shortId(d.vaultId)}</div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div><span className={`sb-tag${isSpent ? " sb-tag--dim" : " sb-tag--solid"}`}>{stateLabel(d.state)}</span></div>
                  <div className="sb-row__amount">{formatBtc(d.amountSats)} dBTC</div>
                </div>
                <span className="sb-row__chev" aria-hidden="true">{isExp ? "▾" : "›"}</span>
              </div>
              {isExp && (
                <div className="sb-row__detail">
                  <div className="sb-kv">
                    <span className="sb-kv__k">Vault ID</span>
                    <span className="sb-kv__v sb-kv__v--mono">{d.vaultId}</span>
                  </div>
                  <div className="sb-kv">
                    <span className="sb-kv__k">State</span>
                    <span className="sb-kv__v">{stateLabel(d.state)}</span>
                  </div>
                  <div className="sb-kv">
                    <span className="sb-kv__k">Amount</span>
                    <span className="sb-kv__v">{formatBtc(d.amountSats)} dBTC</span>
                  </div>
                  <div className="sb-kv">
                    <span className="sb-kv__k">Direction</span>
                    <span className="sb-kv__v">{directionLabel(d.direction)}</span>
                  </div>
                  {d.htlcAddress && (
                    <div className="sb-kv">
                      <span className="sb-kv__k">HTLC</span>
                      <span className="sb-kv__v sb-kv__v--mono">{d.htlcAddress}</span>
                    </div>
                  )}
                  {d.entryHeader.length > 0 && (
                    <div className="sb-kv">
                      <span className="sb-kv__k">Entry Header</span>
                      <span className="sb-kv__v">{d.entryHeader.length} bytes</span>
                    </div>
                  )}
                </div>
              )}
            </React.Fragment>
          );
        })}
      </section>
    </>
  );
};
