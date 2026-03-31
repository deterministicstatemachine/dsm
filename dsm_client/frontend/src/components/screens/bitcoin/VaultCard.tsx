// SPDX-License-Identifier: Apache-2.0
import React, { useCallback, useState } from 'react';
import { getVaultDetail, formatBtc } from '../../../services/bitcoinTap';
import { encodeBase32Crockford } from '../../../utils/textId';
import type { VaultSummary, VaultDetail } from '../../../services/bitcoinTap';

const VAULT_STATE_BORDERS: Record<string, string> = {
  limbo: 'dotted',
  active: 'solid',
  unlocked: 'solid',
  claimed: 'double',
  invalidated: 'dashed',
};

export default function VaultCard({ vault }: { vault: VaultSummary }): JSX.Element {
  const [expanded, setExpanded] = useState(false);
  const [detail, setDetail] = useState<VaultDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState(false);

  const fetchDetail = useCallback(async () => {
    setLoadingDetail(true);
    setDetailError(false);
    try {
      const loaded = await getVaultDetail(vault.vaultId);
      setDetail(loaded);
    } catch {
      setDetailError(true);
    } finally {
      setLoadingDetail(false);
    }
  }, [vault.vaultId]);

  const handleExpand = useCallback(async () => {
    const next = !expanded;
    setExpanded(next);
    if (next && !detail && !detailError) {
      await fetchDetail();
    }
  }, [expanded, detail, detailError, fetchDetail]);

  const stateBorder = VAULT_STATE_BORDERS[vault.state] || 'solid';
  const idDisplay = encodeBase32Crockford(new TextEncoder().encode(vault.vaultId)).slice(0, 16);

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 6, marginBottom: 8, padding: '8px 10px', fontSize: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }} onClick={() => void handleExpand()}>
        <div>
          <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{idDisplay}…</span>
          <span style={{ marginLeft: 8, padding: '1px 6px', borderRadius: 3, fontSize: 10, fontWeight: 600, color: 'var(--text-dark)', background: 'rgba(var(--text-rgb),0.10)', border: `2px ${stateBorder} var(--border)` }}>
            {vault.state.toUpperCase()}
          </span>
        </div>
        <div style={{ fontSize: 11, fontFamily: 'monospace' }}>{formatBtc(vault.amountSats)} BTC</div>
      </div>

      {expanded && (
        <div style={{ marginTop: 8, fontSize: 11 }}>
          <div><b>Direction:</b> {vault.direction === 'btc_to_dbtc' ? 'BTC \u2192 dBTC' : vault.direction === 'dbtc_to_btc' ? 'dBTC \u2192 BTC' : vault.direction}</div>
          {vault.htlcAddress && <div style={{ wordBreak: 'break-all' }}><b>HTLC:</b> {vault.htlcAddress}</div>}
          {vault.entryHeader.length > 0 && (
            <div style={{ wordBreak: 'break-all' }}><b>Entry Header:</b> {encodeBase32Crockford(vault.entryHeader).slice(0, 32)}\u2026</div>
          )}
          {loadingDetail && <div style={{ color: 'var(--text-disabled)', marginTop: 4 }}>Loading\u2026</div>}
          {detailError && !loadingDetail && (
            <div
              style={{ color: 'var(--text-disabled)', marginTop: 4, cursor: 'pointer', textDecoration: 'underline' }}
              onClick={(e) => { e.stopPropagation(); void fetchDetail(); }}
            >
              Failed to load details. Tap to retry.
            </div>
          )}
          {detail && (
            <div style={{ marginTop: 4 }}>
              <div><b>Created at state:</b> {detail.createdAtState.toString()}</div>
              {detail.depositId && <div><b>Deposit ID:</b> {detail.depositId}</div>}
              {detail.contentCommitment.length > 0 && (
                <div style={{ wordBreak: 'break-all' }}><b>Commitment:</b> {encodeBase32Crockford(detail.contentCommitment).slice(0, 32)}\u2026</div>
              )}
            </div>
          )}

          <div style={{ marginTop: 8, padding: '6px 8px', border: '1px dashed var(--border)', borderRadius: 6, fontSize: 10, color: 'var(--text-disabled)', background: 'var(--bg-secondary)' }}>
            Withdrawals are planned from the dedicated review flow. Vault cards are status-only.
          </div>
        </div>
      )}
    </div>
  );
}
