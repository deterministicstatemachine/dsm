// SPDX-License-Identifier: Apache-2.0
import React, { useCallback, useState } from 'react';
import { getVaultDetail, formatBtc } from '../../../services/bitcoinTap';
import { encodeBase32Crockford } from '../../../utils/textId';
import { directionLabel, vaultStateLabel } from './labels';
import type { VaultSummary, VaultDetail } from '../../../services/bitcoinTap';

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

  const idDisplay = encodeBase32Crockford(new TextEncoder().encode(vault.vaultId)).slice(0, 16);
  const isLive = vault.state === 'active' || vault.state === 'limbo';

  return (
    <div className="sb-card" style={{ padding: '8px 10px', cursor: 'pointer' }} onClick={() => void handleExpand()} role="button" tabIndex={0} aria-expanded={expanded} onKeyDown={(e) => e.key === 'Enter' && void handleExpand()}>
      <div className="sb-row" style={{ padding: 0, borderBottom: 0 }}>
        <div className="sb-row__main">
          <div className="sb-row__title"><span>{directionLabel(vault.direction)}</span></div>
          <div className="sb-row__sub sb-mono">{idDisplay}{'…'}</div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div className="sb-row__amount">{formatBtc(vault.amountSats)} BTC</div>
          <span className={`sb-tag${isLive ? ' sb-tag--solid' : ' sb-tag--dim'}`}>{vaultStateLabel(vault.state)}</span>
        </div>
      </div>

      {expanded && (
        <div style={{ marginTop: 8, paddingTop: 6, borderTop: '1px dashed var(--border)' }} onClick={(e) => e.stopPropagation()}>
          <div className="sb-kv"><span className="sb-kv__k">State</span><span className="sb-kv__v">{vault.state}</span></div>
          {vault.htlcAddress && (
            <div className="sb-kv"><span className="sb-kv__k">HTLC</span><span className="sb-kv__v sb-kv__v--mono">{vault.htlcAddress}</span></div>
          )}
          {vault.entryHeader.length > 0 && (
            <div className="sb-kv"><span className="sb-kv__k">Entry header</span><span className="sb-kv__v sb-kv__v--mono">{encodeBase32Crockford(vault.entryHeader).slice(0, 32)}{'…'}</span></div>
          )}
          {loadingDetail && <p className="sb-hint sb-hint--tight">Loading{'…'}</p>}
          {detailError && !loadingDetail && (
            <button type="button" className="sb-btn sb-btn--small" style={{ marginTop: 6 }} onClick={() => void fetchDetail()}>
              Failed to load details. Retry
            </button>
          )}
          {detail && (
            <>
              <div className="sb-kv"><span className="sb-kv__k">Created at state</span><span className="sb-kv__v">{detail.createdAtState.toString()}</span></div>
              {detail.depositId && (
                <div className="sb-kv"><span className="sb-kv__k">Deposit ID</span><span className="sb-kv__v sb-kv__v--mono">{detail.depositId}</span></div>
              )}
              {detail.contentCommitment.length > 0 && (
                <div className="sb-kv"><span className="sb-kv__k">Commitment</span><span className="sb-kv__v sb-kv__v--mono">{encodeBase32Crockford(detail.contentCommitment).slice(0, 32)}{'…'}</span></div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
