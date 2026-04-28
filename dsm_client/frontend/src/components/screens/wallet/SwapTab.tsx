// SPDX-License-Identifier: Apache-2.0
// Swap tab — AMM constant-product trade flow inside the wallet.
//
// Mirrors SendTab's idiom (form → ConfirmModal → status → success toast)
// over the chunks #1–#7 trade pipeline.  All cryptographic operations
// stay Rust-side per the architectural rule; this tab only frames typed
// inputs and orchestrates the async sequence of bridge calls.

import React, { useCallback, useMemo, useState } from 'react';
import {
  listAdvertisementsForPair,
  syncVaultsForPair,
  findAndBindBestPath,
  signRouteCommit,
  computeExternalCommitment,
  publishExternalCommitment,
  unlockVaultRouted,
  type RoutingAdvertisementSummary,
} from '../../../dsm/route_commit';
import { decodeBase32Crockford } from '../../../utils/textId';
import ConfirmModal from '../../ConfirmModal';
import type { Balance } from './helpers';

type Phase =
  | 'idle'
  | 'discovering'
  | 'quoted'
  | 'signing'
  | 'publishing'
  | 'settling'
  | 'settled'
  | 'error';

type QuotedRoute = {
  unsignedBytes: Uint8Array;
  vaults: RoutingAdvertisementSummary[];
  inputAmountBytes: Uint8Array;
  inputToken: Uint8Array;
  outputToken: Uint8Array;
  primaryVaultId: Uint8Array;
};

type Props = {
  balances: Balance[];
  deviceB32: string;
  onCancel: () => void;
  onSwapComplete: () => void;
  loadWalletData: () => Promise<void>;
  setError: (err: string | null) => void;
};

function phaseLabel(phase: Phase): string {
  switch (phase) {
    case 'discovering': return 'Discovering route…';
    case 'quoted': return 'Route ready';
    case 'signing': return 'Signing route commit…';
    case 'publishing': return 'Publishing anchor…';
    case 'settling': return 'Settling on vault…';
    case 'settled': return 'Trade settled';
    case 'error': return 'Failed';
    default: return '';
  }
}

function generateNonce(): Uint8Array {
  const out = new Uint8Array(32);
  crypto.getRandomValues(out);
  return out;
}

function bigIntFromString(s: string): bigint {
  if (!/^[0-9]+$/.test(s)) throw new Error('amount must be a non-negative integer');
  return BigInt(s);
}

function u128BigEndian(n: bigint): Uint8Array {
  if (n < 0n) throw new Error('amount must be non-negative');
  const out = new Uint8Array(16);
  let v = n;
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error('amount exceeds u128');
  return out;
}

function decodeReserveBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) {
    acc = (acc << 8n) | BigInt(b);
  }
  return acc;
}

function SwapTabInner({
  balances,
  deviceB32,
  onCancel,
  onSwapComplete,
  loadWalletData,
  setError,
}: Props): JSX.Element {
  const [inputToken, setInputToken] = useState('ERA');
  const [outputToken, setOutputToken] = useState('');
  const [amount, setAmount] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [phaseDetail, setPhaseDetail] = useState<string>('');
  const [quoted, setQuoted] = useState<QuotedRoute | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);

  const tokenOptions = useMemo(() => {
    if (!Array.isArray(balances) || balances.length === 0) {
      return [{ tokenId: 'ERA', symbol: 'ERA', balance: '0' } as Balance];
    }
    return balances;
  }, [balances]);

  const canQuote = inputToken.trim().length > 0 && outputToken.trim().length > 0 && amount.trim().length > 0;
  const busy = phase === 'discovering' || phase === 'signing' || phase === 'publishing' || phase === 'settling';

  const handleQuote = useCallback(async () => {
    setError(null);
    setQuoted(null);
    setPhaseDetail('');
    try {
      setPhase('discovering');
      const inputTokenBytes = new TextEncoder().encode(inputToken);
      const outputTokenBytes = new TextEncoder().encode(outputToken);
      const amountBig = bigIntFromString(amount);

      // Sync first so the path search runs against fresh vault state.
      const syncRes = await syncVaultsForPair({
        tokenA: inputTokenBytes,
        tokenB: outputTokenBytes,
      });
      if (!syncRes.success) {
        throw new Error(syncRes.error || 'syncVaultsForPair failed');
      }

      const listRes = await listAdvertisementsForPair({
        tokenA: inputTokenBytes,
        tokenB: outputTokenBytes,
      });
      if (!listRes.success) {
        throw new Error(listRes.error || 'listAdvertisementsForPair failed');
      }
      const vaults = listRes.advertisements ?? [];
      if (vaults.length === 0) {
        throw new Error(`No vault advertised for ${inputToken} ↔ ${outputToken}`);
      }

      const bindRes = await findAndBindBestPath({
        inputToken: inputTokenBytes,
        outputToken: outputTokenBytes,
        inputAmount: amountBig,
        nonce: generateNonce(),
      });
      if (!bindRes.success || !bindRes.unsignedRouteCommitBytes) {
        throw new Error(bindRes.error || 'findAndBindBestPath failed');
      }

      const primaryVaultBytes = decodeBase32Crockford(vaults[0].vaultIdBase32);
      setQuoted({
        unsignedBytes: bindRes.unsignedRouteCommitBytes,
        vaults,
        inputAmountBytes: u128BigEndian(amountBig),
        inputToken: inputTokenBytes,
        outputToken: outputTokenBytes,
        primaryVaultId: primaryVaultBytes,
      });
      setPhase('quoted');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'quote failed';
      setError(msg);
      setPhase('error');
      setPhaseDetail(msg);
    }
  }, [inputToken, outputToken, amount, setError]);

  const handleExecute = useCallback(async () => {
    if (!quoted) return;
    setError(null);
    setPhaseDetail('');
    try {
      setPhase('signing');
      const signed = await signRouteCommit(quoted.unsignedBytes);
      if (!signed.success || !signed.signedRouteCommitBase32) {
        throw new Error(signed.error || 'signRouteCommit failed');
      }
      const signedBytes = decodeBase32Crockford(signed.signedRouteCommitBase32);

      const xRes = await computeExternalCommitment(signedBytes);
      if (!xRes.success || !xRes.xBase32) {
        throw new Error(xRes.error || 'computeExternalCommitment failed');
      }

      setPhase('publishing');
      const publish = await publishExternalCommitment({
        x: decodeBase32Crockford(xRes.xBase32),
      });
      if (!publish.success) {
        throw new Error(publish.error || 'publishExternalCommitment failed');
      }

      setPhase('settling');
      if (!deviceB32) {
        throw new Error('wallet device id unavailable');
      }
      const deviceBytes = decodeBase32Crockford(deviceB32);
      const unlock = await unlockVaultRouted({
        vaultId: quoted.primaryVaultId,
        deviceId: deviceBytes,
        routeCommitBytes: signedBytes,
      });
      if (!unlock.success) {
        throw new Error(unlock.error || 'unlockVaultRouted failed');
      }

      setPhase('settled');
      await loadWalletData();
      onSwapComplete();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'execute failed';
      setError(msg);
      setPhase('error');
      setPhaseDetail(msg);
    }
  }, [quoted, deviceB32, loadWalletData, onSwapComplete, setError]);

  const expectedOutput = useMemo(() => {
    if (!quoted || quoted.vaults.length === 0) return '';
    // Show the primary vault's quote as the route preview.  Multi-hop
    // routing is supported by the bridge but the headline number is
    // the first hop's expected output for now.
    const v = quoted.vaults[0];
    const inA = decodeReserveBigInt(quoted.inputAmountBytes);
    if (inA === 0n) return '';
    const reserveIn = v.reserveA; // canonical pair-ordering enforced by Rust.
    const reserveOut = v.reserveB;
    const fee = BigInt(10_000 - v.feeBps);
    const inEffective = (inA * fee) / 10_000n;
    if (reserveIn + inEffective === 0n) return '';
    const out = (reserveOut * inEffective) / (reserveIn + inEffective);
    return out.toString();
  }, [quoted]);

  return (
    <div>
      <div className="form-group">
        <label htmlFor="swap-from">From</label>
        <div className="amount-input-group">
          <input
            id="swap-amount"
            type="number"
            min="0"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="0"
            className="form-input"
          />
          <select
            id="swap-from"
            value={inputToken}
            onChange={(e) => setInputToken(e.target.value)}
            className="token-selector"
          >
            {tokenOptions.map((b) => (
              <option key={b.tokenId} value={b.tokenId}>{b.symbol || b.tokenId}</option>
            ))}
          </select>
        </div>
      </div>
      <div className="form-group">
        <label htmlFor="swap-to">To</label>
        <input
          id="swap-to"
          type="text"
          value={outputToken}
          onChange={(e) => setOutputToken(e.target.value)}
          placeholder="Output token id"
          className="form-input"
        />
      </div>

      {quoted && (
        <div className="balance-section" style={{ marginBottom: 12 }}>
          <h4 style={{ fontSize: 12, marginBottom: 8 }}>Route</h4>
          <div className="balance-card" style={{ padding: '8px 12px' }}>
            <div className="balance-info">
              <span className="token-symbol">{quoted.vaults.length} vault{quoted.vaults.length === 1 ? '' : 's'} discovered</span>
              <span className="balance-amount">{expectedOutput} {outputToken}</span>
            </div>
            <div style={{ fontSize: 10, opacity: 0.7, marginTop: 4 }}>
              fee {quoted.vaults[0]?.feeBps} bps · vault {quoted.vaults[0]?.vaultIdBase32.slice(0, 12)}…
            </div>
          </div>
        </div>
      )}

      {phase !== 'idle' && phase !== 'quoted' && (
        <div
          className="warning-banner"
          style={{
            padding: '8px 12px',
            marginBottom: 12,
            fontSize: 11,
            border: '1px solid var(--border)',
            background: phase === 'error' ? 'rgba(255,0,0,0.08)' : 'rgba(var(--text-rgb),0.08)',
          }}
          role="status"
          aria-live="polite"
        >
          <strong>{phaseLabel(phase)}</strong>
          {phaseDetail && <div style={{ marginTop: 4, opacity: 0.85 }}>{phaseDetail}</div>}
        </div>
      )}

      <div className="form-actions">
        <button type="button" onClick={onCancel} className="cancel-button" disabled={busy}>
          Cancel
        </button>
        {!quoted && (
          <button
            type="button"
            onClick={() => void handleQuote()}
            className="send-button button-brick"
            disabled={!canQuote || busy}
          >
            {phase === 'discovering' ? 'Quoting…' : 'Quote'}
          </button>
        )}
        {quoted && (
          <button
            type="button"
            onClick={() => setShowConfirm(true)}
            className="send-button button-brick"
            disabled={busy}
          >
            {busy ? 'Settling…' : 'Swap'}
          </button>
        )}
      </div>

      <ConfirmModal
        visible={showConfirm}
        title="Confirm swap"
        message={`Swap ${amount} ${inputToken} for ~${expectedOutput} ${outputToken} via ${quoted?.vaults.length ?? 0} vault${(quoted?.vaults.length ?? 0) === 1 ? '' : 's'}?`}
        onConfirm={() => { setShowConfirm(false); void handleExecute(); }}
        onCancel={() => setShowConfirm(false)}
      />
    </div>
  );
}

const SwapTab = React.memo(SwapTabInner);
export default SwapTab;
