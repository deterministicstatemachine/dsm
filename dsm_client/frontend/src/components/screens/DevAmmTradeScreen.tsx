/* eslint-disable @typescript-eslint/no-explicit-any, no-console */
// SPDX-License-Identifier: Apache-2.0
// path: src/components/screens/DevAmmTradeScreen.tsx
//
// AMM trader — discovers vaults for a token pair, runs the full
// trade pipeline (sync → find+bind → sign → compute X → publish
// anchor → unlockRouted) end-to-end on the local device.
//
// All protocol logic stays Rust-side: this screen only frames typed
// inputs and renders status.  The 6-step pipeline below is six bridge
// calls — no crypto, no canonicalisation, no signing in TypeScript.

import React, { useState, useMemo, useCallback } from 'react';
import { useDpadNav } from '../../hooks/useDpadNav';
import {
  listAdvertisementsForPair,
  syncVaultsForPair,
  findAndBindBestPath,
  signRouteCommit,
  computeExternalCommitment,
  publishExternalCommitment,
  unlockVaultRouted,
  type RoutingAdvertisementSummary,
} from '../../dsm/route_commit';
import { decodeBase32Crockford } from '../../utils/textId';
import './SettingsScreen.css';

const DEFAULT_INPUT = 'DEMO_AAA';
const DEFAULT_OUTPUT = 'DEMO_BBB';
const DEFAULT_AMOUNT = '10000';

function bigIntFromString(s: string): bigint {
  if (!/^[0-9]+$/.test(s)) throw new Error('must be a non-negative integer');
  return BigInt(s);
}

function randomNonce32(): Uint8Array {
  // Replay-protection nonce.  Not protocol-defined crypto — just an
  // opaque random uint128 worth of bytes per RouteCommit binding.
  const out = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(out);
  } else {
    // Webkit/Android fallback (paranoia — production builds always
    // have crypto.getRandomValues).
    for (let i = 0; i < 32; i++) {
      // eslint-disable-next-line security/detect-non-literal-require
      out[i] = Math.floor(Math.random() * 256);
    }
  }
  return out;
}

interface TradeStep {
  label: string;
  status: 'pending' | 'running' | 'ok' | 'fail';
  detail?: string;
}

const INITIAL_STEPS = (): TradeStep[] => [
  { label: '1. Sync local DLVManager from routing keyspace', status: 'pending' },
  { label: '2. Find + bind best path (unsigned RouteCommit)', status: 'pending' },
  { label: '3. Sign the RouteCommit (wallet pk + SPHINCS+)', status: 'pending' },
  { label: '4. Compute external commitment X', status: 'pending' },
  { label: '5. Publish anchor at defi/extcommit/X', status: 'pending' },
  { label: '6. Execute unlockRouted on selected vault', status: 'pending' },
];

export default function DevAmmTradeScreen(): JSX.Element {
  const [inputToken, setInputToken] = useState(DEFAULT_INPUT);
  const [outputToken, setOutputToken] = useState(DEFAULT_OUTPUT);
  const [inputAmount, setInputAmount] = useState(DEFAULT_AMOUNT);
  const [discoveredAds, setDiscoveredAds] = useState<RoutingAdvertisementSummary[]>([]);
  const [selectedVaultIdB32, setSelectedVaultIdB32] = useState('');
  const [steps, setSteps] = useState<TradeStep[]>(INITIAL_STEPS());
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string>('');

  const updateStep = useCallback(
    (index: number, status: TradeStep['status'], detail?: string) => {
      setSteps((prev) => {
        const next = prev.slice();
        next[index] = { ...next[index], status, detail };
        return next;
      });
    },
    [],
  );

  const handleQuote = useCallback(async () => {
    setBusy(true);
    setStatus('');
    try {
      if (!inputToken.trim() || !outputToken.trim()) {
        setStatus('Both tokens are required');
        return;
      }
      const result = await listAdvertisementsForPair({
        tokenA: new TextEncoder().encode(inputToken.trim()),
        tokenB: new TextEncoder().encode(outputToken.trim()),
      });
      if (!result.success) {
        setStatus(`Quote failed: ${result.error ?? 'unknown'}`);
        return;
      }
      setDiscoveredAds(result.advertisements ?? []);
      if ((result.advertisements ?? []).length === 0) {
        setStatus('No vaults advertised for this pair');
      } else {
        setStatus(`${(result.advertisements ?? []).length} vault(s) discovered`);
        if (!selectedVaultIdB32 && result.advertisements?.[0]) {
          setSelectedVaultIdB32(result.advertisements[0].vaultIdBase32);
        }
      }
    } catch (e: any) {
      setStatus(e?.message || 'Quote failed');
    } finally {
      setBusy(false);
    }
  }, [inputToken, outputToken, selectedVaultIdB32]);

  const handleTrade = useCallback(async () => {
    setBusy(true);
    setStatus('');
    setSteps(INITIAL_STEPS());
    const inputBytes = new TextEncoder().encode(inputToken.trim());
    const outputBytes = new TextEncoder().encode(outputToken.trim());
    let amount: bigint;
    try {
      amount = bigIntFromString(inputAmount.trim());
    } catch (e: any) {
      setStatus(`inputAmount: ${e?.message ?? 'invalid'}`);
      setBusy(false);
      return;
    }
    if (!selectedVaultIdB32) {
      setStatus('Select a vault first (run Quote)');
      setBusy(false);
      return;
    }
    let vaultIdBytes: Uint8Array;
    try {
      vaultIdBytes = new Uint8Array(decodeBase32Crockford(selectedVaultIdB32));
      if (vaultIdBytes.length !== 32) {
        throw new Error('decoded vault id is not 32 bytes');
      }
    } catch (e: any) {
      setStatus(`Selected vault id invalid: ${e?.message}`);
      setBusy(false);
      return;
    }

    try {
      // 1. Sync
      updateStep(0, 'running');
      const sync = await syncVaultsForPair({ tokenA: inputBytes, tokenB: outputBytes });
      if (!sync.success) {
        updateStep(0, 'fail', sync.error);
        setStatus(`Step 1 failed: ${sync.error}`);
        return;
      }
      updateStep(0, 'ok', `${sync.newlyMirroredBase32?.length ?? 0} newly mirrored`);

      // 2. Find + bind
      updateStep(1, 'running');
      const nonce = randomNonce32();
      const findRes = await findAndBindBestPath({
        inputToken: inputBytes,
        outputToken: outputBytes,
        inputAmount: amount,
        nonce,
      });
      if (!findRes.success || !findRes.unsignedRouteCommitBytes) {
        updateStep(1, 'fail', findRes.error);
        setStatus(`Step 2 failed: ${findRes.error}`);
        return;
      }
      const unsignedBytes = findRes.unsignedRouteCommitBytes;
      updateStep(1, 'ok', `unsigned RouteCommit = ${unsignedBytes.length} bytes`);

      // 3. Sign
      updateStep(2, 'running');
      const signRes = await signRouteCommit(unsignedBytes);
      if (!signRes.success || !signRes.signedRouteCommitBase32) {
        updateStep(2, 'fail', signRes.error);
        setStatus(`Step 3 failed: ${signRes.error}`);
        return;
      }
      const signedBytes = new Uint8Array(decodeBase32Crockford(signRes.signedRouteCommitBase32));
      updateStep(2, 'ok', `signed bytes = ${signedBytes.length}`);

      // 4. Compute X
      updateStep(3, 'running');
      const xRes = await computeExternalCommitment(signedBytes);
      if (!xRes.success || !xRes.xBase32) {
        updateStep(3, 'fail', xRes.error);
        setStatus(`Step 4 failed: ${xRes.error}`);
        return;
      }
      const xBytes = new Uint8Array(decodeBase32Crockford(xRes.xBase32));
      updateStep(3, 'ok', `X = ${xRes.xBase32.slice(0, 12)}…`);

      // 5. Publish anchor
      updateStep(4, 'running');
      // Wallet pk is exposed via the existing wallet bridge; for a
      // dev-tools screen we forward an empty publisher pk and let the
      // handler reject if needed (Track C.4 follow-up: stamp wallet pk
      // on empty publisher field too).  For now, use a zero placeholder
      // — the chunk #4 anchor verifier checks digest binding, not pk.
      const publisherPlaceholder = new Uint8Array(64);
      const pubRes = await publishExternalCommitment({
        x: xBytes,
        publisherPublicKey: publisherPlaceholder,
        label: 'dev-amm-trade',
      });
      if (!pubRes.success) {
        updateStep(4, 'fail', pubRes.error);
        setStatus(`Step 5 failed: ${pubRes.error}`);
        return;
      }
      updateStep(4, 'ok', 'anchor published');

      // 6. unlockRouted
      updateStep(5, 'running');
      // device_id placeholder — handler resolves the real one from
      // local state.  For dev tools we can pass any 32-byte filler;
      // the gate uses the actor self-loop derived inside Rust.
      const deviceIdPlaceholder = new Uint8Array(32);
      const unlockRes = await unlockVaultRouted({
        vaultId: vaultIdBytes,
        deviceId: deviceIdPlaceholder,
        routeCommitBytes: signedBytes,
      });
      if (!unlockRes.success) {
        updateStep(5, 'fail', unlockRes.error);
        setStatus(`Step 6 failed: ${unlockRes.error}`);
        return;
      }
      updateStep(5, 'ok', `vault_id=${unlockRes.vaultIdBase32}`);
      setStatus('Trade settled.');
    } catch (e: any) {
      setStatus(e?.message || 'Trade pipeline failed');
    } finally {
      setBusy(false);
    }
  }, [inputToken, outputToken, inputAmount, selectedVaultIdB32, updateStep]);

  const navActions = useMemo(
    () => [() => void handleQuote(), () => void handleTrade()],
    [handleQuote, handleTrade],
  );
  useDpadNav({ actions: navActions });

  return (
    <div className="settings-screen">
      <h1>AMM Trade (Dev)</h1>
      <p className="settings-subtitle">
        Pair → quote → 6-step trade pipeline.  All crypto + path
        search runs in Rust.
      </p>

      <section style={{ marginBottom: 16 }}>
        <h2>Trade</h2>
        <label>
          input token
          <input
            type="text"
            value={inputToken}
            onChange={(e) => setInputToken(e.target.value)}
            disabled={busy}
            style={{ width: '100%' }}
          />
        </label>
        <label>
          output token
          <input
            type="text"
            value={outputToken}
            onChange={(e) => setOutputToken(e.target.value)}
            disabled={busy}
            style={{ width: '100%' }}
          />
        </label>
        <label>
          input amount
          <input
            type="text"
            inputMode="numeric"
            value={inputAmount}
            onChange={(e) => setInputAmount(e.target.value)}
            disabled={busy}
            style={{ width: '100%' }}
          />
        </label>
      </section>

      <section style={{ marginBottom: 16 }}>
        <button type="button" onClick={handleQuote} disabled={busy}>
          {busy ? 'Working…' : 'Quote'}
        </button>{' '}
        <button
          type="button"
          onClick={handleTrade}
          disabled={busy || !selectedVaultIdB32}
        >
          {busy ? 'Working…' : 'Execute trade'}
        </button>
      </section>

      {discoveredAds.length > 0 && (
        <section style={{ marginBottom: 16 }}>
          <h2>Discovered vaults</h2>
          {discoveredAds.map((ad) => (
            <label
              key={ad.vaultIdBase32}
              style={{
                display: 'block',
                padding: 6,
                marginBottom: 4,
                background:
                  selectedVaultIdB32 === ad.vaultIdBase32 ? '#22444466' : 'transparent',
                cursor: 'pointer',
              }}
            >
              <input
                type="radio"
                name="vault"
                value={ad.vaultIdBase32}
                checked={selectedVaultIdB32 === ad.vaultIdBase32}
                onChange={() => setSelectedVaultIdB32(ad.vaultIdBase32)}
                disabled={busy}
              />{' '}
              <code style={{ fontSize: 11 }}>
                {ad.vaultIdBase32.slice(0, 12)}… reserves=({String(ad.reserveA)},{' '}
                {String(ad.reserveB)}) fee={ad.feeBps}bps state#={String(ad.stateNumber)}
              </code>
            </label>
          ))}
        </section>
      )}

      <section style={{ marginBottom: 16 }}>
        <h2>Pipeline</h2>
        {steps.map((s) => (
          <div key={s.label} style={{ fontFamily: 'monospace', fontSize: 12 }}>
            <span style={{ marginRight: 6 }}>
              {s.status === 'ok' && '✓'}
              {s.status === 'fail' && '✗'}
              {s.status === 'running' && '·'}
              {s.status === 'pending' && ' '}
            </span>
            {s.label}
            {s.detail && (
              <span style={{ color: '#888', marginLeft: 6 }}>— {s.detail}</span>
            )}
          </div>
        ))}
      </section>

      {status && (
        <p
          style={{
            padding: 8,
            background: status.toLowerCase().includes('fail') ? '#cc444433' : '#44cc4433',
            fontFamily: 'monospace',
            fontSize: 12,
            wordBreak: 'break-all',
          }}
        >
          {status}
        </p>
      )}
    </div>
  );
}
