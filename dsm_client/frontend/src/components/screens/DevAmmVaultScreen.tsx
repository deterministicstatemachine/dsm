/* eslint-disable @typescript-eslint/no-explicit-any, no-console */
// SPDX-License-Identifier: Apache-2.0
// path: src/components/screens/DevAmmVaultScreen.tsx
//
// AMM vault owner — create a constant-product vault and publish its
// routing advertisement so traders can discover + route through it.
//
// Per the architecture rules, this screen carries ZERO protocol
// logic: every protocol-side step (digest computation, SPHINCS+
// signing, vault state advance, advertisement digest binding) runs
// in Rust over the bridge.  This file only frames typed inputs and
// renders results.

import React, { useState, useMemo } from 'react';
import { useDpadNav } from '../../hooks/useDpadNav';
import { createAmmVault } from '../../dsm/amm';
import { publishRoutingAdvertisement } from '../../dsm/route_commit';
import { decodeBase32Crockford } from '../../utils/textId';
import './SettingsScreen.css';

const DEFAULT_TOKEN_A = 'DEMO_AAA';
const DEFAULT_TOKEN_B = 'DEMO_BBB';
const DEFAULT_RESERVE = '1000000';
const DEFAULT_FEE_BPS = '30';

function bigIntFromString(s: string): bigint {
  if (!/^[0-9]+$/.test(s)) throw new Error('must be a non-negative integer');
  return BigInt(s);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function compareTokens(a: string, b: string): number {
  const aB = new TextEncoder().encode(a);
  const bB = new TextEncoder().encode(b);
  const len = Math.min(aB.length, bB.length);
  for (let i = 0; i < len; i++) {
    if (aB[i] !== bB[i]) return aB[i] - bB[i];
  }
  return aB.length - bB.length;
}

export default function DevAmmVaultScreen(): JSX.Element {
  const [tokenA, setTokenA] = useState(DEFAULT_TOKEN_A);
  const [tokenB, setTokenB] = useState(DEFAULT_TOKEN_B);
  const [reserveA, setReserveA] = useState(DEFAULT_RESERVE);
  const [reserveB, setReserveB] = useState(DEFAULT_RESERVE);
  const [feeBps, setFeeBps] = useState(DEFAULT_FEE_BPS);
  // 32-byte CPTA anchor as Base32 Crockford.  Per the rules: copy/
  // paste-able identifiers must be Base32 Crockford.  No hex.
  const [policyAnchor, setPolicyAnchor] = useState('');
  // Vault id from the most recent create — pre-populates the
  // "publish advertisement" step.
  const [lastVaultIdB32, setLastVaultIdB32] = useState('');
  const [status, setStatus] = useState<string>('');
  const [busy, setBusy] = useState(false);

  const pairOk = useMemo(
    () => tokenA.length > 0 && tokenB.length > 0 && compareTokens(tokenA, tokenB) < 0,
    [tokenA, tokenB],
  );
  const policyAnchorBytes = useMemo(() => {
    if (!policyAnchor.trim()) return null;
    try {
      const decoded = new Uint8Array(decodeBase32Crockford(policyAnchor.trim()));
      if (decoded.length !== 32) return null;
      return decoded;
    } catch {
      return null;
    }
  }, [policyAnchor]);

  const handleCreate = async () => {
    setBusy(true);
    setStatus('');
    try {
      if (!pairOk) {
        setStatus('Pair must be lex-ordered (tokenA < tokenB) and non-empty');
        return;
      }
      if (!policyAnchorBytes) {
        setStatus('Policy anchor must be a 32-byte Base32 Crockford string');
        return;
      }
      const reserveAVal = bigIntFromString(reserveA.trim());
      const reserveBVal = bigIntFromString(reserveB.trim());
      const feeBpsVal = Number(feeBps.trim());
      if (!Number.isInteger(feeBpsVal) || feeBpsVal < 0 || feeBpsVal >= 10000) {
        setStatus('feeBps must be 0..9999');
        return;
      }
      const result = await createAmmVault({
        tokenA: new TextEncoder().encode(tokenA),
        tokenB: new TextEncoder().encode(tokenB),
        reserveA: reserveAVal,
        reserveB: reserveBVal,
        feeBps: feeBpsVal,
        policyDigest: policyAnchorBytes,
      });
      if (result.success && result.vaultIdBase32) {
        setLastVaultIdB32(result.vaultIdBase32);
        setStatus(`Vault created. id=${result.vaultIdBase32}`);
      } else {
        setStatus(`Vault creation failed: ${result.error ?? 'unknown'}`);
      }
    } catch (e: any) {
      setStatus(e?.message || 'Vault creation failed');
    } finally {
      setBusy(false);
    }
  };

  const handlePublishAd = async () => {
    setBusy(true);
    setStatus('');
    try {
      if (!lastVaultIdB32) {
        setStatus('Create the vault first; advertisement needs the vault id');
        return;
      }
      if (!pairOk || !policyAnchorBytes) {
        setStatus('Pair / anchor invalid — cannot publish ad');
        return;
      }
      const vaultIdBytes = new Uint8Array(decodeBase32Crockford(lastVaultIdB32));
      if (vaultIdBytes.length !== 32) {
        setStatus('Decoded vault id is not 32 bytes');
        return;
      }
      // The unlock spec digest is the policy anchor for the AMM
      // policy itself (the curve + fee bps are already inside the
      // FulfillmentMechanism on the vault; the spec digest is
      // strictly informational on the advertisement).
      const reserveAVal = bigIntFromString(reserveA.trim());
      const reserveBVal = bigIntFromString(reserveB.trim());
      const feeBpsVal = Number(feeBps.trim());

      // Synthetic vault_proto_bytes — chunk #1 hashes them but does
      // not decode at publish time, only at fetch-verify time.  For
      // a dev-tools screen this is a small placeholder; production
      // would carry the full LimboVaultProto.
      const vaultProtoPlaceholder = new TextEncoder().encode(
        `dev-amm-vault-${lastVaultIdB32}`,
      );
      const ownerPlaceholder = new Uint8Array(64);
      // Owner pk is stamped at the routing-vault advertisement layer
      // by the publishing device's wallet.  Placeholder zeros are
      // safe here because the chunk-#1 advertisement does not
      // signature-verify the owner pk; chunk #5 / chunk #7 verify
      // RouteCommits separately.

      const result = await publishRoutingAdvertisement({
        vaultId: vaultIdBytes,
        tokenA: new TextEncoder().encode(tokenA),
        tokenB: new TextEncoder().encode(tokenB),
        reserveA: reserveAVal,
        reserveB: reserveBVal,
        feeBps: feeBpsVal,
        unlockSpecDigest: policyAnchorBytes,
        unlockSpecKey: 'defi/spec/dev-amm',
        ownerPublicKey: ownerPlaceholder,
        vaultProtoBytes: vaultProtoPlaceholder,
      });
      if (result.success) {
        setStatus(`Advertisement published. vaultId=${result.vaultIdBase32}`);
      } else {
        setStatus(`Publish failed: ${result.error ?? 'unknown'}`);
      }
    } catch (e: any) {
      setStatus(e?.message || 'Publish failed');
    } finally {
      setBusy(false);
    }
  };

  const navActions = useMemo(
    () => [() => void handleCreate(), () => void handlePublishAd()],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [tokenA, tokenB, reserveA, reserveB, feeBps, policyAnchor, lastVaultIdB32],
  );
  useDpadNav({ actions: navActions });

  return (
    <div className="settings-screen">
      <h1>AMM Vault (Dev)</h1>
      <p className="settings-subtitle">
        Create a constant-product vault and publish its routing
        advertisement.  All crypto runs in Rust.
      </p>

      <section style={{ marginBottom: 16 }}>
        <h2>Pair</h2>
        <label>
          token_a (lex-lower)
          <input
            type="text"
            value={tokenA}
            onChange={(e) => setTokenA(e.target.value)}
            disabled={busy}
            style={{ width: '100%' }}
          />
        </label>
        <label>
          token_b (lex-higher)
          <input
            type="text"
            value={tokenB}
            onChange={(e) => setTokenB(e.target.value)}
            disabled={busy}
            style={{ width: '100%' }}
          />
        </label>
        {!pairOk && (
          <p style={{ color: '#cc4444', fontSize: 12 }}>
            Pair must be non-empty and tokenA must be lex-lower than tokenB.
          </p>
        )}
      </section>

      <section style={{ marginBottom: 16 }}>
        <h2>Reserves + Fee</h2>
        <label>
          reserve_a
          <input
            type="text"
            inputMode="numeric"
            value={reserveA}
            onChange={(e) => setReserveA(e.target.value)}
            disabled={busy}
            style={{ width: '100%' }}
          />
        </label>
        <label>
          reserve_b
          <input
            type="text"
            inputMode="numeric"
            value={reserveB}
            onChange={(e) => setReserveB(e.target.value)}
            disabled={busy}
            style={{ width: '100%' }}
          />
        </label>
        <label>
          fee (basis points; 30 = 0.30%)
          <input
            type="text"
            inputMode="numeric"
            value={feeBps}
            onChange={(e) => setFeeBps(e.target.value)}
            disabled={busy}
            style={{ width: '100%' }}
          />
        </label>
      </section>

      <section style={{ marginBottom: 16 }}>
        <h2>Policy anchor</h2>
        <p style={{ fontSize: 12, color: '#666' }}>
          32-byte CPTA anchor as Base32 Crockford.  Use the policy that
          governs balance accounting for the trade legs.  Paste from
          your published policy id.
        </p>
        <input
          type="text"
          value={policyAnchor}
          onChange={(e) => setPolicyAnchor(e.target.value)}
          disabled={busy}
          placeholder="Base32 Crockford..."
          style={{ width: '100%', fontFamily: 'monospace', fontSize: 11 }}
        />
        {policyAnchor.trim().length > 0 && policyAnchorBytes === null && (
          <p style={{ color: '#cc4444', fontSize: 12 }}>
            Anchor must decode to exactly 32 bytes Base32 Crockford.
          </p>
        )}
      </section>

      <section style={{ marginBottom: 16 }}>
        <button
          type="button"
          onClick={handleCreate}
          disabled={busy || !pairOk || !policyAnchorBytes}
        >
          {busy ? 'Creating…' : 'Create AMM vault'}
        </button>{' '}
        <button
          type="button"
          onClick={handlePublishAd}
          disabled={busy || !lastVaultIdB32}
        >
          {busy ? 'Publishing…' : 'Publish routing ad'}
        </button>
      </section>

      {lastVaultIdB32 && (
        <section style={{ marginBottom: 16 }}>
          <h2>Last vault</h2>
          <code style={{ fontSize: 11, wordBreak: 'break-all' }}>
            {lastVaultIdB32}
          </code>
        </section>
      )}

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

// `bytesEqual` may be useful for follow-up screens that compare anchor
// values; export to keep tree-shake from removing the helper.
export const __helpers = { bytesEqual };
