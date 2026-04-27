/* eslint-disable @typescript-eslint/no-explicit-any, no-console */
// SPDX-License-Identifier: Apache-2.0
// path: src/components/screens/DevPostedSendScreen.tsx
//
// Posted-mode DLV sender — typed UI for creating a posted DLV
// addressed to a specific recipient Kyber pk.  Closes the
// sender-side gap that the inbox screen left open.
//
// Per the architecture rules, this screen carries ZERO protocol
// logic.  All crypto runs in Rust: the empty `creatorPublicKey` +
// `signature` fields ride to `dlv.create` which stamps the wallet
// pk + signs Rust-side (Track C.4 accept-or-stamp pattern).

import React, { useState, useMemo } from 'react';
import { useDpadNav } from '../../hooks/useDpadNav';
import { createPostedDlv } from '../../dsm/dlv';
import { decodeBase32Crockford } from '../../utils/textId';
import './SettingsScreen.css';

const DEFAULT_TOKEN_ID = '';
const DEFAULT_AMOUNT = '0';
const DEFAULT_CONTENT = 'Posted DLV from dev tools';

function bigIntFromString(s: string): bigint {
  if (!/^[0-9]+$/.test(s)) throw new Error('must be a non-negative integer');
  return BigInt(s);
}

export default function DevPostedSendScreen(): JSX.Element {
  const [recipientPkBase32, setRecipientPkBase32] = useState('');
  const [policyAnchor, setPolicyAnchor] = useState('');
  const [tokenId, setTokenId] = useState(DEFAULT_TOKEN_ID);
  const [lockedAmount, setLockedAmount] = useState(DEFAULT_AMOUNT);
  const [content, setContent] = useState(DEFAULT_CONTENT);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string>('');

  const recipientPkBytes = useMemo(() => {
    if (!recipientPkBase32.trim()) return null;
    try {
      const decoded = new Uint8Array(decodeBase32Crockford(recipientPkBase32.trim()));
      if (decoded.length === 0) return null;
      return decoded;
    } catch {
      return null;
    }
  }, [recipientPkBase32]);

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

  const handleSend = async () => {
    setBusy(true);
    setStatus('');
    try {
      if (!recipientPkBytes) {
        setStatus('Recipient Kyber pk must be a non-empty Base32 Crockford string');
        return;
      }
      if (!policyAnchorBytes) {
        setStatus('Policy anchor must decode to exactly 32 bytes Base32 Crockford');
        return;
      }
      let lockedAmountValue: bigint;
      try {
        lockedAmountValue = bigIntFromString(lockedAmount.trim());
      } catch (e: any) {
        setStatus(`lockedAmount: ${e?.message ?? 'invalid'}`);
        return;
      }

      const result = await createPostedDlv({
        recipientKyberPk: recipientPkBytes,
        policyDigest: policyAnchorBytes,
        tokenId: tokenId.trim() || undefined,
        lockedAmount: lockedAmountValue,
        content: new TextEncoder().encode(content),
      });
      if (result.success && result.id) {
        setStatus(`Posted DLV created. id=${result.id}`);
      } else {
        setStatus(`Send failed: ${result.error ?? 'unknown'}`);
      }
    } catch (e: any) {
      setStatus(e?.message || 'Send failed');
    } finally {
      setBusy(false);
    }
  };

  const navActions = useMemo(
    () => [() => void handleSend()],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [recipientPkBase32, policyAnchor, tokenId, lockedAmount, content],
  );
  useDpadNav({ actions: navActions });

  return (
    <div className="settings-screen">
      <h1>Posted DLV Send (Dev)</h1>
      <p className="settings-subtitle">
        Create a posted-mode DLV addressed to a specific Kyber public
        key.  All crypto runs in Rust.
      </p>

      <section style={{ marginBottom: 16 }}>
        <h2>Recipient</h2>
        <p style={{ fontSize: 12, color: '#666' }}>
          Recipient&apos;s Kyber-1024 public key as Base32 Crockford.  Get
          it from their wallet&apos;s bootstrap output.
        </p>
        <textarea
          value={recipientPkBase32}
          onChange={(e) => setRecipientPkBase32(e.target.value)}
          disabled={busy}
          rows={3}
          placeholder="Base32 Crockford..."
          style={{ width: '100%', fontFamily: 'monospace', fontSize: 11 }}
        />
        {recipientPkBase32.trim().length > 0 && recipientPkBytes === null && (
          <p style={{ color: '#cc4444', fontSize: 12 }}>
            Recipient pk must decode to non-empty bytes.
          </p>
        )}
      </section>

      <section style={{ marginBottom: 16 }}>
        <h2>Policy anchor</h2>
        <p style={{ fontSize: 12, color: '#666' }}>
          32-byte CPTA anchor of the policy governing the locked
          token.  Same field as the AMM owner screen.
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
        <h2>Locked token</h2>
        <label>
          token_id (optional; empty = content-only vault)
          <input
            type="text"
            value={tokenId}
            onChange={(e) => setTokenId(e.target.value)}
            disabled={busy}
            style={{ width: '100%' }}
          />
        </label>
        <label>
          locked amount (u128, big-endian; 0 for none)
          <input
            type="text"
            inputMode="numeric"
            value={lockedAmount}
            onChange={(e) => setLockedAmount(e.target.value)}
            disabled={busy}
            style={{ width: '100%' }}
          />
        </label>
      </section>

      <section style={{ marginBottom: 16 }}>
        <h2>Content</h2>
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          disabled={busy}
          rows={3}
          style={{ width: '100%' }}
        />
      </section>

      <section style={{ marginBottom: 16 }}>
        <button
          type="button"
          onClick={handleSend}
          disabled={busy || !recipientPkBytes || !policyAnchorBytes}
        >
          {busy ? 'Sending…' : 'Send posted DLV'}
        </button>
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
