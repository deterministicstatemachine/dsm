/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, security/detect-object-injection, security/detect-unsafe-regex, no-console, react-hooks/exhaustive-deps */
// SPDX-License-Identifier: Apache-2.0
import React, { useState, useMemo } from 'react';
import { dsmClient } from '../../services/dsmClient';
import { computeB0xAddressFromBase32 } from '../../services/dlv/b0xService';
import { useDpadNav } from '../../hooks/useDpadNav';
import './SettingsScreen.css';

export default function DevDlvScreen(): JSX.Element {
  const [lock, setLock] = useState('');
  const [condition, setCondition] = useState('');
  const [status, setStatus] = useState<string>('');
  // Example DLV Create (Base32 Crockford of DlvInstantiateV1 proto bytes).
  // Commit 8 supplies a real example; for now the example slot is empty so
  // the UI compiles against the new contract without embedding a stale
  // legacy blob that would fail to decode.
  const exampleDlvInstantiateBase32 = '';
  const [contacts, setContacts] = useState<any[]>([]);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [b0x, setB0x] = useState<string>('');
  const [dlvStatus, setDlvStatus] = useState<string>('');

  const handleCreate = async () => {
    setStatus('');
    setDlvStatus('');
    try {
      const out = await dsmClient.createCustomDlv({ lock, condition });
      setStatus(out?.success ? `DLV created: ${out?.id ?? 'ok'}` : `DLV create failed: ${out?.error ?? 'unknown'}`);
    } catch (e: any) {
      setStatus(e?.message || 'DLV create failed');
    }
  };

  const pasteLockFromClipboard = async () => {
    try {
      if (!navigator?.clipboard?.readText) {
        setDlvStatus('Clipboard API unavailable; paste lock manually.');
        return;
      }
      const txt = await navigator.clipboard.readText();
      if (!txt) {
        setDlvStatus('Clipboard empty');
        return;
      }
      setLock(txt.trim());
      setDlvStatus('Pasted DLV create payload');
    } catch (e: any) {
      setDlvStatus(e?.message || 'Clipboard read failed');
    }
  };

  const pasteConditionFromClipboard = async () => {
    try {
      if (!navigator?.clipboard?.readText) {
        setDlvStatus('Clipboard API unavailable; paste condition manually.');
        return;
      }
      const txt = await navigator.clipboard.readText();
      if (!txt) {
        setDlvStatus('Clipboard empty');
        return;
      }
      setCondition(txt.trim());
      setDlvStatus('Pasted DLV unlock/condition payload');
    } catch (e: any) {
      setDlvStatus(e?.message || 'Clipboard read failed');
    }
  };

  const handleLoadContacts = async () => {
    setStatus('');
    setB0x('');
    try {
      const resp = await dsmClient.getContacts();
      setContacts(resp.contacts || []);
      setStatus(`Loaded ${resp.contacts.length} contacts`);
    } catch (e: any) {
      setStatus(`Failed to load contacts: ${e?.message || String(e)}`);
    }
  };

  const handleComputeB0x = async () => {
    setB0x('');
    if (selectedIdx === null) { setStatus('Select a contact first'); return; }
    const c = contacts[selectedIdx];
    if (!c) { setStatus('Invalid contact'); return; }
    try {
      const addr = computeB0xAddressFromBase32({
        genesisHashB32: c.genesisHash || '',
        deviceIdB32: c.deviceId || '',
        chainTipB32: c.chainTip || '',
      });
      setB0x(addr || '');
      setStatus(addr ? 'Computed b0x' : 'computeB0xAddressBridge returned empty');
    } catch (e: any) {
      setStatus(`computeB0x failed: ${e?.message || String(e)}`);
    }
  };


  // --- D-pad navigation ---
  // Items: Load Contacts (0), Compute b0x (1), Create DLV (2), Load Example (3), Paste Create (4), Paste Unlock (5)
  const navActions = useMemo(() => [
    () => void handleLoadContacts(),
    () => void handleComputeB0x(),
    () => void handleCreate(),
    () => setLock(exampleDlvInstantiateBase32),
    () => void pasteLockFromClipboard(),
    () => void pasteConditionFromClipboard(),
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [selectedIdx, lock, condition]);

  const { focusedIndex } = useDpadNav({
    itemCount: navActions.length,
    onSelect: (idx) => navActions[idx]?.(),
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');

  return (
    <div className="settings-shell settings-shell--dev">
      <div className="settings-shell__title">DLV Tools</div>
      <div className="settings-shell__stack">
        <div style={{ fontSize: 10, lineHeight: 1.4, color: 'var(--text-dark)', display: 'grid', gap: 4 }}>
          <div>
            Paste Base32 (Crockford) encodings of the binary DLV lifecycle protos. No JSON/YAML, no hex/base64. Invalid payloads will fail with a clear error.
          </div>
          <div style={{ display: 'grid', gap: 2, marginLeft: 8 }}>
            <div><strong>DLV Create (<code>DlvInstantiateV1</code>)</strong></div>
            <div>1) <code>spec.policy_digest</code>: 32-byte CPTA policy anchor.</div>
            <div>2) <code>spec.content_digest</code>: 32-byte H(&quot;DSM/dlv-content&quot;, content).</div>
            <div>3) <code>spec.fulfillment_digest</code>: 32-byte H(&quot;DSM/dlv-fulfillment&quot;, fulfillment_bytes).</div>
            <div>4) <code>spec.intended_recipient</code>: optional Kyber pk (empty = self-encrypted).</div>
            <div>5) <code>spec.fulfillment_bytes</code>: canonical FulfillmentMechanism proto.</div>
            <div>6) <code>spec.content</code>: plaintext for local; sender-encrypted for posted.</div>
            <div>7) <code>creator_public_key</code>: SPHINCS+ pk.</div>
            <div>8) <code>token_id</code>: optional (empty = content-only vault).</div>
            <div>9) <code>locked_amount_u128</code>: 16-byte big-endian u128 (all-zeros if no lock).</div>
            <div>10) <code>signature</code>: SPHINCS+ over canonical Operation::DlvCreate bytes.</div>
            <div>Then serialize the proto (<code>proto/dsm_app.proto</code>) → Base32 Crockford.</div>
            <div>Optional unlock payload: use <code>DlvOpenV3</code> (device_id, vault_id, reveal_material) as Base32 if your flow posts an unlock proof.</div>
          </div>
        </div>
        <button className={`settings-shell__button${fc(0)}`} onClick={() => void handleLoadContacts()} style={{ fontSize: '9px' }}>Load Contacts</button>
        <div>
          <select className="settings-input" style={{ width: '100%', padding: 6, background: 'var(--bg)', color: 'var(--text-dark)', border: '2px solid var(--border)', borderRadius: '4px', outline: 'none' }} value={selectedIdx ?? ''} onChange={(e) => setSelectedIdx(e.target.value === '' ? null : Number(e.target.value))}>
            <option value="">-- select contact --</option>
            {contacts.map((c, i) => (
              <option key={i} value={i}>{c.alias || `contact ${i}`}</option>
            ))}
          </select>
        </div>
        <div className="settings-shell__info" style={{ fontSize: 11 }}>
          {selectedIdx !== null && contacts[selectedIdx] ? (
            <div>
              <div><b>Alias:</b> {contacts[selectedIdx].alias}</div>
              <div><b>DeviceId:</b> {contacts[selectedIdx].deviceId}</div>
              <div><b>Genesis:</b> {contacts[selectedIdx].genesisHash}</div>
              <div><b>ChainTip:</b> {contacts[selectedIdx].chainTip || 'none'}</div>
            </div>
          ) : <div style={{ opacity: 0.7 }}>No contact selected</div>}
        </div>
        <div className="settings-shell__button-row">
          <button className={`settings-shell__button${fc(1)}`} onClick={() => void handleComputeB0x()} style={{ fontSize: '9px' }}>Compute b0x</button>
        </div>
        {b0x && <div className="settings-shell__status"><b>b0x:</b> {b0x}</div>}
      </div>
      <div className="settings-shell__panel">
        <label style={{ fontSize: 10 }}>
          DLV Create (Base32 Crockford of <code>DlvInstantiateV1</code> bytes)
          <textarea className="settings-input" value={lock} onChange={e => setLock(e.target.value)} rows={4} style={{ width: '100%', padding: 6, fontFamily: 'monospace', fontSize: 10, background: 'var(--bg)', color: 'var(--text-dark)', border: '2px solid var(--border)', borderRadius: '4px', outline: 'none' }} />
        </label>
        <label style={{ fontSize: 10 }}>
          Unlock / Condition Payload (optional) — Base32 of <code>DlvOpenV3</code> or proof bytes
          <textarea className="settings-input" value={condition} onChange={e => setCondition(e.target.value)} rows={3} style={{ width: '100%', padding: 6, fontFamily: 'monospace', fontSize: 10, background: 'var(--bg)', color: 'var(--text-dark)', border: '2px solid var(--border)', borderRadius: '4px', outline: 'none' }} />
        </label>
        <div className="settings-shell__button-row">
          <button className={`settings-shell__button${fc(2)}`} onClick={() => void handleCreate()} style={{ fontSize: '9px' }}>Create DLV</button>
          <button className={`settings-shell__button${fc(3)}`} onClick={() => setLock(exampleDlvInstantiateBase32)} style={{ fontSize: '9px', background: 'var(--bg-secondary)', color: 'var(--text-dark)' }}>Load Example DLV Create</button>
          <button className={`settings-shell__button${fc(4)}`} onClick={() => void pasteLockFromClipboard()} style={{ fontSize: '9px', background: 'var(--bg-secondary)', color: 'var(--text-dark)' }}>Paste Create from Clipboard</button>
          <button className={`settings-shell__button${fc(5)}`} onClick={() => void pasteConditionFromClipboard()} style={{ fontSize: '9px', background: 'var(--bg-secondary)', color: 'var(--text-dark)' }}>Paste Unlock from Clipboard</button>
        </div>
        <div className="settings-shell__info">
          <div style={{ fontWeight: 'bold', marginBottom: 4 }}>Example DlvInstantiateV1 (Base32)</div>
          <div className="settings-shell__mono">{exampleDlvInstantiateBase32 || '(example pending commit 8)'}</div>
          <div style={{ marginTop: 4 }}>
            Example blob pending commit 8 — will carry a valid DlvInstantiateV1 with a zero-locked content-only vault for local-mode testing.
          </div>
        </div>
        {(status || dlvStatus) && <div className="settings-shell__status">{status || dlvStatus}</div>}
      </div>
      <div className="settings-shell__hint">Press B to go back</div>
    </div>
  );
}
