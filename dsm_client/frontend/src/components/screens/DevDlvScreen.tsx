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
  // Example DLV Create (Base32 Crockford of DlvCreateV3 proto bytes)
  const exampleDlvCreateBase32 =
    '18G68SBP5NJ6AXK9CDJJTTB40000000000000000000000000000000J41R6YV39CDWJTS39CXJQ6X1DCHJPTVR00000000000000000000006H0E1S6ARVFDNPPJX1DCHJPTVR00000000000000000000000000002483PC5TPRX1DD5J2TS35DNQG000000000000000000000000000000';
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
    () => setLock(exampleDlvCreateBase32),
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
            <div><strong>DLV Create (preferred: <code>DlvCreateV3</code>)</strong></div>
            <div>1) <code>device_id</code>: 32 bytes (your device ID).</div>
            <div>2) <code>policy_digest</code>: 32-byte policy anchor digest (raw bytes, not hex text).</div>
            <div>3) <code>precommit</code>: 32-byte pre-commit hash for the vault branch.</div>
            <div>4) <code>vault_id</code>: 32-byte vault identifier (raw bytes).</div>
            <div>5) <code>parent_digest</code>: optional 32 bytes; leave empty for genesis branch.</div>
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
          DLV Create (Base32 Crockford of <code>DlvCreateV3</code> bytes)
          <textarea className="settings-input" value={lock} onChange={e => setLock(e.target.value)} rows={4} style={{ width: '100%', padding: 6, fontFamily: 'monospace', fontSize: 10, background: 'var(--bg)', color: 'var(--text-dark)', border: '2px solid var(--border)', borderRadius: '4px', outline: 'none' }} />
        </label>
        <label style={{ fontSize: 10 }}>
          Unlock / Condition Payload (optional) — Base32 of <code>DlvOpenV3</code> or proof bytes
          <textarea className="settings-input" value={condition} onChange={e => setCondition(e.target.value)} rows={3} style={{ width: '100%', padding: 6, fontFamily: 'monospace', fontSize: 10, background: 'var(--bg)', color: 'var(--text-dark)', border: '2px solid var(--border)', borderRadius: '4px', outline: 'none' }} />
        </label>
        <div className="settings-shell__button-row">
          <button className={`settings-shell__button${fc(2)}`} onClick={() => void handleCreate()} style={{ fontSize: '9px' }}>Create DLV</button>
          <button className={`settings-shell__button${fc(3)}`} onClick={() => setLock(exampleDlvCreateBase32)} style={{ fontSize: '9px', background: 'var(--bg-secondary)', color: 'var(--text-dark)' }}>Load Example DLV Create</button>
          <button className={`settings-shell__button${fc(4)}`} onClick={() => void pasteLockFromClipboard()} style={{ fontSize: '9px', background: 'var(--bg-secondary)', color: 'var(--text-dark)' }}>Paste Create from Clipboard</button>
          <button className={`settings-shell__button${fc(5)}`} onClick={() => void pasteConditionFromClipboard()} style={{ fontSize: '9px', background: 'var(--bg-secondary)', color: 'var(--text-dark)' }}>Paste Unlock from Clipboard</button>
        </div>
        <div className="settings-shell__info">
          <div style={{ fontWeight: 'bold', marginBottom: 4 }}>Example DlvCreateV3 (Base32)</div>
          <div className="settings-shell__mono">{exampleDlvCreateBase32}</div>
          <div style={{ marginTop: 4 }}>
            Fields: device_id=<code>&quot;dev-device-id&quot;</code> padded to 32 bytes; policy_digest=<code>&quot;policy-digest-demo&quot;</code>; precommit=<code>&quot;precommit-demo&quot;</code>; vault_id=<code>&quot;vault-id-demo&quot;</code>; parent_digest empty.
          </div>
        </div>
        {(status || dlvStatus) && <div className="settings-shell__status">{status || dlvStatus}</div>}
      </div>
      <div className="settings-shell__hint">Press B to go back</div>
    </div>
  );
}
