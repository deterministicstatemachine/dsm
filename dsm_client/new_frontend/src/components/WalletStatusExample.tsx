/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
import React, { useEffect, useMemo, useState } from 'react';
import { dsmClient } from '../services/dsmClient';

type DeviceSeen = { deviceId: string; rssi?: number; lastSeenMs?: number };

function shortTextId(id?: string | null): string {
  const s = String(id || '').trim();
  if (!s) return '';
  return s.slice(0, 8);
}

export const WalletStatusExample: React.FC = () => {
  // Identity
  const [network, setNetwork] = useState<string>('');
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [genesisHash, setGenesisHash] = useState<string | null>(null);

  // Balances
  const [balances, setBalances] = useState<
    Array<{ tokenId: string; balance: string; symbol: string; lastUpdated?: number }>
  >([]);

  // Contacts
  const [contacts, setContacts] = useState<Array<{ alias: string; deviceId: string; genesisHash: string }>>([]);

  // BLE
  const [bleEnabled, setBleEnabled] = useState<boolean>(false);
  const [bleState, setBleState] = useState<'OFF' | 'ON' | 'SCANNING' | 'ADVERTISING' | 'CONNECTED' | 'IDLE'>('OFF');
  const [devices, setDevices] = useState<DeviceSeen[]>([]);

  // Loading flags
  const [loading, setLoading] = useState<{ id: boolean; bal: boolean; cts: boolean; ble: boolean }>({
    id: false, bal: false, cts: false, ble: false,
  });

  // ---------- Loaders ----------
  const loadIdentity = async () => {
    setLoading((s) => ({ ...s, id: true }));
    try {
      const id = await dsmClient.getIdentity();
      setNetwork('');
      setDeviceId(id?.deviceId || null);
      setGenesisHash(id?.genesisHash || null);
    } catch (e) {
      console.warn('Identity load failed:', e);
    } finally {
      setLoading((s) => ({ ...s, id: false }));
    }
  };

  const loadBalances = async () => {
    setLoading((s) => ({ ...s, bal: true }));
    try {
      const list = await dsmClient.getAllBalances();
      setBalances(list);
    } catch (e) {
      console.warn('Balances load failed:', e);
    } finally {
      setLoading((s) => ({ ...s, bal: false }));
    }
  };

  const loadContacts = async () => {
    setLoading((s) => ({ ...s, cts: true }));
    try {
      const res = await dsmClient.getContacts();
      setContacts((res.contacts ?? []).map((c: any) => ({
        alias: String(c.alias ?? ''),
        deviceId: typeof c.deviceId === 'string' ? c.deviceId : Array.from(c.deviceId ?? []).map((b: any) => b.toString(16).padStart(2, '0')).join(''),
        genesisHash: typeof c.genesisHash === 'string' ? c.genesisHash : Array.from(c.genesisHash ?? []).map((b: any) => b.toString(16).padStart(2, '0')).join(''),
      })));
    } catch (e) {
      console.warn('Contacts load failed:', e);
    } finally {
      setLoading((s) => ({ ...s, cts: false }));
    }
  };

  const loadBleStatus = async () => {
    setLoading((s) => ({ ...s, ble: true }));
    try {
      const st = await dsmClient.getBluetoothStatus();
      setBleEnabled(!!st?.enabled);
      setBleState(st?.enabled ? 'ON' : 'OFF');
    } catch (e) {
      console.warn('BLE status fetch failed:', e);
    } finally {
      setLoading((s) => ({ ...s, ble: false }));
    }
  };

  const refreshAll = async () => {
    await Promise.all([loadIdentity(), loadBalances(), loadContacts(), loadBleStatus()]);
  };

  // ---------- BLE event bus ----------
  useEffect(() => {
    const unsub = dsmClient.subscribeBleEvents((detail) => {
      // detail.state may be: scanning | advertising | enabled | disabled | idle | connected | disconnected | device | device_lost | error
      const state = String(detail.state || '').toLowerCase();
      switch (state) {
        case 'scanning': setBleEnabled(true); setBleState('SCANNING'); break;
        case 'advertising': setBleEnabled(true); setBleState('ADVERTISING'); break;
        case 'enabled': setBleEnabled(true); setBleState('ON'); break;
        case 'idle': setBleEnabled(true); setBleState('IDLE'); break;
        case 'disabled': setBleEnabled(false); setBleState('OFF'); break;
        case 'connected': setBleEnabled(true); setBleState('CONNECTED'); break;
        case 'disconnected': setBleEnabled(true); setBleState('ON'); break;
        case 'device': {
          const id = String(detail.deviceId || '');
          if (!id) break;
          setDevices((curr) => {
            const idx = curr.findIndex((d) => d.deviceId === id);
            const upd: DeviceSeen = {
              deviceId: id,
              rssi: typeof detail.rssi === 'number' ? detail.rssi : curr[idx]?.rssi,
              lastSeenMs: typeof detail.lastSeenMs === 'number' ? detail.lastSeenMs : 0,
            };
            if (idx === -1) return [...curr, upd];
            const next = curr.slice(); next[idx] = { ...next[idx], ...upd }; return next;
          });
          break;
        }
        case 'device_lost': {
          const id = String(detail.deviceId || '');
          if (!id) break;
          setDevices((curr) => curr.filter((d) => d.deviceId !== id));
          break;
        }
        default:
          // ignore noisy errors; UI is best-effort
          break;
      }
    });
    return () => { try { unsub(); } catch {} };
  }, []);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { refreshAll(); }, []);

  // ---------- Derived ----------
  const shortDeviceId = useMemo(() => shortTextId(deviceId), [deviceId]);
  const shortGenesis = useMemo(() => shortTextId(genesisHash), [genesisHash]);

  // ---------- UI ----------
  return (
    <div style={{ padding: 16, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace' }}>
      <h2 style={{ margin: 0, marginBottom: 12 }}>DSM Wallet Status</h2>
      <button
        onClick={refreshAll}
        style={{ fontSize: 12, padding: '6px 10px', marginBottom: 16, cursor: 'pointer' }}
        disabled={loading.id || loading.bal || loading.cts || loading.ble}
      >
        {loading.id || loading.bal || loading.cts || loading.ble ? 'Refreshing…' : 'Refresh'}
      </button>

      {/* Identity */}
      <section style={{ border: '1px solid #ddd', borderRadius: 6, padding: 12, marginBottom: 12 }}>
        <div style={{ fontWeight: 700, marginBottom: 8 }}>Identity {loading.id && '(loading)'}</div>
        <div>Network: <strong>{network || '—'}</strong></div>
        <div>Device ID: <code>{shortDeviceId || '—'}</code></div>
        <div>Genesis: <code>{shortGenesis || '—'}</code></div>
      </section>

      {/* Balances */}
      <section style={{ border: '1px solid #ddd', borderRadius: 6, padding: 12, marginBottom: 12 }}>
        <div style={{ fontWeight: 700, marginBottom: 8 }}>Balances {loading.bal && '(loading)'}</div>
        {balances.length === 0 ? (
          <div style={{ opacity: 0.7 }}>No balances yet.</div>
        ) : (
          <ul style={{ margin: 0, paddingLeft: 16 }}>
            {balances.map((b, i) => (
              <li key={`${b.tokenId}:${i}`}>
                {b.symbol || b.tokenId}: <strong>{b.balance}</strong>
                {typeof b.lastUpdated === 'number' && (
                  <span style={{ opacity: 0.6, marginLeft: 6 }}>
                    (t={b.lastUpdated})
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Contacts */}
      <section style={{ border: '1px solid #ddd', borderRadius: 6, padding: 12, marginBottom: 12 }}>
        <div style={{ fontWeight: 700, marginBottom: 8 }}>Contacts {loading.cts && '(loading)'}</div>
        <div>Total: <strong>{contacts.length}</strong></div>
        {contacts.length > 0 && (
          <ul style={{ margin: '6px 0 0', paddingLeft: 16, maxHeight: 120, overflowY: 'auto' }}>
            {contacts.map((c, i) => (
              <li key={`${c.alias}:${i}`}>
                {c.alias} — dev:{' '}
                <code>{shortTextId(c.deviceId)}</code> — gen:{' '}
                <code>{shortTextId(c.genesisHash)}</code>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Bluetooth */}
      <section style={{ border: '1px solid #ddd', borderRadius: 6, padding: 12 }}>
        <div style={{ fontWeight: 700, marginBottom: 8 }}>Bluetooth {loading.ble && '(loading)'}</div>
        <div>Enabled: <strong>{bleEnabled ? 'Yes' : 'No'}</strong></div>
        <div>State: <strong>{bleState}</strong></div>
        <div style={{ marginTop: 8 }}>Discovered devices: <strong>{devices.length}</strong></div>
        {devices.length > 0 && (
          <ul style={{ margin: '6px 0 0', paddingLeft: 16, maxHeight: 140, overflowY: 'auto' }}>
            {devices.map((d) => (
              <li key={d.deviceId}>
                {d.deviceId.slice(0, 8)}… — RSSI: {typeof d.rssi === 'number' ? d.rssi : '—'}
                {d.lastSeenMs ? <span style={{ opacity: 0.6 }}> — tick {String(d.lastSeenMs)}</span> : null}
              </li>
            ))}
          </ul>
        )}
        <div style={{ opacity: 0.65, marginTop: 8, fontSize: 12 }}>
          Note: scanning/advertising are controlled by the native service; this panel is read-only.
        </div>
      </section>
    </div>
  );
};

export default WalletStatusExample;