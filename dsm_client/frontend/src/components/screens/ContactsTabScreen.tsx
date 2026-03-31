/* SPDX-License-Identifier: Apache-2.0 */
/* eslint-disable no-console */
// Tabbed contacts interface with "My Contacts" and "Add Contact"
const CONTACTS_DEBUG = false; // flip to true for on-device BLE/contacts debugging
import React, { useCallback, useEffect, useState, useRef, useMemo } from 'react';
import SatelliteIcon from '../icons/SatelliteIcon';
import ArrowIcon from '../icons/ArrowIcon';
import QRCodeScannerPanel from '../qr/QRCodeScannerPanel';
import MyContactInfoPanel from '../contacts/MyContactInfoPanel';
import { useContacts } from '../../contexts/ContactsContext';
import { useTransactions } from '../../hooks/useTransactions';
import { startPairingAll, stopPairingAll } from '../../dsm/WebViewBridge';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import StitchedReceiptDetails from '../receipts/StitchedReceiptDetails';
import { formatSignedTokenAmount } from '../../utils/tokenMeta';
import { useDpadNav } from '../../hooks/useDpadNav';

interface Props { onNavigate?: (screen: string) => void; eraTokenSrc?: string }

type Tab = 'list' | 'add' | 'myqr';

// Loading overlay with the era token GIF - covers entire tab content
const LoadingOverlay: React.FC<{ message?: string; eraTokenSrc?: string }> = ({ message = 'Loading...', eraTokenSrc = 'images/logos/era_token_gb.gif' }) => (
  <div style={{
    position: 'absolute',
    inset: 0,
    background: 'rgba(var(--text-dark-rgb), 0.92)',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 100,
    borderRadius: 8,
  }}>
    <img 
      src={eraTokenSrc}
      alt="Loading" 
      style={{ width: 64, height: 64, marginBottom: 12, imageRendering: 'pixelated' }} 
    />
    <div style={{
      fontSize: 10,
      fontFamily: "'Press Start 2P', monospace",
      letterSpacing: '1px',
      color: 'var(--text)',
      textTransform: 'uppercase',
    }}>
      {message}
    </div>
  </div>
);


const TAB_STORAGE_KEY = 'dsm_contacts_active_tab';

const ContactsTabScreen: React.FC<Props> = ({ eraTokenSrc = 'images/logos/era_token_gb.gif' }) => {
  const [activeTab, setActiveTab] = useState<Tab>(() => {
    try {
      const saved = localStorage.getItem(TAB_STORAGE_KEY);
      if (saved === 'list' || saved === 'add' || saved === 'myqr') return saved;
    } catch {}
    return 'list';
  });
  const { contacts, refreshContacts, isLoading: contextLoading } = useContacts();
  const { transactions, refresh: refreshTransactions } = useTransactions();
  const [selected, setSelected] = useState<number | null>(null);
  const [error] = useState<string | null>(null);
  const [loadingMessage] = useState('Loading contacts...');
  
  // BLE discovery status: tracks real connection progress
  type BleStatus = 'idle' | 'scanning' | 'found' | 'connected' | 'paired';
  const [bleStatus, setBleStatus] = useState<BleStatus>('idle');


  // Debounce ref to prevent rapid refresh calls
  const refreshPendingRef = useRef(false);

  // Debounced load function - prevents rapid-fire refreshes
  const load = useCallback(async (reason?: string) => {
    if (CONTACTS_DEBUG) console.log('[ContactsTab] Refreshing contacts:', reason || 'manual');
    await refreshContacts();
  }, [refreshContacts]);

  // Load contacts on mount
  useEffect(() => { void load('mount'); }, [load]);
  
  // Load when switching to ANY tab - ensures pairing checks have fresh contact data
  useEffect(() => {
    if (CONTACTS_DEBUG) console.log('[ContactsTab] Tab switched to:', activeTab);
    // Optimization: Do not flood reload when switching to QR screens (myqr/add)
    // This prevents BridgeGate congestion when generating the QR code.
    if (activeTab === 'list') {
      void load('tab-switch');
      void refreshTransactions();
    }
    try {
      localStorage.setItem(TAB_STORAGE_KEY, activeTab);
    } catch {}
  }, [activeTab, load, refreshTransactions]);

  // Periodic refresh to catch backend updates (e.g., BLE pairing completion)
  useEffect(() => {
    const interval = setInterval(() => {
      void load('periodic');
    }, 5000);
    return () => clearInterval(interval);
  }, [load]);

  const detailRowStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '62px 1fr',
    gap: 4,
    alignItems: 'start',
    fontSize: 7,
    wordBreak: 'break-all',
    overflowWrap: 'anywhere',
  };

  const detailLabelStyle: React.CSSProperties = {
    color: 'var(--text-dark)',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    flexShrink: 0,
  };

  // Listen for contact-added events - refresh and auto-switch to list.
  // No loading overlay — the refresh is near-instant and the overlay
  // just causes a visible flicker.
  useEffect(() => {
    const handleContactAdded = (_e: Event) => {
      if (CONTACTS_DEBUG) console.log('[ContactsTab] dsm-contact-added event received');

      // Deterministic coalescing: no wall-clock debounce.
      if (refreshPendingRef.current) return;
      refreshPendingRef.current = true;
      queueMicrotask(() => {
        refreshPendingRef.current = false;
        void (async () => {
          await load('contact-added');
          // Auto-switch to list tab to show the new contact
          setActiveTab('list');
        })();
      });
    };

    const offBleMapped = bridgeEvents.on('contact.bleMapped', () => {
      if (CONTACTS_DEBUG) console.log('[ContactsTab] contact.bleMapped event received');
      if (refreshPendingRef.current) return;
      refreshPendingRef.current = true;
      queueMicrotask(() => {
        refreshPendingRef.current = false;
        void load('ble-mapped');
      });
    });

    const offBleUpdated = bridgeEvents.on('contact.bleUpdated', () => {
      if (CONTACTS_DEBUG) console.log('[ContactsTab] contact.bleUpdated event received');
      if (refreshPendingRef.current) return;
      refreshPendingRef.current = true;
      queueMicrotask(() => {
        refreshPendingRef.current = false;
        void load('ble-updated');
      });
    });

    const offContactAdded = bridgeEvents.on('contact.added', () => {
      handleContactAdded(new Event('contact.added'));
    });

    return () => {
      offBleMapped();
      offBleUpdated();
      offContactAdded();
    };
  }, [load]);

  // Reactive BLE status: driven by actual BLE events, not timers.
  // scanning → found → connected → paired → idle
  useEffect(() => {
    const hasUnpairedContacts = contacts.some(c => !c.bleAddress && c.deviceId);
    if (!hasUnpairedContacts) {
      // All contacts paired or none have deviceId — go idle (skip if already paired/idle)
      if (bleStatus !== 'idle') {
        setBleStatus('idle');
      }
      return;
    }
    // We have unpaired contacts — start at "scanning" if idle
    if (bleStatus === 'idle') {
      setBleStatus('scanning');
    }
  }, [contacts, bleStatus]);

  // Listen for BLE lifecycle events to advance status
  useEffect(() => {
    const offFound = bridgeEvents.on('ble.deviceFound', () => {
      setBleStatus(prev => (prev === 'scanning' || prev === 'idle') ? 'found' : prev);
    });
    const offConnected = bridgeEvents.on('ble.deviceConnected', () => {
      setBleStatus(prev => (prev !== 'paired' && prev !== 'idle') ? 'connected' : prev);
    });
    const offMapped = bridgeEvents.on('contact.bleMapped', () => {
      setBleStatus('paired');
    });
    const offScanStarted = bridgeEvents.on('ble.scanStarted', () => {
      setBleStatus(prev => prev === 'idle' ? 'scanning' : prev);
    });
    const offDisconnected = bridgeEvents.on('ble.deviceDisconnected', () => {
      // Regress to scanning if we lost connection before pairing
      setBleStatus(prev => (prev === 'connected' || prev === 'found') ? 'scanning' : prev);
    });
    const offFailed = bridgeEvents.on('ble.connectionFailed', () => {
      setBleStatus(prev => (prev === 'connected' || prev === 'found') ? 'scanning' : prev);
    });

    return () => {
      offFound(); offConnected(); offMapped();
      offScanStarted(); offDisconnected(); offFailed();
    };
  }, []);


  // Rust-driven BLE pairing: trigger when unpaired contacts appear.
  // Track the count of unpaired contacts so we only call startPairingAll when
  // new unpaired contacts are detected (avoids stop/start thrashing on every refresh).
  const prevUnpairedCountRef = useRef(0);
  useEffect(() => {
    const unpairedCount = contacts.filter(c => !c.bleAddress && c.deviceId).length;
    if (unpairedCount > 0 && unpairedCount > prevUnpairedCountRef.current) {
      if (CONTACTS_DEBUG) console.log(`[ContactsTab] ${unpairedCount} unpaired contacts detected, starting pairing orchestrator`);
      void startPairingAll().catch(e =>
        console.warn('[ContactsTab] startPairingAll failed:', e)
      );
    }
    prevUnpairedCountRef.current = unpairedCount;
  }, [contacts]);

  // Stop pairing on unmount
  useEffect(() => {
    return () => {
      void stopPairingAll().catch(() => {});
    };
  }, []);

  // Listen for Rust pairing status events to advance BLE status indicator
  useEffect(() => {
    const offPairingStatus = bridgeEvents.on('ble.pairingStatus', (evt) => {
      if (CONTACTS_DEBUG) console.log('[ContactsTab] ble.pairingStatus:', evt.status, evt.message);
      switch (evt.status) {
        case 'scanning':
          setBleStatus(prev => prev === 'idle' ? 'scanning' : prev);
          break;
        case 'found':
          setBleStatus(prev => (prev === 'scanning' || prev === 'idle') ? 'found' : prev);
          break;
        case 'connected':
          setBleStatus(prev => (prev !== 'paired') ? 'connected' : prev);
          break;
        case 'paired':
          setBleStatus('paired');
          break;
        case 'failed':
        case 'timeout':
          // Regress to scanning to show we're retrying
          setBleStatus(prev => (prev !== 'paired') ? 'scanning' : prev);
          break;
      }
    });
    return () => { offPairingStatus(); };
  }, []);

  // Only show loading overlay on cold start when there are truly no contacts yet.
  // Contact-add refreshes are too fast for an overlay — it just flickers.
  const showLoadingOverlay = contextLoading && contacts.length === 0;

  // --- D-pad navigation ---
  // Items: 3 tab buttons + content items (contact rows on list tab, or scan button if empty)
  const contentItemCount = activeTab === 'list'
    ? (contacts.length > 0 ? contacts.length : 1) // contacts or "Scan QR" button
    : 0; // add/myqr tabs have no navigable items below tabs
  const navItemCount = 3 + contentItemCount;

  const navActions = useMemo(() => {
    const actions: Array<() => void> = [
      () => setActiveTab('list'),
      () => setActiveTab('add'),
      () => setActiveTab('myqr'),
    ];
    if (activeTab === 'list') {
      if (contacts.length > 0) {
        contacts.forEach((_c, i) => {
          actions.push(() => setSelected(selected === i ? null : i));
        });
      } else {
        actions.push(() => setActiveTab('add')); // "Scan QR Code" button
      }
    }
    return actions;
  }, [activeTab, contacts, selected]);

  const { focusedIndex } = useDpadNav({
    itemCount: navItemCount,
    onSelect: (idx) => navActions[idx]?.(),
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');

  return (
    <div className="dsm-content" style={{ padding: 12, position: 'relative', minHeight: 200 }}>
      {/* Loading overlay for contact add/refresh operations */}
      {showLoadingOverlay && <LoadingOverlay message={loadingMessage} eraTokenSrc={eraTokenSrc} />}
      
      {/* Tab navigation */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <button
          className={`wallet-style-button${fc(0)}`}
          onClick={() => setActiveTab('list')}
          style={{
            flex: 1,
            padding: '10px 12px',
            fontSize: 10,
            fontFamily: '\'Martian Mono\', monospace',
            textTransform: 'uppercase',
            background: activeTab === 'list'
              ? 'linear-gradient(0deg, rgba(var(--bg-rgb),0.08), rgba(var(--text-rgb),0.12)), repeating-linear-gradient(45deg, rgba(var(--bg-rgb),0.12) 0px, rgba(var(--bg-rgb),0.12) 2px, transparent 2px, transparent 4px)'
              : 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)',
            color: activeTab === 'list' ? 'var(--text)' : 'var(--text-dark)',
            border: '2px solid var(--border)',
            borderRadius: 8,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
          }}
        >
          My Contacts
        </button>
        <button
          className={`wallet-style-button${fc(1)}`}
          onClick={() => setActiveTab('add')}
          style={{
            flex: 1,
            padding: '10px 12px',
            fontSize: 10,
            fontFamily: '\'Martian Mono\', monospace',
            textTransform: 'uppercase',
            background: activeTab === 'add'
              ? 'linear-gradient(0deg, rgba(var(--bg-rgb),0.08), rgba(var(--text-rgb),0.12)), repeating-linear-gradient(45deg, rgba(var(--bg-rgb),0.12) 0px, rgba(var(--bg-rgb),0.12) 2px, transparent 2px, transparent 4px)'
              : 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)',
            color: activeTab === 'add' ? 'var(--text)' : 'var(--text-dark)',
            border: '2px solid var(--border)',
            borderRadius: 8,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
          }}
        >
          Add Contact
        </button>
        <button
          className={`wallet-style-button${fc(2)}`}
          onClick={() => setActiveTab('myqr')}
          style={{
            flex: 1,
            padding: '10px 12px',
            fontSize: 10,
            fontFamily: '\'Martian Mono\', monospace',
            textTransform: 'uppercase',
            background: activeTab === 'myqr'
              ? 'linear-gradient(0deg, rgba(var(--bg-rgb),0.08), rgba(var(--text-rgb),0.12)), repeating-linear-gradient(45deg, rgba(var(--bg-rgb),0.12) 0px, rgba(var(--bg-rgb),0.12) 2px, transparent 2px, transparent 4px)'
              : 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)',
            color: activeTab === 'myqr' ? 'var(--text)' : 'var(--text-dark)',
            border: '2px solid var(--border)',
            borderRadius: 8,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
          }}
        >
          My QR
        </button>
      </div>

      {/* Tab content */}
      {activeTab === 'list' ? (
        <div style={{ width: '100%' }}>
          {error && (
            <div style={{ 
              fontSize: 10, 
              color: 'var(--text-dark)', 
              border: '1px solid var(--error)', 
              padding: 8, 
              marginBottom: 10,
              borderRadius: 4,
              fontFamily: '\'Martian Mono\', monospace'
            }}>
              {error}
            </div>
          )}
          
          {/* BLE status indicator - reactive to actual BLE events */}
          {bleStatus !== 'idle' && contacts.length > 0 && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              padding: 12,
              marginBottom: 12,
              background: bleStatus === 'paired'
                ? 'rgba(var(--text-dark-rgb), 0.7)'
                : bleStatus === 'connected'
                  ? 'rgba(var(--text-dark-rgb), 0.65)'
                  : 'rgba(var(--text-dark-rgb), 0.6)',
              border: `2px solid ${bleStatus === 'paired' ? 'var(--accent)' : 'var(--border)'}`,
              borderRadius: 8,
              fontFamily: "'Martian Mono', monospace",
              transition: 'background 0.3s, border-color 0.3s',
            }}>
              <img
                src={eraTokenSrc}
                alt="BLE Status"
                style={{ width: 32, height: 32, imageRendering: 'pixelated' }}
              />
              <div>
                <div style={{
                  fontSize: 9,
                  fontFamily: "'Press Start 2P', monospace",
                  letterSpacing: '1px',
                  color: bleStatus === 'paired' ? 'var(--accent)' : 'var(--text)',
                  marginBottom: 4,
                }}>
                  {bleStatus === 'scanning' && 'Scanning for Peers'}
                  {bleStatus === 'found' && 'Peer Found'}
                  {bleStatus === 'connected' && 'Connected'}
                  {bleStatus === 'paired' && 'Paired!'}
                </div>
                <div style={{ fontSize: 9, opacity: 0.8, color: 'var(--text-dark)' }}>
                  {bleStatus === 'scanning' && 'Keep both devices on this screen'}
                  {bleStatus === 'found' && 'Establishing connection...'}
                  {bleStatus === 'connected' && 'Exchanging identity...'}
                  {bleStatus === 'paired' && 'Contact linked successfully'}
                </div>
              </div>
            </div>
          )}
          
          {contacts.length === 0 ? (
            <div style={{ 
              textAlign: 'center', 
              padding: 24, 
              fontSize: 10, 
              border: '1px dashed var(--border)', 
              background: 'var(--bg)', 
              borderRadius: 8,
              fontFamily: '\'Martian Mono\', monospace'
            }}>
              <div style={{ 
                marginBottom: 12, 
                fontSize: 9, 
                fontFamily: '\'Press Start 2P\', monospace',
                letterSpacing: '1px',
                color: 'var(--text-dark)'
              }}>
                No contacts yet
              </div>
              <div style={{ marginBottom: 16, opacity: 0.8, fontSize: 9 }}>
                Scan a contact&#39;s QR code to get started
              </div>
              <button
                className={`wallet-style-button${fc(3)}`}
                style={{
                  fontSize: 10,
                  padding: '10px 16px',
                  fontFamily: '\'Martian Mono\', monospace',
                  textTransform: 'uppercase',
                  background: 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)',
                  color: 'var(--text)',
                  border: '2px solid var(--border)',
                  borderRadius: 8,
                  boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
                }}
                onClick={() => setActiveTab('add')}
              >
                Scan QR Code
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12, width: '100%' }}>
              {contacts.map((c, i) => (
                <div key={c.id || c.alias || `contact-${i}`} style={{ width: '100%' }}>
                  <div
                    className={focusedIndex === i + 3 ? 'dpad-focus-ring' : undefined}
                    onClick={() => setSelected(selected === i ? null : i)}
                    style={{
                      padding: '10px 12px',
                      border: `2px solid ${selected === i ? 'var(--stateboy-screen)' : 'var(--border)'}`,
                      borderRadius: selected === i ? '8px 8px 0 0' : 8,
                      background: selected === i
                        ? 'linear-gradient(0deg, rgba(var(--bg-rgb),0.08), rgba(var(--text-rgb),0.12)), repeating-linear-gradient(45deg, rgba(var(--bg-rgb),0.12) 0px, rgba(var(--bg-rgb),0.12) 2px, transparent 2px, transparent 4px)'
                        : 'linear-gradient(0deg, rgba(var(--text-rgb),0.08), rgba(var(--bg-rgb),0.04)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.10) 0px, rgba(var(--text-rgb),0.10) 2px, transparent 2px, transparent 4px)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
                      fontFamily: '\'Martian Mono\', monospace',
                      width: '100%',
                      boxSizing: 'border-box',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ fontSize: 10, fontWeight: 'bold', color: 'var(--text-dark)' }}>
                        {c.alias}
                      </div>
                      <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        {c.bleAddress && (
                          <SatelliteIcon size={12} color="var(--stateboy-dark)" />
                        )}
                        <ArrowIcon
                          direction={selected === i ? 'down' : 'right'}
                          size={12}
                          color={selected === i ? 'var(--stateboy-dark)' : 'var(--stateboy-gray)'}
                        />
                      </div>
                    </div>
                  </div>

                  {selected === i && (
                    <div style={{
                      padding: '8px 12px',
                      background: 'rgba(var(--text-dark-rgb),0.06)',
                      border: '2px solid var(--border)',
                      borderTop: 'none',
                      borderRadius: '0 0 8px 8px',
                      fontFamily: '\'Martian Mono\', monospace',
                      fontSize: 7,
                      color: 'var(--text-dark)',
                      maxHeight: '200px',
                      overflowY: 'auto',
                      overflowX: 'hidden',
                      wordBreak: 'break-all',
                      width: '100%',
                      boxSizing: 'border-box',
                    }}>
                      <div style={{ marginBottom: 6, fontSize: 8, fontWeight: 'bold' }}>
                        {c.bleAddress ? 'BLE PAIRED' : c.isVerified ? 'VERIFIED' : 'ONLINE'}
                      </div>
                      <div style={{ display: 'grid', gap: 4 }}>
                        <div style={detailRowStyle}>
                          <span style={detailLabelStyle}>Device</span>
                          <span>{c.deviceId ? c.deviceId : '—'}</span>
                        </div>
                        <div style={detailRowStyle}>
                          <span style={detailLabelStyle}>Genesis</span>
                          <span>{c.genesisHash ? c.genesisHash : '—'}</span>
                        </div>
                        <div style={detailRowStyle}>
                          <span style={detailLabelStyle}>Chain tip</span>
                          <span>{c.chainTip ? c.chainTip : '—'}</span>
                        </div>
                        {c.publicKey && (
                          <div style={detailRowStyle}>
                            <span style={detailLabelStyle}>Pub Key</span>
                            <span>{c.publicKey.length > 24 ? `${c.publicKey.slice(0, 12)}...${c.publicKey.slice(-10)}` : c.publicKey}</span>
                          </div>
                        )}
                        <div style={detailRowStyle}>
                          <span style={detailLabelStyle}>Verified</span>
                          <span>{c.isVerified ? 'YES' : 'NO'}</span>
                        </div>
                        {((c.addedCounter !== undefined && c.addedCounter > 0) || (c.verifyCounter !== undefined && c.verifyCounter > 0)) && (
                          <div style={detailRowStyle}>
                            <span style={detailLabelStyle}>Counters</span>
                            <span>Added: {c.addedCounter ?? 0} · Verify: {c.verifyCounter ?? 0}</span>
                          </div>
                        )}
                        {c.chainTipSmtProof && typeof c.chainTipSmtProof?.siblings?.length === 'number' && (
                          <div style={detailRowStyle}>
                            <span style={detailLabelStyle}>SMT proof</span>
                            <span>{c.chainTipSmtProof.siblings.length} siblings</span>
                          </div>
                        )}
                      </div>
                      <div style={{ marginTop: 10 }}>
                        <div style={{ fontSize: 8, textTransform: 'uppercase', marginBottom: 6, fontWeight: 'bold' }}>Stitched receipts</div>
                        {(() => {
                          const contactTxs = transactions.filter((tx) => {
                            const counterparty = tx.counterpartyDeviceId || tx.fromDeviceId || tx.toDeviceId || '';
                            if (counterparty && counterparty === c.deviceId) return true;
                            if (tx.fromDeviceId === c.deviceId || tx.toDeviceId === c.deviceId) return true;
                            if (typeof tx.recipient === 'string' && tx.recipient === c.alias) return true;
                            return false;
                          });

                          if (contactTxs.length === 0) {
                            return <div style={{ opacity: 0.8 }}>No receipts yet</div>;
                          }

                          return (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                              {contactTxs.map((tx, idx) => {
                                const direction = tx.amount < 0n ? 'Sent' : 'Received';
                                const rawTokenId = (tx as { tokenId?: string }).tokenId || 'ERA';
                                const tokenId = rawTokenId.toUpperCase();
                                const amountLabel = `${formatSignedTokenAmount(tx.amount, rawTokenId)} ${tokenId}`;
                                const summary = `#${idx + 1} · ${direction} ${amountLabel}`;
                                return (
                                  <details key={`${tx.txId}-${idx}`}>
                                    <summary style={{ cursor: 'pointer' }}>{summary}</summary>
                                    <div style={{ marginTop: 6 }}>
                                      <div style={detailRowStyle}>
                                        <span style={detailLabelStyle}>Tx ID</span>
                                        <span>{tx.txId}</span>
                                      </div>
                                      {tx.createdAt ? (
                                        <div style={detailRowStyle}>
                                          <span style={detailLabelStyle}>Date</span>
                                          <span>{new Date((tx.createdAt as number) * 1000).toLocaleString()}</span>
                                        </div>
                                      ) : null}
                                      <div style={detailRowStyle}>
                                        <span style={detailLabelStyle}>Type</span>
                                        <span>{tx.txType || tx.type}</span>
                                      </div>
                                      <StitchedReceiptDetails bytes={tx.stitchedReceipt} />
                                    </div>
                                  </details>
                                );
                              })}
                            </div>
                          );
                        })()}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      ) : activeTab === 'add' ? (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            height: '100%',
            width: '100%',
            overflow: 'hidden'
          }}
        >
          <div style={{ flex: 1, minHeight: 0 }}>
            <QRCodeScannerPanel onCancel={() => setActiveTab('list')} />
          </div>
        </div>
      ) : (
        <MyContactInfoPanel />
      )}
    </div>
  );
};

export default ContactsTabScreen;
