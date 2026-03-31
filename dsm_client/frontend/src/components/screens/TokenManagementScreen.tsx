/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useEffect, useMemo, useRef, useState } from 'react';
import QRCodeScannerPanel from '../qr/QRCodeScannerPanel';
import EraFaucetScreen from './EraFaucetScreen';
import { importTokenPolicyFromScanData } from '../../services/policy/policyScanService';
import { mapPoliciesToDisplayEntries } from '../../services/policy/policyDisplayService';
import { dsmClient } from '../../services/dsmClient';

// PRODUCTION-ONLY: No placeholders, no localStorage.
// Token creation is handled exclusively via Settings > Policy Tools (DevPolicyScreen).

interface DsmPolicyService {
  listPolicies: () => Promise<unknown>;
}

// Unified display item for both built-in and scanned/imported tokens.
interface TokenDisplayItem {
  key: string;
  label: string;
  ticker?: string;
  alias?: string;
  decimals?: number;
  maxSupply?: string;
  cptaType: string;
  cptaAnchorId: string;
  cptaAnchorFull: string;
  builtIn: boolean;
}

// Protocol-defined built-in tokens — always present regardless of policy service state.
const BUILTIN_TOKENS: TokenDisplayItem[] = [
  {
    key: '__era__',
    label: 'ERA',
    ticker: 'ERA',
    decimals: 2,
    maxSupply: '80,000,000,000',
    cptaType: 'DJTE EMISSION TOKEN',
    cptaAnchorId: 'PROTOCOL-DEFINED',
    cptaAnchorFull:
      'BLAKE3("DSM/cpta\\0" || djte_emission_genesis)\n' +
      'Deterministic Join-Triggered Emission. ERA has an 80 billion total supply and is presented with 2 decimal places.',
    builtIn: true,
  },
  {
    key: '__dbtc__',
    label: 'dBTC',
    ticker: 'dBTC',
    decimals: 8,
    maxSupply: 'Variable — net BTC tapped into DSM',
    cptaType: 'BITCOIN TAP TOKEN',
    cptaAnchorId: 'PROTOCOL-DEFINED',
    cptaAnchorFull:
      'BLAKE3("DSM/cpta\\0" || bitcoin_tap_genesis)\n' +
      'Mint/burn BTC tap asset. dBTC tracks the net BTC tapped into DSM; there is no fixed protocol cap. ' +
      'Fractional exits and possession transfers stay supported.',
    builtIn: true,
  },
];

// Event-driven snackbar: no timers, dismissed on next pointer/ESC.
function useSnackbar() {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState<string>('');
  const teardownRef = useRef<(() => void) | null>(null);

  const hide = () => {
    setOpen(false);
    setMessage('');
    if (teardownRef.current) {
      teardownRef.current();
      teardownRef.current = null;
    }
  };

  const show = (msg: string) => {
    setMessage(msg);
    setOpen(true);
    const onPointer = () => hide();
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') hide(); };
    document.addEventListener('pointerdown', onPointer, { once: true });
    document.addEventListener('keydown', onKey);
    teardownRef.current = () => { document.removeEventListener('keydown', onKey); };
  };

  useEffect(() => () => { if (teardownRef.current) teardownRef.current(); }, []);

  return { open, message, show, hide };
}

function usePolicies(): { policies: unknown; refresh: () => void } {
  const [policies, setPolicies] = useState<unknown>([]);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const svc = (dsmClient as unknown as Partial<DsmPolicyService> | undefined);
        if (!svc || typeof svc.listPolicies !== 'function') {
          if (!cancelled) setPolicies([]);
          return;
        }
        const res = await svc.listPolicies();
        if (!cancelled) setPolicies(res);
      } catch {
        if (!cancelled) setPolicies([]);
      }
    })();
    return () => { cancelled = true; };
  }, [version]);

  return { policies, refresh: () => setVersion(v => v + 1) };
}

// Label + value row used inside the expanded CPTA panel.
function CptaRow({ label, value, mono = false, preWrap = false }: {
  label: string;
  value: string;
  mono?: boolean;
  preWrap?: boolean;
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginBottom: 8 }}>
      <div style={{ fontSize: 9, letterSpacing: '0.08em', color: 'var(--text-dark)', opacity: 0.7 }}>
        {label}
      </div>
      <div
        style={{
          fontSize: 11,
          color: 'var(--text)',
          fontFamily: mono
            ? 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace'
            : undefined,
          whiteSpace: preWrap ? 'pre-wrap' : undefined,
          wordBreak: preWrap ? 'break-word' : undefined,
        }}
      >
        {value}
      </div>
    </div>
  );
}

type Tab = 'list' | 'scan' | 'faucet';

export default function TokenManagementScreen(): JSX.Element | null {
  const { policies, refresh } = usePolicies();
  const snackbar = useSnackbar();
  const [activeTab, setActiveTab] = useState<Tab>('list');
  const [expandedKey, setExpandedKey] = useState<string | null>(null);

  const handleScan = async (data: string) => {
    const res = await importTokenPolicyFromScanData(data);
    if (res.ok) {
      snackbar.show(`Token imported: ${res.shortId || 'OK'}`);
      refresh();
      setActiveTab('list');
      return;
    }
    snackbar.show(`Scan failed: ${res.message || 'Import failed'}`);
  };

  // Map scanned/imported policies to TokenDisplayItems, deduplicating against built-ins.
  const scannedEntries = useMemo((): TokenDisplayItem[] => {
    const raw = mapPoliciesToDisplayEntries(policies);
    return raw
      .filter(e => {
        const t = (e.ticker ?? e.label ?? '').toUpperCase();
        return t !== 'ERA' && t !== 'DBTC';
      })
      .map(e => ({
        key: e.label ? `${e.label}:${e.shortId}` : e.shortId,
        label: e.label,
        ticker: e.ticker,
        alias: e.alias,
        decimals: e.decimals,
        maxSupply: e.maxSupply,
        cptaType: 'CPTA POLICY',
        cptaAnchorId: e.shortId,
        cptaAnchorFull: e.prettyAnchor,
        builtIn: false,
      }));
  }, [policies]);

  // Built-in tokens always appear first.
  const allTokens: TokenDisplayItem[] = [...BUILTIN_TOKENS, ...scannedEntries];

  const toggleExpand = (key: string) => {
    setExpandedKey(prev => (prev === key ? null : key));
  };

  const tabStyle = (tab: Tab): React.CSSProperties => ({
    flex: 1,
    padding: '12px 16px',
    background: 'none',
    border: 'none',
    borderBottom: activeTab === tab ? '2px solid var(--accent)' : '2px solid transparent',
    color: activeTab === tab ? 'var(--text)' : 'var(--text-muted)',
    fontWeight: activeTab === tab ? 600 : 400,
    cursor: 'pointer',
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Tabs Header */}
      <div style={{
        display: 'flex',
        borderBottom: '1px solid var(--border)',
        padding: '0 16px',
        marginBottom: 16,
        background: 'var(--bg-elevated)',
      }}>
        <button onClick={() => setActiveTab('list')} style={tabStyle('list')}>My Tokens</button>
        <button onClick={() => setActiveTab('scan')} style={tabStyle('scan')}>Scan</button>
        <button onClick={() => setActiveTab('faucet')} style={tabStyle('faucet')}>Faucet</button>
      </div>

      <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        {activeTab === 'scan' ? (
          <div style={{ position: 'absolute', inset: 0, zIndex: 10 }}>
            <QRCodeScannerPanel onScan={handleScan} onCancel={() => setActiveTab('list')} />
          </div>
        ) : activeTab === 'faucet' ? (
          <div style={{ height: '100%', overflowY: 'auto', padding: 0 }}>
            <EraFaucetScreen />
          </div>
        ) : (
          <div style={{ padding: '0 16px 16px 16px', overflowY: 'auto', height: '100%' }}>
            <div style={{ display: 'grid', gap: 10 }}>
              {allTokens.map(token => {
                const isExpanded = expandedKey === token.key;
                return (
                  <div
                    key={token.key}
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 6,
                      overflow: 'hidden',
                      background: isExpanded ? 'rgba(var(--text-rgb),0.04)' : 'transparent',
                    }}
                  >
                    {/* Card header — always visible, tap to toggle expand */}
                    <button
                      type="button"
                      onClick={() => toggleExpand(token.key)}
                      style={{
                        width: '100%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '11px 12px',
                        background: 'transparent',
                        border: 'none',
                        cursor: 'pointer',
                        textAlign: 'left',
                        color: 'var(--text)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontWeight: 700, fontSize: 13, letterSpacing: '0.04em' }}>
                          {token.label}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {token.decimals !== undefined && (
                          <span style={{ fontSize: 10, color: 'var(--text-dark)', opacity: 0.7 }}>
                            {token.decimals}dp
                          </span>
                        )}
                        <span style={{ fontSize: 14, color: 'var(--text-dark)' }}>
                          {isExpanded ? '\u25b2' : '\u25bc'}
                        </span>
                      </div>
                    </button>

                    {/* Expanded CPTA detail panel */}
                    {isExpanded && (
                      <div
                        style={{
                          padding: '4px 12px 14px 12px',
                          borderTop: '1px solid var(--border)',
                        }}
                      >
                        <div
                          style={{
                            fontSize: 9,
                            fontWeight: 700,
                            letterSpacing: '0.1em',
                            color: 'var(--text-dark)',
                            marginBottom: 10,
                            marginTop: 8,
                            opacity: 0.6,
                          }}
                        >
                          CPTA INFORMATION
                        </div>

                        {token.ticker && <CptaRow label="TICKER" value={token.ticker} />}
                        {token.alias && <CptaRow label="ALIAS" value={token.alias} />}
                        {token.decimals !== undefined && (
                          <CptaRow label="DECIMALS" value={String(token.decimals)} />
                        )}
                        {token.maxSupply && (
                          <CptaRow label="TOTAL SUPPLY (MAX)" value={token.maxSupply} />
                        )}
                        <CptaRow label="CPTA TYPE" value={token.cptaType} />
                        <CptaRow label="CPTA ANCHOR ID" value={token.cptaAnchorId} mono />
                        <CptaRow
                          label="CPTA ANCHOR"
                          value={token.cptaAnchorFull}
                          mono
                          preWrap
                        />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Screen-local, event-driven snackbar (dismiss on click or ESC). */}
      {snackbar.open && (
        <div
          role="alert"
          aria-live="polite"
          onClick={snackbar.hide}
          style={{
            position: 'absolute',
            left: '50%',
            transform: 'translateX(-50%)',
            bottom: 24,
            background: 'rgba(var(--text-rgb),0.95)',
            color: 'var(--text-bright, #d6ffb3)',
            padding: '10px 14px',
            borderRadius: 8,
            boxShadow: '0 4px 12px rgba(var(--text-rgb),0.3)',
            fontSize: 14,
            zIndex: 3000,
            maxWidth: '90%',
            wordBreak: 'break-word',
            cursor: 'pointer',
          }}
        >
          {snackbar.message}
        </div>
      )}
    </div>
  );
}
