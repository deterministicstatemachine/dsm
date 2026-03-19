/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, security/detect-object-injection, security/detect-unsafe-regex, no-console, react-hooks/exhaustive-deps */
// SPDX-License-Identifier: Apache-2.0
// AccountsScreen — Tabbed Tokens & Faucet view

import React, { useEffect, useMemo, useState, useCallback } from 'react';
import LoadingSpinner from '../common/LoadingSpinner';
import { dsmClient } from '../../services/dsmClient';
import { useWallet } from '../../contexts/WalletContext';
import { formatBtc, getDbtcBalance } from '../../services/bitcoinTap';
import { useDpadNav } from '../../hooks/useDpadNav';

type TokenSymbol = 'ERA' | string;
type Tab = 'tokens' | 'faucet';

export interface TokenBalance {
  tokenId: string;
  balance: string;        // human-readable (already scaled by backend)
  symbol: TokenSymbol;
  lastUpdated?: number;   // optional, backend-provided; not used for logic
}

const ATOMIC_DECIMALS_DEFAULT = 8; // used only if backend returns atomic amounts

interface CptaInfo {
  cptaType: string;
  anchorId: string;
  anchor: string;
  maxSupply: string;
  supplyLabel: string;
  decimals: number;
}

const CPTA_INFO: Record<string, CptaInfo> = {
  ERA: {
    cptaType: 'DJTE EMISSION TOKEN',
    anchorId: 'PROTOCOL-DEFINED',
    anchor: 'BLAKE3("DSM/cpta\\0" || djte_emission_genesis)\nDeterministic Join-Triggered Emission. ERA has an 80 billion total supply and is presented with 2 decimal places.',
    maxSupply: '80,000,000,000',
    supplyLabel: 'Total Supply',
    decimals: 2,
  },
  DBTC: {
    cptaType: 'BITCOIN TAP TOKEN',
    anchorId: 'PROTOCOL-DEFINED',
    anchor: 'BLAKE3("DSM/cpta\\0" || bitcoin_tap_genesis)\nMint/burn BTC tap asset. dBTC tracks the net BTC tapped into DSM; there is no fixed protocol cap. Fractional exits and possession transfers stay supported.',
    maxSupply: 'Variable \u2014 net BTC tapped into DSM',
    supplyLabel: 'Supply Model',
    decimals: 8,
  },
};

function formatTokens(tokensReceived: unknown, humanScaled?: boolean, decimals = ATOMIC_DECIMALS_DEFAULT): string {
  // Accept string | number | bigint; fall back to string echo.
  if (humanScaled) return String(tokensReceived);

  // Try numeric conversion
  const n =
    typeof tokensReceived === 'bigint'
      ? Number(tokensReceived)
      : typeof tokensReceived === 'number'
      ? tokensReceived
      : Number(tokensReceived as any);

  if (!Number.isFinite(n)) return String(tokensReceived ?? '');

  const denom = Math.pow(10, decimals >>> 0);
  return (n / denom).toFixed(decimals);
}

function formatCompactDbtc(sats: bigint): string {
  if (sats === 0n) return '0.00';
  if (sats >= 1000000n) {
    const [whole, frac = '00'] = formatBtc(sats).split('.');
    return `${whole}.${frac.slice(0, 2)}`;
  }
  return formatBtc(sats).replace(/0+$/, '').replace(/\.$/, '');
}

const AccountsScreen: React.FC<{ eraTokenSrc?: string; btcLogoSrc?: string }> = ({ eraTokenSrc = 'images/logos/era_token_gb.gif', btcLogoSrc = 'images/logos/btc-logo.gif' }) => {
  const { refreshAll, isInitialized } = useWallet();
  const [activeTab, setActiveTab] = useState<Tab>('tokens');
  const [balances, setBalances] = useState<TokenBalance[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [claimingId, setClaimingId] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [expandedToken, setExpandedToken] = useState<string | null>(null);
  const faucetEnabled = !!isInitialized || !!(window as any).DsmBridge;

  const hasBalances = useMemo(() => balances.length > 0, [balances]);

  const loadBalances = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const [data, dbtcBal] = await Promise.all([
        dsmClient.getAllBalances(),
        getDbtcBalance(),
      ]);
      const raw = Array.isArray(data) ? data : Array.isArray((data as any)?.balances) ? (data as any).balances : [];
      const list: TokenBalance[] = (raw as any[]).map((b: any) => ({
        tokenId: String(b.tokenId || ''),
        symbol: String(b.symbol || b.tokenName || b.tokenId || ''),
        balance: String(b.tokenId || '').toUpperCase() === 'DBTC'
          ? formatCompactDbtc(typeof b.balance === 'bigint' ? b.balance : BigInt(b.balance || 0))
          : String(b.balance ?? '0'),
      }));
      // Merge authoritative dBTC balance from the bitcoin.balance endpoint.
      const available = typeof dbtcBal.available === 'bigint' ? dbtcBal.available : BigInt(0);
      const dbtcIdx = list.findIndex((b) => b.tokenId.toUpperCase() === 'DBTC');
      const dbtcEntry: TokenBalance = { tokenId: 'dBTC', symbol: 'dBTC', balance: formatCompactDbtc(available) };
      if (dbtcIdx >= 0) {
        list[dbtcIdx] = dbtcEntry;
      } else {
        list.unshift(dbtcEntry);
      }
      setBalances(list);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to load balances';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadBalances();
  }, [loadBalances]);

  const claimFromFaucet = useCallback(
    async (tokenId: string, symbol: string) => {
      console.log('[UI:faucet] claimFromFaucet click', { tokenId, symbol });
      setError(null);
      setSuccessMsg(null);
      setClaimingId(tokenId);

      try {
        if (!faucetEnabled) {
          throw new Error('Faucet is unavailable until your wallet is initialized. Please finish genesis setup and try again.');
        }

        // Faucet claim via dsmClient.claimFaucet()
        const result: any = await dsmClient.claimFaucet(tokenId);

        console.log('[UI:faucet] claimFaucet result', result);

        if (!result?.success) {
          const msg = result?.message ?? 'Faucet claim failed';
          throw new Error(msg);
        }

        // Some bridge paths may not include tokensReceived/humanScaled; keep UI deterministic.
        const rawTokens = (result as any)?.tokensReceived;
        const tokensHuman =
          rawTokens == null ? '—' : formatTokens(rawTokens, (result as any)?.humanScaled, ATOMIC_DECIMALS_DEFAULT);
        const nextAvail = result?.nextAvailable != null ? String(result.nextAvailable) : '—';

        await loadBalances();
        try {
          await refreshAll();
        } catch (refreshErr) {
          // non-fatal UI refresh miss
          console.warn('AccountsScreen: refreshAll failed after faucet claim:', refreshErr);
        }
        // refreshAll() already updated WalletContext (balance + history).
        // Do NOT emit wallet.refresh here — that would trigger 3 more RPCs for
        // data we just fetched (useWalletSync balance+history, useWalletRefreshListener
        // history again).

        setSuccessMsg(
          `Claimed ${tokensHuman} ${symbol || 'ERA'}. Next claim in ~${nextAvail}s.`
        );
      } catch (e) {
        console.warn('[UI:faucet] claim failed', e);
        const msg = e instanceof Error ? e.message : 'Faucet claim failed';
        setError(msg);
      } finally {
        setClaimingId(null);
      }
    },
    [loadBalances, refreshAll]
  );

  // --- D-pad navigation ---
  // Items: [Balances tab, Faucet tab, ...content items]
  const contentItemCount = activeTab === 'tokens' ? balances.length : 1; // 1 = claim button
  const navItemCount = 2 + contentItemCount; // 2 tabs + content

  const { focusedIndex } = useDpadNav({
    itemCount: navItemCount,
    onSelect: (idx) => {
      if (idx === 0) { setActiveTab('tokens'); return; }
      if (idx === 1) { setActiveTab('faucet'); return; }
      // Content items (idx >= 2)
      if (activeTab === 'faucet') {
        void claimFromFaucet(balances[0]?.tokenId || 'era', 'ERA');
      }
      // Token items: toggle expand on select
      if (activeTab === 'tokens' && balances[idx - 2]) {
        const tid = balances[idx - 2].tokenId;
        setExpandedToken((prev) => (prev === tid ? null : tid));
      }
    },
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');

  return (
    <div className="dsm-content" style={{
      alignSelf: 'stretch',
      width: '100%',
      minHeight: '100%',
      boxSizing: 'border-box',
      padding: '0 6px',
      margin: 0,
      background: 'linear-gradient(0deg, rgba(var(--text-rgb),0.08), rgba(var(--text-rgb),0.02)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.1) 0px, rgba(var(--text-rgb),0.1) 2px, transparent 2px, transparent 4px)',
    }}>
      {/* Header */}
      <div style={{
        fontSize: 10,
        color: 'var(--text-dark)',
        letterSpacing: 1,
        fontWeight: 'bold',
        marginBottom: 12,
        fontFamily: '\'Martian Mono\', monospace',
        textTransform: 'uppercase',
        padding: '12px 0 0',
      }}>
        TOKENS
      </div>

      {/* Tab navigation */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <button
          className={`wallet-style-button${fc(0)}`}
          onClick={() => setActiveTab('tokens')}
          style={{
            flex: 1,
            padding: '10px 12px',
            fontSize: 10,
            fontFamily: '\'Martian Mono\', monospace',
            textTransform: 'uppercase',
            background: activeTab === 'tokens'
              ? 'linear-gradient(0deg, rgba(var(--bg-rgb),0.08), rgba(var(--text-rgb),0.12)), repeating-linear-gradient(45deg, rgba(var(--bg-rgb),0.12) 0px, rgba(var(--bg-rgb),0.12) 2px, transparent 2px, transparent 4px)'
              : 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)',
            color: activeTab === 'tokens' ? 'var(--text)' : 'var(--text-dark)',
            border: '2px solid var(--border)',
            borderRadius: 8,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
          }}
        >
          Balances
        </button>
        <button
          className={`wallet-style-button${fc(1)}`}
          onClick={() => setActiveTab('faucet')}
          style={{
            flex: 1,
            padding: '10px 12px',
            fontSize: 10,
            fontFamily: '\'Martian Mono\', monospace',
            textTransform: 'uppercase',
            background: activeTab === 'faucet' 
              ? 'linear-gradient(0deg, rgba(var(--bg-rgb),0.08), rgba(var(--text-rgb),0.12)), repeating-linear-gradient(45deg, rgba(var(--bg-rgb),0.12) 0px, rgba(var(--bg-rgb),0.12) 2px, transparent 2px, transparent 4px)'
              : 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)',
            color: activeTab === 'faucet' ? 'var(--text)' : 'var(--text-dark)',
            border: '2px solid var(--border)',
            borderRadius: 8,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
          }}
        >
          Faucet
        </button>
      </div>

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 24 }}>
          <LoadingSpinner message="Loading" size="medium" />
        </div>
      ) : (
        <>
          {error && (
            <div
              role="alert"
              style={{
                fontSize: 9,
                color: 'var(--text-dark)',
                border: '1px solid var(--error)',
                padding: 8,
                marginBottom: 12,
                borderRadius: 0,
                fontFamily: "'Martian Mono', monospace",
              }}
            >
              {error}
            </div>
          )}

          {activeTab === 'tokens' ? (
            <div style={{ width: '100%' }}>
              {!hasBalances ? (
                <div style={{
                  textAlign: 'center',
                  padding: 24,
                  fontSize: 10,
                  borderTop: '1px dashed var(--border)',
                  borderBottom: '1px dashed var(--border)',
                  fontFamily: "'Martian Mono', monospace",
                  color: 'var(--text-dark)',
                }}>
                  No tokens yet
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 0, width: '100%' }}>
                  {balances.map((balance, bIdx) => {
                    const sym = (balance.symbol || balance.tokenId || '').toLowerCase();
                    const isBtc = sym.includes('btc') || sym.includes('dbtc');
                    const logoSrc = isBtc ? btcLogoSrc : eraTokenSrc;
                    const logoAlt = isBtc ? 'BTC' : 'ERA';
                    const isFocused = focusedIndex === 2 + bIdx;
                    const isExpanded = expandedToken === balance.tokenId;
                    const cpta = CPTA_INFO[(balance.tokenId || '').toUpperCase()] || CPTA_INFO[(balance.symbol || '').toUpperCase()];
                    const isZero = !balance.balance || balance.balance === '0' || balance.balance === '0.00000000';
                    return (
                    <div
                      key={balance.tokenId}
                      className={isFocused ? 'dpad-focus-ring' : undefined}
                      onClick={() => setExpandedToken((prev) => (prev === balance.tokenId ? null : balance.tokenId))}
                      style={{
                        width: '100%',
                        boxSizing: 'border-box',
                        border: '2px solid var(--border)',
                        borderBottom: bIdx === balances.length - 1 ? '2px solid var(--border)' : 'none',
                        borderRadius: 0,
                        background: 'var(--text-dark)',
                        color: 'var(--bg)',
                        overflow: 'hidden',
                        fontFamily: "'Martian Mono', monospace",
                        cursor: 'pointer',
                      }}
                    >
                      {/* Card header — light bg for dark coin GIFs */}
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 10px',
                        minHeight: 44,
                        background: 'linear-gradient(0deg, rgba(var(--text-rgb),0.08), rgba(var(--text-rgb),0.02)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.1) 0px, rgba(var(--text-rgb),0.1) 2px, transparent 2px, transparent 4px), var(--bg)',
                        color: 'var(--text)',
                      }}>
                        <span style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                          fontSize: 11,
                          fontWeight: 700,
                          color: 'var(--text)',
                          textTransform: 'uppercase',
                          letterSpacing: 0.2,
                        }}>
                          <img
                            src={logoSrc}
                            alt={logoAlt}
                            className={isBtc ? 'btc-gif small' : 'era-gif small'}
                            style={{ flexShrink: 0, imageRendering: 'pixelated' }}
                          />
                          {balance.symbol || balance.tokenId}
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{
                            fontSize: 12,
                            fontWeight: 700,
                            color: isZero ? 'var(--text-dark)' : 'var(--text)',
                            opacity: isZero ? 0.55 : 1,
                            fontVariantNumeric: 'tabular-nums',
                            whiteSpace: 'nowrap',
                          }}>
                            {String(balance.balance ?? '0')} {balance.symbol || ''}
                          </span>
                          <span style={{ fontSize: 10, opacity: 0.5, color: 'var(--text-dark)' }}>
                            {isExpanded ? '\u25B2' : '\u25BC'}
                          </span>
                        </span>
                      </div>
                      {/* Expanded CPTA panel — dark bg */}
                      {isExpanded && cpta && (
                        <div style={{ borderTop: '1px solid rgba(var(--bg-rgb),0.14)' }}>
                          <div style={{
                            padding: '6px 10px 4px',
                            fontSize: 6,
                            fontWeight: 700,
                            letterSpacing: 0.8,
                            textTransform: 'uppercase',
                            color: 'rgba(var(--bg-rgb),0.55)',
                          }}>
                            CPTA Information
                          </div>
                          {([
                            ['Your Balance', `${balance.balance ?? '0'} ${balance.symbol || ''}`],
                            ['CPTA Type', cpta.cptaType],
                            ['Decimals', String(cpta.decimals)],
                            [cpta.supplyLabel, cpta.maxSupply],
                            ['Anchor ID', cpta.anchorId],
                          ] as [string, string][]).map(([label, value]) => (
                            <div key={label} style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'flex-start',
                              gap: 8,
                              padding: '5px 10px',
                              borderBottom: '1px solid rgba(var(--bg-rgb),0.14)',
                              fontSize: 8,
                            }}>
                              <span style={{
                                flex: '0 0 auto',
                                opacity: 0.6,
                                textTransform: 'uppercase',
                                letterSpacing: 0.4,
                                fontSize: 6,
                                fontWeight: 700,
                                paddingTop: 1,
                              }}>
                                {label}
                              </span>
                              <span style={{
                                flex: '1 1 auto',
                                textAlign: 'right',
                                wordBreak: 'break-word',
                                overflowWrap: 'anywhere',
                                fontSize: 7,
                                fontFamily: "'Martian Mono', monospace",
                              }}>
                                {value}
                              </span>
                            </div>
                          ))}
                          <div style={{
                            padding: '6px 10px 8px',
                            fontSize: 7,
                            lineHeight: 1.5,
                            opacity: 0.72,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-word',
                          }}>
                            {cpta.anchor}
                          </div>
                        </div>
                      )}
                    </div>
                    );
                  })}
                </div>
              )}
            </div>
          ) : (
            <div style={{ width: '100%' }}>
              {/* Faucet tab */}
              <div style={{
                width: '100%',
                boxSizing: 'border-box',
                background: 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)',
                border: '2px solid var(--border)',
                borderRadius: 0,
                padding: 16,
                marginBottom: 12,
                boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 12
              }}>
                <img
                  src={eraTokenSrc}
                  alt="ERA Token"
                  style={{
                    width: 60,
                    height: 60,
                    imageRendering: 'pixelated'
                  }}
                />
                <div style={{
                  fontSize: 10,
                  fontFamily: '\'Martian Mono\', monospace',
                  color: 'var(--text-dark)',
                  textAlign: 'center'
                }}>
                  ERA TOKEN FAUCET
                </div>
              </div>

              {successMsg && (
                <div style={{
                  fontSize: 9,
                  color: 'var(--text)',
                  padding: 8,
                  background: 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)',
                  border: '2px solid var(--border)',
                  borderRadius: 0,
                  fontFamily: '\'Martian Mono\', monospace',
                  textAlign: 'center',
                  marginBottom: 12
                }}>
                  {successMsg}
                </div>
              )}

              <div>
                <button
                  className={`wallet-style-button${fc(2)}`}
                  onClick={() => void claimFromFaucet(balances[0]?.tokenId || 'era', 'ERA')}
                  disabled={claimingId !== null}
                  style={{
                    width: '100%',
                    padding: 12,
                    fontSize: 10,
                    fontFamily: '\'Martian Mono\', monospace',
                    textTransform: 'uppercase',
                    background: (claimingId !== null)
                      ? 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)'
                      : 'linear-gradient(0deg, rgba(var(--bg-rgb),0.08), rgba(var(--text-rgb),0.12)), repeating-linear-gradient(45deg, rgba(var(--bg-rgb),0.12) 0px, rgba(var(--bg-rgb),0.12) 2px, transparent 2px, transparent 4px)',
                    color: (claimingId !== null) ? 'var(--text-dark)' : 'var(--text)',
                    border: '2px solid var(--border)',
                    borderRadius: 8,
                    cursor: (claimingId !== null) ? 'not-allowed' : 'pointer',
                    boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
                  }}
                >
                  {claimingId !== null ? 'CLAIMING...' : 'CLAIM FAUCET'}
                </button>
              </div>
            </div>
          )}
        </>
      )}

      <div className="navigation-hint" style={{ color: 'var(--text-dark)', marginTop: 'auto', paddingTop: 20, fontSize: 8 }}>
        Press B to go back
      </div>
    </div>
  );
};

export default AccountsScreen;
