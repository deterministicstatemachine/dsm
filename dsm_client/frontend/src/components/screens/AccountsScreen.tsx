/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, security/detect-object-injection, security/detect-unsafe-regex, no-console, react-hooks/exhaustive-deps */
// SPDX-License-Identifier: Apache-2.0
// AccountsScreen — Tabbed Tokens & Faucet view

import React, { useEffect, useMemo, useState, useCallback } from 'react';
import LoadingSpinner from '../common/LoadingSpinner';
import { dsmClient } from '../../services/dsmClient';
import { useWallet } from '../../contexts/WalletContext';
import { useDpadNav } from '../../hooks/useDpadNav';
import { useWalletRefreshListener } from '../../hooks/useWalletRefreshListener';
import { TokenCreationDialog } from '../TokenCreationDialog';
import { mintToken, burnToken, addTokenByAnchor } from '../../dsm/policies';

type TokenSymbol = 'ERA' | string;
type Tab = 'tokens' | 'faucet';

export interface TokenBalance {
  tokenId: string;
  balance: string;        // human-readable (already scaled by backend)
  symbol: TokenSymbol;
  lastUpdated?: number;   // optional, backend-provided; not used for logic
}


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

const SUPPLY_BTN: React.CSSProperties = {
  flex: 1,
  padding: '8px 10px',
  fontSize: 9,
  fontFamily: "'Martian Mono', monospace",
  textTransform: 'uppercase',
  letterSpacing: 0.6,
  fontWeight: 700,
  background: 'var(--bg)',
  color: 'var(--text)',
  border: '2px solid var(--border)',
  borderRadius: 0,
  cursor: 'pointer',
};

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

  // Token creation and supply control. ERA and dBTC are protocol-defined, so
  // they are described by CPTA_INFO and are not user-mintable; anything else in
  // this list was created by this device and carries its own policy.
  const [creating, setCreating] = useState(false);
  /// Adding a token created elsewhere, by its CPTA anchor. A device cannot
  /// hold a token whose policy it does not have, so this is the step between
  /// someone creating a token and this device being able to receive any.
  const [addingAnchor, setAddingAnchor] = useState<string | null>(null);
  /// The adopted token's identifiers, kept on screen until dismissed. A
  /// snackbar that fades is not an acknowledgement for something the user may
  /// need to write down or check against the creating device.
  const [addedToken, setAddedToken] = useState<
    { ticker: string; tokenId: string; anchorBase32: string } | null
  >(null);
  const [supplyAction, setSupplyAction] = useState<{ tokenId: string; kind: 'mint' | 'burn' } | null>(null);
  const [amount, setAmount] = useState('');
  const [busy, setBusy] = useState(false);

  const isProtocolToken = useCallback(
    (b: TokenBalance) =>
      Boolean(
        CPTA_INFO[(b.tokenId || '').toUpperCase()] || CPTA_INFO[(b.symbol || '').toUpperCase()],
      ),
    [],
  );

  const hasBalances = useMemo(() => balances.length > 0, [balances]);

  const loadBalances = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const data = await dsmClient.getAllBalances();
      const raw = Array.isArray(data) ? data : Array.isArray((data as any)?.balances) ? (data as any).balances : [];
      const list: TokenBalance[] = (raw as any[]).map((b: any) => ({
        tokenId: String(b.tokenId || ''),
        symbol: String(b.symbol || b.tokenName || b.tokenId || ''),
        // Rust renders the display amount; this screen shows it.
        //
        // Converting base units here would be a SECOND implementation of the
        // unit rule, and two implementations disagree — which is precisely how
        // a token holding 100,000 base units at 2 decimals came to be created
        // as 1,000 and displayed as 100000. Amount conversion has one owner, in
        // Rust, in both directions.
        balance: String(b.displayAmount ?? b.balance ?? '0'),
      }));
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

  // Rust emits dsm-wallet-refresh beside the registry write, so the list
  // refreshes from persisted state whatever caused the change — including an
  // adoption that happened while this screen was already open.
  useWalletRefreshListener(loadBalances, [loadBalances]);

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
          // ERA is a whole-unit token, so the claimed amount IS its display
          // form. This used to divide by 10^8 in floating point, which is both
          // the wrong scale and the wrong arithmetic for an amount.
          rawTokens == null ? '—' : String(rawTokens);
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

  /// Run a mint or burn and show whatever the policy decided, verbatim.
  ///
  /// The amount goes to Rust exactly as typed — no client-side rescaling — and
  /// this never pre-judges whether the operation is permitted. Authority,
  /// k-of-N threshold and the supply cap are the committed policy's call, and
  /// its refusal is the message the user sees.
  const runSupplyAction = useCallback(async () => {
    if (!supplyAction || !amount.trim()) return;
    setBusy(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const fn = supplyAction.kind === 'mint' ? mintToken : burnToken;
      const res = await fn({ tokenId: supplyAction.tokenId, amount: amount.trim() });
      if (res?.success) {
        setSuccessMsg(`${supplyAction.kind === 'mint' ? 'Minted' : 'Burned'} ${amount.trim()} ${supplyAction.tokenId}.`);
        setSupplyAction(null);
        setAmount('');
        await loadBalances();
        try {
          await refreshAll();
        } catch {
          /* non-fatal refresh miss */
        }
      } else {
        setError(res?.message || `${supplyAction.kind} failed`);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : `${supplyAction.kind} failed`);
    } finally {
      setBusy(false);
    }
  }, [supplyAction, amount, loadBalances, refreshAll]);

  /// Add a token by CPTA anchor and show whatever Rust decided.
  const runAddToken = useCallback(async () => {
    const anchor = (addingAnchor || '').trim();
    if (!anchor) return;
    setBusy(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await addTokenByAnchor({ anchorBase32: anchor });
      if (res?.success) {
        // Reload from the persisted registry before announcing anything. The
        // route's reply says what Rust did; the list must show what Rust
        // KEPT. Rendering an optimistic row would claim a token is holdable
        // on the strength of a response rather than of stored state.
        await loadBalances();
        setAddedToken({
          ticker: res.ticker || '',
          tokenId: res.tokenId || '',
          anchorBase32: anchor,
        });
        setAddingAnchor(null);
      } else {
        setError(res?.error || 'Could not add that token');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not add that token');
    } finally {
      setBusy(false);
    }
  }, [addingAnchor, loadBalances]);

  // --- D-pad navigation ---
  // Items: [Balances tab, Faucet tab, Create token, ...content items]
  const contentItemCount = activeTab === 'tokens' ? balances.length : 1; // 1 = claim button
  const createOffset = activeTab === 'tokens' ? 1 : 0; // the create button
  const navItemCount = 2 + createOffset + contentItemCount;

  const { focusedIndex } = useDpadNav({
    itemCount: navItemCount,
    onSelect: (idx) => {
      if (idx === 0) { setActiveTab('tokens'); return; }
      if (idx === 1) { setActiveTab('faucet'); return; }
      if (activeTab === 'tokens' && idx === 2) { setCreating(true); return; }
      // Content items
      if (activeTab === 'faucet') {
        void claimFromFaucet(balances[0]?.tokenId || 'era', 'ERA');
      }
      // Token items: toggle expand on select
      const tokenIdx = idx - 2 - createOffset;
      if (activeTab === 'tokens' && balances[tokenIdx]) {
        const tid = balances[tokenIdx].tokenId;
        setExpandedToken((prev) => (prev === tid ? null : tid));
      }
    },
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');

  return (
    <div className="dsm-content" style={{
      alignSelf: 'stretch',
      width: 'calc(100% + 40px)',
      minHeight: 'calc(100% + 20px)',
      height: 'calc(100% + 20px)',
      boxSizing: 'border-box',
      padding: '0 8px',
      margin: '-20px -20px 0',
      overflow: 'hidden',
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
              <button
                type="button"
                className={`wallet-style-button${fc(2)}`}
                onClick={() => setCreating(true)}
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  marginBottom: 10,
                  fontSize: 9,
                  fontFamily: "'Martian Mono', monospace",
                  textTransform: 'uppercase',
                  letterSpacing: 0.6,
                  fontWeight: 700,
                  background: 'transparent',
                  color: 'var(--text-dark)',
                  border: '2px solid var(--border)',
                  borderRadius: 0,
                  cursor: 'pointer',
                }}
              >
                + Create Token
              </button>

              {/* Adopting someone else's token. Separate from creation because
                  it is a different act: no policy is authored, no fee is
                  burned, nothing is issued — this device is only learning the
                  rules of a token that already exists so it can hold it. */}
              {addingAnchor === null ? (
                <button
                  type="button"
                  onClick={() => { setAddingAnchor(''); setError(null); setSuccessMsg(null); }}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    marginBottom: 10,
                    fontSize: 9,
                    fontFamily: "'Martian Mono', monospace",
                    textTransform: 'uppercase',
                    letterSpacing: 0.6,
                    fontWeight: 700,
                    background: 'transparent',
                    color: 'var(--text-dark)',
                    border: '2px solid var(--border)',
                    borderRadius: 0,
                    cursor: 'pointer',
                  }}
                >
                  + Add Token (CPTA)
                </button>
              ) : (
                <div style={{ marginBottom: 10, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <input
                    type="text"
                    placeholder="CPTA policy anchor"
                    aria-label="CPTA policy anchor"
                    value={addingAnchor}
                    onChange={(e) => setAddingAnchor(e.target.value.trim().toUpperCase())}
                    style={{
                      width: '100%',
                      boxSizing: 'border-box',
                      padding: '8px 10px',
                      fontSize: 9,
                      fontFamily: "'Martian Mono', monospace",
                      background: 'var(--bg)',
                      color: 'var(--text)',
                      border: '2px solid var(--border)',
                      borderRadius: 0,
                    }}
                  />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      type="button"
                      disabled={busy || !addingAnchor.trim()}
                      onClick={() => void runAddToken()}
                      style={SUPPLY_BTN}
                    >
                      {busy ? 'ADDING...' : 'ADD'}
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => setAddingAnchor(null)}
                      style={SUPPLY_BTN}
                    >
                      CANCEL
                    </button>
                  </div>
                </div>
              )}
              {addedToken && (
                <div
                  role="status"
                  style={{
                    marginBottom: 10,
                    padding: 10,
                    border: '2px solid var(--border)',
                    background: 'var(--text-dark)',
                    color: 'var(--bg)',
                    fontFamily: "'Martian Mono', monospace",
                    fontSize: 8,
                    lineHeight: 1.6,
                  }}
                >
                  <div style={{ fontWeight: 700, fontSize: 9, marginBottom: 6 }}>
                    {addedToken.ticker ? `${addedToken.ticker} added` : 'Token added'}
                  </div>
                  <div style={{ opacity: 0.7, fontSize: 6, textTransform: 'uppercase' }}>Token ID</div>
                  <div style={{ wordBreak: 'break-all', marginBottom: 4 }}>{addedToken.tokenId}</div>
                  <div style={{ opacity: 0.7, fontSize: 6, textTransform: 'uppercase' }}>
                    Policy Anchor (CPTA)
                  </div>
                  <div style={{ wordBreak: 'break-all', marginBottom: 8 }}>
                    {addedToken.anchorBase32}
                  </div>
                  <button type="button" onClick={() => setAddedToken(null)} style={SUPPLY_BTN}>
                    OK
                  </button>
                </div>
              )}
              {successMsg && (
                <div
                  role="status"
                  style={{
                    fontSize: 8,
                    color: 'var(--text-dark)',
                    border: '1px solid var(--border)',
                    padding: 8,
                    marginBottom: 10,
                    fontFamily: "'Martian Mono', monospace",
                  }}
                >
                  {successMsg}
                </div>
              )}
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
                    const isFocused = focusedIndex === 2 + createOffset + bIdx;
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

                      {/* Supply controls — only for tokens this device created.
                          ERA and dBTC are protocol-defined and deliberately
                          offer nothing here. */}
                      {isExpanded && !isProtocolToken(balance) && (
                        <div
                          onClick={(e) => e.stopPropagation()}
                          style={{
                            padding: '8px 10px 10px',
                            borderTop: '1px solid rgba(var(--bg-rgb),0.14)',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 8,
                          }}
                        >
                          {supplyAction?.tokenId === balance.tokenId ? (
                            <>
                              <input
                                type="text"
                                inputMode="numeric"
                                placeholder="0"
                                value={amount}
                                onChange={(e) => setAmount(e.target.value)}
                                aria-label={`${supplyAction.kind} amount`}
                                style={{
                                  width: '100%',
                                  boxSizing: 'border-box',
                                  padding: '8px 10px',
                                  fontSize: 10,
                                  fontFamily: "'Martian Mono', monospace",
                                  background: 'var(--bg)',
                                  color: 'var(--text)',
                                  border: '2px solid var(--border)',
                                  borderRadius: 0,
                                }}
                              />
                              <div style={{ display: 'flex', gap: 8 }}>
                                <button
                                  type="button"
                                  disabled={busy || !amount.trim()}
                                  onClick={() => void runSupplyAction()}
                                  style={SUPPLY_BTN}
                                >
                                  {busy ? 'WORKING...' : 'CONFIRM'}
                                </button>
                                <button
                                  type="button"
                                  disabled={busy}
                                  onClick={() => { setSupplyAction(null); setAmount(''); }}
                                  style={SUPPLY_BTN}
                                >
                                  CANCEL
                                </button>
                              </div>
                            </>
                          ) : (
                            <div style={{ display: 'flex', gap: 8 }}>
                              <button
                                type="button"
                                onClick={() => { setSupplyAction({ tokenId: balance.tokenId, kind: 'mint' }); setAmount(''); }}
                                style={SUPPLY_BTN}
                              >
                                MINT
                              </button>
                              <button
                                type="button"
                                onClick={() => { setSupplyAction({ tokenId: balance.tokenId, kind: 'burn' }); setAmount(''); }}
                                style={SUPPLY_BTN}
                              >
                                BURN
                              </button>
                            </div>
                          )}
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

      {creating && (
        <TokenCreationDialog
          onClose={() => setCreating(false)}
          onSuccess={() => {
            void loadBalances();
          }}
        />
      )}
    </div>
  );
};

export default AccountsScreen;
