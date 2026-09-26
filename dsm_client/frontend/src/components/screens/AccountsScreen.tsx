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
import TokenIdentityPanel from '../TokenIdentityPanel';
import { burnToken, addTokenByAnchor, forgetToken } from '../../dsm/policies';
import { TokenCoin } from '../TokenCoin';

type Tab = 'tokens' | 'faucet';

export interface TokenBalance {
  tokenId: string;
  /** Display form, rendered by Rust from the token's decimals. */
  balance: string;
  /** The same balance in base units, as Rust reported it. */
  baseUnits: bigint;
  decimals: number;
  symbol: string;
  /** The token's canonical id — `tokenId` here is the ticker, not an identity. */
  canonicalTokenId?: string;
  /** CPTA policy anchor, Base32 Crockford, rendered by Rust. */
  policyAnchorB32?: string;
  /** Short head of the anchor, for reading against a peer's screen. */
  anchorFingerprint?: string;
  /** The token policy's icon field, carried from Rust; the row draws the token's coin from it. */
  iconUrl?: string;
  /** Whether Rust reports the token as one the protocol defines. Never decided here from the ticker. */
  protocolDefined: boolean;
  /** The whole supply that will ever exist, rendered by Rust; absent when Rust holds none. */
  genesisSupplyDisplay?: string;
  /** What the committed policy permits, as Rust read it; absent when Rust holds no policy for the token. */
  permissions?: { burnEnabled: boolean; transferable: boolean };
}

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
  const [claiming, setClaiming] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [expandedToken, setExpandedToken] = useState<string | null>(null);
  const faucetEnabled = !!isInitialized || !!(window as any).DsmBridge;

  // Token creation and supply control. Rust reports which tokens the protocol
  // defines; those offer no supply controls. Anything else in this list was
  // created or adopted by this device and carries its own committed policy,
  // whose facts Rust reports on the row.
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
  const [supplyAction, setSupplyAction] = useState<{ tokenId: string; kind: 'burn' } | null>(null);
  const [amount, setAmount] = useState('');
  const [busy, setBusy] = useState(false);

  // Rust's word, never the ticker's: a created token may read "ERA".
  const isProtocolToken = useCallback((b: TokenBalance) => b.protocolDefined, []);

  const hasBalances = useMemo(() => balances.length > 0, [balances]);

  const loadBalances = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const data = await dsmClient.getAllBalances();
      const list: TokenBalance[] = data.map((b) => ({
        tokenId: b.tokenId,
        symbol: b.symbol,
        // Rust renders the display amount; this screen shows it.
        //
        // Converting base units here would be a SECOND implementation of the
        // unit rule, and two implementations disagree — which is precisely how
        // a token holding 100,000 base units at 2 decimals came to be created
        // as 1,000 and displayed as 100000. Amount conversion has one owner, in
        // Rust, in both directions.
        balance: b.displayAmount,
        baseUnits: b.baseUnits,
        decimals: b.decimals,
        // The anchor a peer needs to adopt this token, carried from Rust.
        canonicalTokenId: b.canonicalTokenId,
        policyAnchorB32: b.policyAnchorB32,
        anchorFingerprint: b.anchorFingerprint,
        iconUrl: b.iconUrl,
        // What the token is and what its policy fixes and permits, as Rust reports them.
        protocolDefined: b.protocolDefined,
        genesisSupplyDisplay: b.genesisSupplyDisplay,
        permissions: b.permissions,
      }));
      setBalances(list);
      return list;
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
  // The listener wants nothing back; loadBalances answers with the rows it read.
  useWalletRefreshListener(() => { void loadBalances(); }, [loadBalances]);

  /// Forget a token's identity, after saying plainly what that means.
  ///
  /// It removes the NAMING only — canonical balances are untouched, and Rust
  /// refuses outright while any balance is held. The token can be adopted
  /// again from its anchor, so this is reversible while online.
  const handleForget = useCallback(async (b: TokenBalance) => {
    const label = b.symbol;
    if (!window.confirm(
      `Forget ${label}?\n\nThis removes the token from this device so its ticker ` +
      `can be used by another token. Your balance is not affected, and you can ` +
      `add ${label} again from its CPTA anchor while online.`,
    )) return;
    setBusy(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await forgetToken(b.tokenId);
      if (!res.success) throw new Error(res.message || 'forget failed');
      setSuccessMsg(res.message || `${label} forgotten`);
      setExpandedToken(null);
      await loadBalances();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to forget token');
    } finally {
      setBusy(false);
    }
  }, [loadBalances]);


  const claimFromFaucet = useCallback(async () => {
    setError(null);
    setSuccessMsg(null);
    setClaiming(true);
    try {
      if (!faucetEnabled) {
        throw new Error('Faucet is unavailable until your wallet is initialized. Please finish genesis setup and try again.');
      }
      const result = await dsmClient.claimFaucet();
      if (!result.success) {
        throw new Error(result.message);
      }
      await loadBalances();
      try {
        await refreshAll();
      } catch (refreshErr) {
        // non-fatal UI refresh miss
        console.warn('AccountsScreen: refreshAll failed after faucet claim:', refreshErr);
      }
      // refreshAll() already updated WalletContext (balance + history).
      // Do NOT emit wallet.refresh here — that would reload, through the
      // provider's listener, the data we just fetched.

      // What Rust released, in its words.
      setSuccessMsg(result.message);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Faucet claim failed');
    } finally {
      setClaiming(false);
    }
  }, [loadBalances, refreshAll]);

  /// Run a burn and show whatever the policy decided, verbatim.
  ///
  /// The amount goes to Rust exactly as typed — no client-side rescaling — and
  /// this never pre-judges whether the operation is permitted. That is the
  /// committed policy's call, and its refusal is the message the user sees.
  const runSupplyAction = useCallback(async () => {
    if (!supplyAction || !amount.trim()) return;
    setBusy(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await burnToken({ tokenId: supplyAction.tokenId, amount: amount.trim() });
      if (res?.success) {
        setSuccessMsg(`Burned ${amount.trim()} ${supplyAction.tokenId}.`);
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
        // The anchor Rust answered is the one it re-derived from the policy
        // bytes it fetched: the anchor it holds, never the text pasted (a
        // scanned payload is a `dsm:token/v1:` URI, not an anchor).
        setAddedToken({ ticker: res.ticker, tokenId: res.tokenId, anchorBase32: res.anchorBase32 });
        setAddingAnchor(null);
      } else {
        setError(res.error);
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
        void claimFromFaucet();
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
      width: '100%',
      minHeight: '100%',
      height: '100%',
      boxSizing: 'border-box',
      padding: '0 8px',
      margin: 0,
      // The container is a fixed height, so vertical overflow must scroll: an
      // expanded token card is taller than the screen and its BURN / FORGET
      // row sits below the fold. `hidden` made those controls
      // unreachable.
      overflowX: 'hidden',
      overflowY: 'auto',
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
      <div data-tour="tokens-tabs" style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
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
                data-tour="create-token"
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
                    onChange={(e) => setAddingAnchor(e.target.value)}
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
                    {`${addedToken.ticker} added`}
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
                    // The protocol's own artwork is for the protocol's own
                    // assets: which one is Rust's word plus the ticker, so a
                    // created token whose ticker contains "btc" draws its coin.
                    const sym = balance.symbol.toLowerCase();
                    const isBtc = balance.protocolDefined && sym === 'dbtc';
                    const isEra = balance.protocolDefined && sym === 'era';
                    const logoSrc = isBtc ? btcLogoSrc : eraTokenSrc;
                    const logoAlt = isBtc ? 'BTC' : 'ERA';
                    const isFocused = focusedIndex === 2 + createOffset + bIdx;
                    const isExpanded = expandedToken === balance.tokenId;
                    const isZero = balance.baseUnits === 0n;
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
                          {isBtc || isEra ? (
                            <img
                              src={logoSrc}
                              alt={logoAlt}
                              className={isBtc ? 'btc-gif small' : 'era-gif small'}
                              style={{ flexShrink: 0, imageRendering: 'pixelated' }}
                            />
                          ) : (
                            <TokenCoin
                              iconUrl={balance.iconUrl}
                              ticker={balance.symbol}
                              className="era-gif small"
                              fallbackSrc={eraTokenSrc}
                            />
                          )}
                          {balance.symbol}
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
                            {balance.balance} {balance.symbol}
                          </span>
                          <span style={{ fontSize: 10, opacity: 0.5, color: 'var(--text-dark)' }}>
                            {isExpanded ? '\u25B2' : '\u25BC'}
                          </span>
                        </span>
                      </div>
                      {/* Expanded policy panel — dark bg. Every line is a fact
                          Rust reports on the row; a line Rust does not report
                          is not drawn. */}
                      {isExpanded && (
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
                            ['Your Balance', `${balance.balance} ${balance.symbol}`],
                            ['Defined By', balance.protocolDefined ? 'the protocol' : 'its creator’s committed policy'],
                            ['Decimals', String(balance.decimals)],
                            ...(balance.genesisSupplyDisplay
                              ? [['Total Supply', `${balance.genesisSupplyDisplay} ${balance.symbol}`]]
                              : []),
                            ...(balance.permissions
                              ? [
                                  ['Burn', balance.permissions.burnEnabled ? 'permitted' : 'not permitted'],
                                  ['Transfer', balance.permissions.transferable ? 'permitted' : 'not permitted'],
                                ]
                              : []),
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
                        </div>
                      )}

                      {/* Identity — for EVERY token, not just the two in the
                          hardcoded CPTA table. A creator needs the anchor to
                          hand this token to a peer, and had no way to see it. */}
                      {isExpanded && (
                        <TokenIdentityPanel
                          tokenId={balance.tokenId}
                          canonicalTokenId={balance.canonicalTokenId}
                          symbol={balance.symbol}
                          policyAnchorB32={balance.policyAnchorB32}
                          anchorFingerprint={balance.anchorFingerprint}
                          isProtocolToken={isProtocolToken(balance)}
                        />
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
                              {/* Offered only where the committed policy
                                  permits burning, as Rust read it; Rust
                                  enforces the policy either way. */}
                              {balance.permissions?.burnEnabled && (
                                <button
                                  type="button"
                                  onClick={() => { setSupplyAction({ tokenId: balance.tokenId, kind: 'burn' }); setAmount(''); }}
                                  style={SUPPLY_BTN}
                                >
                                  BURN
                                </button>
                              )}
                              {/* Dropping the identity, not the asset. A ticker
                                  names one token, so a superseded token blocks
                                  its own ticker until it is forgotten. Rust
                                  refuses while a balance is held. */}
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() => { void handleForget(balance); }}
                                style={SUPPLY_BTN}
                              >
                                FORGET
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
                  data-tour="faucet-claim"
                  onClick={() => void claimFromFaucet()}
                  disabled={claiming}
                  style={{
                    width: '100%',
                    padding: 12,
                    fontSize: 10,
                    fontFamily: '\'Martian Mono\', monospace',
                    textTransform: 'uppercase',
                    background: (claiming)
                      ? 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)'
                      : 'linear-gradient(0deg, rgba(var(--bg-rgb),0.08), rgba(var(--text-rgb),0.12)), repeating-linear-gradient(45deg, rgba(var(--bg-rgb),0.12) 0px, rgba(var(--bg-rgb),0.12) 2px, transparent 2px, transparent 4px)',
                    color: (claiming) ? 'var(--text-dark)' : 'var(--text)',
                    border: '2px solid var(--border)',
                    borderRadius: 8,
                    cursor: (claiming) ? 'not-allowed' : 'pointer',
                    boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
                  }}
                >
                  {claiming ? 'CLAIMING...' : 'CLAIM FAUCET'}
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
