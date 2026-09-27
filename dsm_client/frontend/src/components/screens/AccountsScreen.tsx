// SPDX-License-Identifier: Apache-2.0
// AccountsScreen — Tokens: every balance Rust lists (with its committed
// policy's facts), creating and adopting tokens, and the ERA faucet.

import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { dsmClient } from '../../services/dsmClient';
import { useWallet } from '../../contexts/WalletContext';
import { useDpadNav } from '../../hooks/useDpadNav';
import { useWalletRefreshListener } from '../../hooks/useWalletRefreshListener';
import { TokenCreationDialog } from '../TokenCreationDialog';
import TokenIdentityPanel from '../TokenIdentityPanel';
import { burnToken, addTokenByAnchor, forgetToken } from '../../dsm/policies';
import { TokenCoin } from '../TokenCoin';
import { Notice, ScreenFrame, ScreenTabs } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';

type Tab = 'tokens' | 'faucet';

const TABS: ReadonlyArray<{ id: Tab; label: string }> = [
  { id: 'tokens', label: 'Balances' },
  { id: 'faucet', label: 'Faucet' },
];

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

const AccountsScreen: React.FC<{ eraTokenSrc?: string; btcLogoSrc?: string }> = ({ eraTokenSrc = 'images/logos/era_token_gb.gif', btcLogoSrc = 'images/logos/btc-logo.gif' }) => {
  const { refreshAll, isInitialized } = useWallet();
  const [activeTab, setActiveTab] = useState<Tab>('tokens');
  const [balances, setBalances] = useState<TokenBalance[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [claiming, setClaiming] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [expandedToken, setExpandedToken] = useState<string | null>(null);
  const faucetEnabled = !!isInitialized || !!(window as { DsmBridge?: unknown }).DsmBridge;

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
  }, [faucetEnabled, loadBalances, refreshAll]);

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

  const banner = (
    <>
      {error && (
        <Notice kind="error" banner onClose={() => setError(null)}>{error}</Notice>
      )}
      {successMsg && (
        <Notice kind="success" banner role="status" onClose={() => setSuccessMsg(null)}>{successMsg}</Notice>
      )}
    </>
  );

  return (
    <ScreenFrame
      title="Tokens"
      className="tokens-screen"
      info={(
        <InfoTip title="Tokens">
          <p><b>Balances</b> lists every token this wallet holds, as Rust reports it. Open one for the facts its committed policy fixes: who defines it, its decimals, its whole supply, and what it permits.</p>
          <p><b>Create Token</b> makes a token of your own under rules you set when you make it. <b>Add Token</b> adopts a token someone else created, from its CPTA anchor, so this device can hold it.</p>
          <p><b>Faucet</b> releases ERA from the network&apos;s reserve under ERA&apos;s committed policy, so you can try things.</p>
        </InfoTip>
      )}
      actions={(
        <button
          type="button"
          onClick={() => void loadBalances()}
          className={`sb-icon-btn${loading ? ' spinning' : ''}`}
          disabled={loading}
          title="Refresh"
          aria-label="Refresh"
        >
          <img src="images/icons/icon_refresh.svg" alt="" />
        </button>
      )}
      tabs={(
        <ScreenTabs
          tabs={TABS}
          active={activeTab}
          onChange={setActiveTab}
          ariaLabel="Token sections"
          dataTour="tokens-tabs"
          focusedIndex={focusedIndex < 2 ? focusedIndex : undefined}
        />
      )}
      banner={banner}
    >
      {loading ? (
        <div className="sb-empty">Loading tokens{'…'}</div>
      ) : activeTab === 'tokens' ? (
        <div className="tokens-tab">
          <div className="sb-actions" style={{ marginTop: 0 }}>
            <button
              type="button"
              className={`sb-btn sb-btn--primary${fc(2)}`}
              data-tour="create-token"
              onClick={() => setCreating(true)}
            >
              + Create Token
            </button>
            {/* Adopting someone else's token. Separate from creation because
                it is a different act: no policy is authored, no fee is
                burned, nothing is issued — this device is only learning the
                rules of a token that already exists so it can hold it. */}
            {addingAnchor === null && (
              <button
                type="button"
                className="sb-btn"
                onClick={() => { setAddingAnchor(''); setError(null); setSuccessMsg(null); }}
              >
                + Add Token (CPTA)
              </button>
            )}
          </div>

          {addingAnchor !== null && (
            <section className="sb-card">
              <div className="sb-field" style={{ marginBottom: 8 }}>
                <label htmlFor="add-token-anchor">Policy anchor of the token to add</label>
                <input
                  id="add-token-anchor"
                  type="text"
                  className="sb-input sb-input--mono"
                  placeholder="CPTA policy anchor"
                  aria-label="CPTA policy anchor"
                  value={addingAnchor}
                  onChange={(e) => setAddingAnchor(e.target.value)}
                  spellCheck={false}
                />
              </div>
              <div className="sb-actions" style={{ margin: 0 }}>
                <button
                  type="button"
                  className="sb-btn"
                  disabled={busy}
                  onClick={() => setAddingAnchor(null)}
                >
                  CANCEL
                </button>
                <button
                  type="button"
                  className="sb-btn sb-btn--primary"
                  disabled={busy || !addingAnchor.trim()}
                  onClick={() => void runAddToken()}
                >
                  {busy ? 'ADDING...' : 'ADD'}
                </button>
              </div>
            </section>
          )}

          {addedToken && (
            <section className="sb-card sb-card--dark" role="status">
              <div className="sb-card__title">{`${addedToken.ticker} added`}</div>
              <div className="sb-kv">
                <span className="sb-kv__k">Token ID</span>
                <span className="sb-kv__v sb-kv__v--mono">{addedToken.tokenId}</span>
              </div>
              <div className="sb-kv">
                <span className="sb-kv__k">Policy Anchor (CPTA)</span>
                <span className="sb-kv__v sb-kv__v--mono">{addedToken.anchorBase32}</span>
              </div>
              <button type="button" className="sb-btn sb-btn--primary sb-btn--block" style={{ marginTop: 8 }} onClick={() => setAddedToken(null)}>
                OK
              </button>
            </section>
          )}

          {!hasBalances ? (
            <div className="sb-empty">No tokens yet</div>
          ) : (
            balances.map((balance, bIdx) => {
              // The protocol's own artwork is for the protocol's own
              // assets: which one is Rust's word plus the ticker, so a
              // created token whose ticker contains "btc" draws its coin.
              const sym = balance.symbol.toLowerCase();
              const isBtc = balance.protocolDefined && sym === 'dbtc';
              const isEra = balance.protocolDefined && sym === 'era';
              const isFocused = focusedIndex === 2 + createOffset + bIdx;
              const isExpanded = expandedToken === balance.tokenId;
              const isZero = balance.baseUnits === 0n;
              const toggle = () => setExpandedToken((prev) => (prev === balance.tokenId ? null : balance.tokenId));
              const facts: [string, string][] = [
                ['Your Balance', `${balance.balance} ${balance.symbol}`],
                ['Defined By', balance.protocolDefined ? 'the protocol' : 'its creator’s committed policy'],
                ['Decimals', String(balance.decimals)],
                ...(balance.genesisSupplyDisplay
                  ? [['Total Supply', `${balance.genesisSupplyDisplay} ${balance.symbol}`] as [string, string]]
                  : []),
                ...(balance.permissions
                  ? [
                      ['Burn', balance.permissions.burnEnabled ? 'permitted' : 'not permitted'] as [string, string],
                      ['Transfer', balance.permissions.transferable ? 'permitted' : 'not permitted'] as [string, string],
                    ]
                  : []),
              ];
              return (
                <section
                  key={balance.tokenId}
                  className={`sb-card token-card${isExpanded ? ' is-open' : ''}${isFocused ? ' focused' : ''}`}
                >
                  <div
                    className={`sb-row sb-row--tap${isExpanded ? ' is-open' : ''}`}
                    role="button"
                    tabIndex={0}
                    aria-expanded={isExpanded}
                    onClick={toggle}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        toggle();
                      }
                    }}
                  >
                    <span className="sb-row__lead">
                      {isBtc || isEra ? (
                        <img
                          src={isBtc ? btcLogoSrc : eraTokenSrc}
                          alt={isBtc ? 'BTC' : 'ERA'}
                          className="sb-coin sb-coin--lg"
                        />
                      ) : (
                        <TokenCoin
                          iconUrl={balance.iconUrl}
                          ticker={balance.symbol}
                          className="sb-coin sb-coin--lg"
                          fallbackSrc={eraTokenSrc}
                        />
                      )}
                    </span>
                    <div className="sb-row__main">
                      <div className="sb-row__title">{balance.symbol}</div>
                      {!balance.protocolDefined && balance.anchorFingerprint && (
                        <div className="sb-row__sub sb-mono">{balance.anchorFingerprint}</div>
                      )}
                    </div>
                    <span className="sb-row__amount" style={isZero ? { opacity: 0.55 } : undefined}>
                      {balance.balance} {balance.symbol}
                    </span>
                    <span className="sb-row__chev" aria-hidden="true">{isExpanded ? '▾' : '›'}</span>
                  </div>

                  {/* Expanded policy panel — dark. Every line is a fact Rust
                      reports on the row; a line Rust does not report is not drawn. */}
                  {isExpanded && (
                    <div className="sb-card sb-card--dark" style={{ marginTop: 8, marginBottom: 0 }}>
                      <h3 className="sb-section-title">CPTA information</h3>
                      {facts.map(([label, value]) => (
                        <div key={label} className="sb-kv">
                          <span className="sb-kv__k">{label}</span>
                          <span className="sb-kv__v">{value}</span>
                        </div>
                      ))}

                      {/* Identity — for EVERY token, not just the two in the
                          hardcoded CPTA table. A creator needs the anchor to
                          hand this token to a peer, and had no way to see it. */}
                      <TokenIdentityPanel
                        tokenId={balance.tokenId}
                        canonicalTokenId={balance.canonicalTokenId}
                        symbol={balance.symbol}
                        policyAnchorB32={balance.policyAnchorB32}
                        anchorFingerprint={balance.anchorFingerprint}
                        isProtocolToken={isProtocolToken(balance)}
                      />

                      {/* Supply controls — only for tokens this device created.
                          ERA and dBTC are protocol-defined and deliberately
                          offer nothing here. */}
                      {!isProtocolToken(balance) && (
                        <div onClick={(e) => e.stopPropagation()}>
                          {supplyAction?.tokenId === balance.tokenId ? (
                            <>
                              <div className="sb-field" style={{ marginTop: 10, marginBottom: 8 }}>
                                <label htmlFor={`burn-amount-${balance.tokenId}`}>Amount to burn</label>
                                <input
                                  id={`burn-amount-${balance.tokenId}`}
                                  type="text"
                                  inputMode="numeric"
                                  className="sb-input sb-input--mono"
                                  placeholder="0"
                                  value={amount}
                                  onChange={(e) => setAmount(e.target.value)}
                                  aria-label={`${supplyAction.kind} amount`}
                                />
                              </div>
                              <div className="sb-actions" style={{ margin: 0 }}>
                                <button
                                  type="button"
                                  className="sb-btn"
                                  disabled={busy}
                                  onClick={() => { setSupplyAction(null); setAmount(''); }}
                                >
                                  CANCEL
                                </button>
                                <button
                                  type="button"
                                  className="sb-btn sb-btn--primary"
                                  disabled={busy || !amount.trim()}
                                  onClick={() => void runSupplyAction()}
                                >
                                  {busy ? 'WORKING...' : 'CONFIRM'}
                                </button>
                              </div>
                            </>
                          ) : (
                            <div className="sb-actions" style={{ marginBottom: 0 }}>
                              {/* Offered only where the committed policy
                                  permits burning, as Rust read it; Rust
                                  enforces the policy either way. */}
                              {balance.permissions?.burnEnabled && (
                                <button
                                  type="button"
                                  className="sb-btn"
                                  onClick={() => { setSupplyAction({ tokenId: balance.tokenId, kind: 'burn' }); setAmount(''); }}
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
                                className="sb-btn"
                                disabled={busy}
                                onClick={() => { void handleForget(balance); }}
                              >
                                FORGET
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </section>
              );
            })
          )}
        </div>
      ) : (
        <div className="faucet-tab">
          <section className="sb-card sb-card--dark sb-card--hero">
            <img
              src={eraTokenSrc}
              alt="ERA Token"
              style={{ width: 56, height: 56, imageRendering: 'pixelated' }}
            />
            <div className="sb-hero__label" style={{ marginTop: 6 }}>ERA token faucet</div>
            <div className="sb-hero__sub">Releases ERA from the network&apos;s reserve, under ERA&apos;s committed policy.</div>
          </section>

          <div className="sb-actions">
            <button
              type="button"
              className={`sb-btn sb-btn--primary sb-btn--block${fc(2)}`}
              data-tour="faucet-claim"
              onClick={() => void claimFromFaucet()}
              disabled={claiming}
            >
              {claiming ? 'CLAIMING...' : 'CLAIM FAUCET'}
            </button>
          </div>
        </div>
      )}

      {creating && (
        <TokenCreationDialog
          onClose={() => setCreating(false)}
          onSuccess={() => {
            void loadBalances();
          }}
        />
      )}
    </ScreenFrame>
  );
};

export default AccountsScreen;
