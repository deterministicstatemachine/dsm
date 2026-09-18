// SPDX-License-Identifier: Apache-2.0
// Liquidity screen — owner-side AMM vault list + create flow.
//
// Reached from the home brick `LIQUIDITY`.  Replaces the dev-side
// DevAmmVaultScreen + DevAmmMonitorScreen pair: shows owned vaults at
// the top, "+ Create vault" at the bottom expands an inline form that
// confirms via ConfirmModal and emits a toast on success.
//
// All cryptographic work stays Rust-side (Track C.4 accept-or-stamp on
// `dlv.create`).  This screen frames typed inputs.

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  createAmmVault,
  listOwnedAmmVaults,
  reconcileVaultSettlement,
  closeAmmVault,
  type AmmVaultSummary,
} from '../../dsm/amm';
import { publishRoutingAdvertisement } from '../../dsm/route_commit';
import { decodeBase32Crockford } from '../../utils/textId';
import { getAllBalances } from '../../dsm/wallet';
import type { TokenBalanceView } from '../../dsm/types';
import ConfirmModal from '../ConfirmModal';
import { Disclosure, Notice, ScreenFrame } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';
import { TokenMark } from '../TokenMark';
import { TokenSelect } from '../common/TokenSelect';
import { useFx } from '../fx/FxProvider';
import { useBackButton } from '../../hooks/useBackButton';

type Phase = 'idle' | 'loading' | 'creating' | 'publishing' | 'republishing' | 'closing' | 'created' | 'error';

interface Props {
  onNavigate?: (screen: string) => void;
}


function bigIntFromString(s: string): bigint {
  if (!/^[0-9]+$/.test(s)) throw new Error('must be a non-negative integer');
  return BigInt(s);
}

export default function LiquidityScreen({ onNavigate }: Props): JSX.Element {
  const fx = useFx();
  const [phase, setPhase] = useState<Phase>('loading');
  const [vaults, setVaults] = useState<AmmVaultSummary[]>([]);
  const [error, setError] = useState<string>('');
  const [toast, setToast] = useState<string>('');
  const [showCreate, setShowCreate] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  /// The vault a Withdraw-all click is awaiting confirmation for. Closing is
  /// irreversible (the vault id is single-use), so it is never one click.
  const [confirmClose, setConfirmClose] = useState<AmmVaultSummary | null>(null);

  // The pair is chosen from assets this device actually HOLDS, and each choice
  // carries the token's 32-byte CPTA anchor. Free text used to be sent as the
  // pair identity, which made a ticker the asset's name AND its identity — and
  // a ticker is not an identity: two distinct RIGB tokens have existed here.
  const [holdings, setHoldings] = useState<TokenBalanceView[]>([]);
  const [tokenA, setTokenA] = useState('');
  const [tokenB, setTokenB] = useState('');
  const [reserveA, setReserveA] = useState('');
  const [reserveB, setReserveB] = useState('');
  const [feeBps, setFeeBps] = useState('30');
  const [pendingPublishId, setPendingPublishId] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setPhase('loading');
    setError('');
    try {
      // Only assets carrying a CPTA anchor can name a pair. One without an
      // anchor has no identity to send, so it is not offered rather than
      // offered and rejected later.
      const bal = await getAllBalances();
      setHoldings(bal.filter((b) => (b.policyAnchorB32 ?? '').length > 0));
    } catch {
      setHoldings([]);
    }
    const r = await listOwnedAmmVaults();
    if (r.success) {
      setVaults(r.vaults ?? []);
      setPhase('idle');
    } else {
      setError(r.error || 'listOwnedAmmVaults failed');
      setPhase('error');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // B (or Escape) closes the create form instead of leaving the screen.
  useBackButton(showCreate, () => setShowCreate(false));

  const handleRepublish = useCallback(async (v: AmmVaultSummary) => {
    setError('');
    setToast('');
    setPendingPublishId(v.vaultIdBase32);
    setPhase('republishing');
    try {
      const vaultIdBytes = decodeBase32Crockford(v.vaultIdBase32);
      if (vaultIdBytes.length !== 32) {
        throw new Error(`vault_id Base32 must decode to 32 bytes (got ${vaultIdBytes.length})`);
      }
      // Phase 13 follow-up: pass the REAL `unlock_spec_digest` +
      // `unlock_spec_key` that Rust persisted in DLV state at create
      // time and exposes on `AmmVaultSummaryV1`.  The pre-fix path
      // stamped 32 zero bytes here (under a comment claiming Rust
      // treated zeros as an "advertisement-only" sentinel) — the
      // claim was false; the route handler stored zeros verbatim and
      // corrupted the advertisement so traders on other devices
      // failed unlock-spec verification.  This guard refuses to fire
      // for legacy vaults (no persisted digest) — the Publish button
      // is suppressed for those vaults in the row render below.
      if (!v.unlockSpecDigest || v.unlockSpecDigest.length !== 32 || !v.unlockSpecKey) {
        throw new Error(
          'vault has no persisted unlock-spec digest (legacy vault created before Phase 13); ' +
            're-create the vault to enable Publish-retry',
        );
      }
      // Re-derive canonical pair ordering (Rust enforces lex-lower-first).
      // listOwnedAmmVaults returns tokenA/tokenB already canonicalised by
      // dlv.create, so the bytes here are good to forward verbatim.
      const publishR = await publishRoutingAdvertisement({
        vaultId: vaultIdBytes,
        tokenA: v.tokenA,
        tokenB: v.tokenB,
        reserveA: v.reserveA,
        reserveB: v.reserveB,
        feeBps: v.feeBps,
        unlockSpecDigest: v.unlockSpecDigest,
        unlockSpecKey: v.unlockSpecKey,
      });
      if (!publishR.success) {
        throw new Error(publishR.error || 'publishRoutingAdvertisement failed');
      }
      setToast(`Advertisement published. id=${v.vaultIdBase32.slice(0, 12)}…`);
      await refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'publish failed';
      setError(msg);
      setPhase('error');
    } finally {
      setPendingPublishId(null);
    }
  }, [refresh]);

  /// Fold every settlement a trader has already completed against this vault.
  ///
  /// The trades are FINAL before this runs — a trader settles on its own device
  /// under the owner's pre-commitment, with the owner offline. Nothing here
  /// authorises anything; the owner is writing down what already happened, so
  /// the reserves it shows stop lagging the chain. Rust checks each receipt and
  /// is idempotent against the reserve leaf's sequence, so a repeat moves
  /// nothing.
  const handleReconcile = useCallback(async (v: AmmVaultSummary) => {
    setError('');
    setToast('');
    setPendingPublishId(v.vaultIdBase32);
    setPhase('republishing');
    try {
      const vaultIdBytes = decodeBase32Crockford(v.vaultIdBase32);
      if (vaultIdBytes.length !== 32) {
        throw new Error(`vault_id Base32 must decode to 32 bytes (got ${vaultIdBytes.length})`);
      }
      let folded = 0;
      for (const x of v.pendingX) {
        const r = await reconcileVaultSettlement({ vaultId: vaultIdBytes, x });
        // Stop at the first refusal rather than pressing on: the rest are
        // folded in sequence order, and continuing past a gap would apply a
        // later settlement over a state that never received the earlier one.
        if (!r.success) {
          throw new Error(r.error || 'dlv.reconcile failed');
        }
        folded += 1;
      }
      setToast(`Reconciled ${folded} settlement${folded === 1 ? '' : 's'}.`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'reconcile failed');
      setPhase('error');
    } finally {
      setPendingPublishId(null);
    }
  }, [refresh]);

  /// Owner: close a vault and take ALL of its remaining liquidity back.
  ///
  /// Irreversible, and Rust refuses unless this device has folded every
  /// settlement the market made — so the button is confirmed, and a refusal is
  /// shown verbatim rather than retried.
  const handleClose = useCallback(async (v: AmmVaultSummary) => {
    setError('');
    setToast('');
    setPendingPublishId(v.vaultIdBase32);
    setPhase('closing');
    try {
      const vaultIdBytes = decodeBase32Crockford(v.vaultIdBase32);
      if (vaultIdBytes.length !== 32) {
        throw new Error(`vault_id Base32 must decode to 32 bytes (got ${vaultIdBytes.length})`);
      }
      const r = await closeAmmVault({ vaultId: vaultIdBytes });
      if (!r.success) throw new Error(r.error || 'dlv.close failed');
      setToast('Vault closed. All liquidity returned to your balance.');
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'close failed');
      setPhase('error');
    } finally {
      setPendingPublishId(null);
    }
  }, [refresh]);

  /// Display name for a selected anchor. Names are for the human reading the
  /// card; the anchor is what is sent.
  const tickerFor = useCallback(
    (anchor: string) => holdings.find((h) => h.policyAnchorB32 === anchor)?.ticker ?? anchor,
    [holdings],
  );

  /** A held token's coin artwork, matched by ticker; undefined draws from the ticker itself. */
  const iconFor = useCallback(
    (ticker: string) => holdings.find((h) => h.ticker === ticker)?.iconUrl,
    [holdings],
  );

  const formValid = useMemo(() => {
    if (!tokenA.trim() || !tokenB.trim()) return false;
    if (tokenA === tokenB) return false;
    if (!reserveA.trim() || !reserveB.trim()) return false;
    return true;
  }, [tokenA, tokenB, reserveA, reserveB]);

  const handleCreate = useCallback(async () => {
    setError('');
    setToast('');
    try {
      setPhase('creating');
      // 32-byte CPTA policy commits, taken from the selected holdings. Identity
      // comes from the picker; nothing here derives it from a name.
      const aBytes = decodeBase32Crockford(tokenA);
      const bBytes = decodeBase32Crockford(tokenB);
      if (aBytes.length !== 32 || bBytes.length !== 32) {
        throw new Error('each side of the pair must be a 32-byte policy commit');
      }
      const rA = bigIntFromString(reserveA);
      const rB = bigIntFromString(reserveB);

      // Ordering is NOT done here. Rust owns canonicalisation: it sorts the pair
      // over the commits and aligns the funding legs to that order, so there is
      // one implementation of "which side is A" rather than a render-layer copy
      // that can disagree with it.

      const fee = Number(feeBps);
      if (!Number.isInteger(fee) || fee < 0 || fee >= 10_000) {
        throw new Error('fee_bps must be an integer in [0, 9999]');
      }

      // No policy anchor is pasted: the vault's DLV-policy digest is derived
      // by Rust from its release and fee policy. A token's CPTA anchor never
      // belonged in that slot — the pair's two anchors are the token layer,
      // carried separately by the AMM predicate.
      const r = await createAmmVault({
        tokenA: aBytes,
        tokenB: bBytes,
        reserveA: rA,
        reserveB: rB,
        feeBps: fee,
      });
      if (!r.success || !r.vaultIdBase32) {
        throw new Error(r.error || 'createAmmVault failed');
      }

      // Chain `publishRoutingAdvertisement` so the vault is
      // discoverable by traders on OTHER devices via
      // `route.syncVaultsForPair`.  Without this step the vault
      // lives only in the local DLVManager and the cross-device
      // SoFi flow we proved on real hardware can't fire from the UI.
      //
      // `vaultProtoBytes` is left empty — Rust derives the canonical
      // VaultPostProto from the local DLVManager (the authoritative
      // source).
      setPhase('publishing');
      const vaultIdBytes = decodeBase32Crockford(r.vaultIdBase32);
      if (vaultIdBytes.length !== 32) {
        throw new Error(`vault_id Base32 must decode to 32 bytes (got ${vaultIdBytes.length})`);
      }
      const publishR = await publishRoutingAdvertisement({
        vaultId: vaultIdBytes,
        tokenA: aBytes,
        tokenB: bBytes,
        reserveA: rA,
        reserveB: rB,
        feeBps: fee,
        // Empty: the publisher fills the advertised digest from the vault
        // record — the DLV-policy digest dlv.create derived and signed —
        // and refuses any other value. Nothing here chooses it.
        unlockSpecDigest: new Uint8Array(),
        unlockSpecKey: `defi/spec/amm/${r.vaultIdBase32.slice(0, 16)}`,
        // No vaultProtoBytes — Rust derives.  No ownerPublicKey —
        // Rust stamps the wallet pk.
      });
      if (!publishR.success) {
        // The vault was created and funded, and its birth proofs are frozen
        // durably. What did NOT happen is the routing advertisement — most
        // often because those proofs have not yet reached quorum on the
        // storage set (Rust refuses to advertise a vault traders could not
        // verify). Nothing to roll back: the wallet replays the proofs on
        // every sync, and Publish appears on the card once they land.
        throw new Error(
          `Vault created and funded, but not yet advertised: ${publishR.error}. ` +
            'It will show "publication pending" until its proofs reach the storage set; ' +
            'then press Publish.',
        );
      }

      setPhase('created');
      fx.play({
        anim: 'vault',
        title: 'Vault created',
        caption: `${tokenA.trim()} / ${tokenB.trim()} is funded and listed for traders`,
      });
      setToast(`Vault created and published. id=${r.vaultIdBase32.slice(0, 12)}\u2026`);
      setShowCreate(false);
      setTokenA('');
      setTokenB('');
      setReserveA('');
      setReserveB('');
      await refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'create failed';
      setError(msg);
      setPhase('error');
    }
  }, [tokenA, tokenB, reserveA, reserveB, feeBps, refresh, fx]);

  const busy = phase === 'creating' || phase === 'publishing' || phase === 'republishing' || phase === 'closing';

  return (
    <ScreenFrame
      title="Liquidity"
      onBack={() => onNavigate?.('home')}
      info={(
        <InfoTip title="Liquidity">
          <p>A vault holds two of your tokens and trades between them for a fee. Every trade against it earns you that fee. You can take everything back at any time with <b>Withdraw all</b>; that retires the vault for good.</p>
          <p><b>Open</b> means traders can find the vault. <b>Publishing</b> means its proofs are still reaching the storage set; that part finishes on its own. <b>Not listed</b> means the proofs are in but the vault is not advertised yet: press <b>Publish</b> to list it.</p>
          <p>Traders settle against your vault while you are offline. When that has happened, the card says how many trades are waiting; <b>Reconcile</b> writes them into the vault&apos;s balances. Nothing is lost while you wait.</p>
        </InfoTip>
      )}
      actions={
        <button
          type="button"
          onClick={() => void refresh()}
          disabled={phase === 'loading' || busy}
          className="sb-icon-btn"
          aria-label="Refresh"
          title="Refresh"
        >
          <img src="images/icons/icon_refresh.svg" alt="" />
        </button>
      }
      banner={
        <>
          {error && <Notice kind="error" banner onClose={() => setError('')}>{error}</Notice>}
          {toast && <Notice kind="success" banner onClose={() => setToast('')}>{toast}</Notice>}
        </>
      }
    >
      <div className="sb-section-title">My vaults ({vaults.length})</div>
      {phase === 'loading' && <div className="sb-empty">Loading{'\u2026'}</div>}
      {phase !== 'loading' && vaults.length === 0 && (
        <div className="sb-empty">
          No AMM vaults owned by this wallet.
          <br />
          Create one below to start earning fees on swaps.
        </div>
      )}
      {vaults.map((v) => {
        const isPublishing = phase === 'republishing' && pendingPublishId === v.vaultIdBase32;
        const isClosing = phase === 'closing' && pendingPublishId === v.vaultIdBase32;
        const canPublish = !v.closed && !v.routingAdvertised && v.publicationState === 'published' && Boolean(v.unlockSpecDigest) && Boolean(v.unlockSpecKey);
        const status = v.closed
          ? { label: 'Closed', cls: ' sb-tag--dim' }
          : v.publicationState !== 'published'
            ? { label: 'Publishing', cls: ' sb-tag--dim' }
            : v.routingAdvertised
              ? { label: 'Open', cls: ' sb-tag--solid' }
              : { label: 'Not listed', cls: '' };
        return (
          <div key={v.vaultIdBase32} className="sb-card">
            <div className="sb-row" style={{ padding: 0, borderBottom: 0 }}>
              <div className="sb-row__main">
                {/* Each coin sits immediately left of the ticker it belongs to. */}
                <div className="sb-row__title" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <TokenMark ticker={v.tokenATicker} iconUrl={iconFor(v.tokenATicker)} className="sb-coin sb-coin--sm" />
                  {v.tokenATicker}
                  <span aria-hidden="true">/</span>
                  <TokenMark ticker={v.tokenBTicker} iconUrl={iconFor(v.tokenBTicker)} className="sb-coin sb-coin--sm" />
                  {v.tokenBTicker}
                </div>
                <div className="sb-row__sub">Fee {(v.feeBps / 100).toFixed(2)}% per trade</div>
              </div>
              <span className={`sb-tag${status.cls}`}>{status.label}</span>
            </div>
            <div className="sb-kv" style={{ marginTop: 6 }}>
              <span className="sb-kv__k">In the vault</span>
              <span className="sb-kv__v">{v.reserveA.toString()} {v.tokenATicker} {'\u00B7'} {v.reserveB.toString()} {v.tokenBTicker}</span>
            </div>

            {v.pendingUnapplied > 0n && (
              // Settled and final already — the reserves above are simply
              // behind until the owner writes them down.
              <div className="sb-notice" style={{ marginTop: 8 }}>
                <span>
                  {v.pendingUnapplied.toString()} settled trade
                  {v.pendingUnapplied === 1n ? '' : 's'} to reconcile
                </span>
                <button
                  type="button"
                  onClick={() => void handleReconcile(v)}
                  disabled={busy}
                  className="sb-btn sb-btn--small"
                  title="Fold settlements traders have already completed into this vault's reserves"
                >
                  {phase === 'republishing' && pendingPublishId === v.vaultIdBase32 ? 'Reconciling\u2026' : 'Reconcile'}
                </button>
              </div>
            )}

            {!v.closed && v.publicationState !== 'published' && (
              // FUNDED IS NOT PUBLISHED. The wallet keeps replaying the vault's
              // frozen birth proofs on every sync until a quorum of its storage
              // set holds them; until then the vault is not market-active and
              // Publish is suppressed (Rust refuses it too).
              <p className="sb-hint sb-hint--tight">Proofs still landing. Nothing to do yet; Publish appears when they are in.</p>
            )}
            {!v.closed && v.publicationState === 'published' && !v.routingAdvertised && !canPublish && (
              <p className="sb-hint sb-hint--tight">Cannot be advertised. Withdraw and create a new vault.</p>
            )}

            {(!v.closed || canPublish) && (
              <div className="sb-actions sb-actions--end" style={{ margin: '8px 0 0' }}>
                {canPublish && (
                  <button
                    type="button"
                    onClick={() => void handleRepublish(v)}
                    disabled={busy}
                    className="sb-btn sb-btn--small sb-btn--primary"
                    title="Republish routing advertisement so traders on other devices can discover this vault"
                  >
                    {isPublishing ? 'Publishing\u2026' : 'Publish'}
                  </button>
                )}
                {!v.closed && (
                  <button
                    type="button"
                    onClick={() => setConfirmClose(v)}
                    disabled={busy}
                    className="sb-btn sb-btn--small sb-btn--ghost"
                    title={
                      v.pendingUnapplied > 0n
                        ? 'Reconcile the settled trades first — a close must consume the vault\'s current state'
                        : 'Withdraw ALL liquidity and retire this vault (irreversible)'
                    }
                  >
                    {isClosing ? 'Closing\u2026' : 'Withdraw all'}
                  </button>
                )}
              </div>
            )}

            <Disclosure summary="Details" className="sb-details--plain">
              <div className="sb-kv"><span className="sb-kv__k">Vault</span><span className="sb-kv__v sb-kv__v--mono">{v.vaultIdBase32}</span></div>
              <div className="sb-kv"><span className="sb-kv__k">Fee</span><span className="sb-kv__v">fee {v.feeBps} bps</span></div>
              <div className="sb-kv"><span className="sb-kv__k">Reserves</span><span className="sb-kv__v">reserves: {v.reserveA.toString()} / {v.reserveB.toString()}</span></div>
              <div className="sb-kv"><span className="sb-kv__k">Routing ad</span><span className="sb-kv__v">{v.routingAdvertised ? `ad: \u2713 seq=${v.advertisedStateNumber.toString()}` : 'ad: \u2717 not published'}</span></div>
              <div className="sb-kv"><span className="sb-kv__k">Publication</span><span className="sb-kv__v">{v.publicationState === 'published' ? 'published' : 'publication pending'}</span></div>
              {v.closed && <p className="sb-hint sb-hint--tight">Closed: all liquidity was returned and this vault id cannot be reused.</p>}
            </Disclosure>
          </div>
        );
      })}

      {!showCreate && (
        <div className="sb-actions">
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="sb-btn sb-btn--primary"
            disabled={busy}
          >
            + Create vault
          </button>
        </div>
      )}

      {showCreate && (
        <div className="sb-card" style={{ marginTop: 4 }}>
          <div className="sb-card__title">
            <span>New vault</span>
            <InfoTip title="New vault" label="About new vaults">
              <p>Pick two tokens you hold and how much of each to put in. The ratio between the two amounts sets the vault&apos;s starting price.</p>
              <p><b>Reserve A</b> and <b>Reserve B</b> are entered in the token&apos;s base units, exactly as the wallet stores them.</p>
              <p><b>Fee</b> is your cut of every trade, in basis points: 30 bps is 0.30%.</p>
              <p>The vault is created and advertised in one step. If the advertisement cannot go out yet, the card shows Publish once it can.</p>
            </InfoTip>
          </div>
          {/* The pair is SELECTED, never typed. The option's value is the
              token's CPTA anchor — its identity — while the label is the
              ticker, which is display only. Free text made the two the same
              thing, and a ticker can name more than one token. */}
          <div className="sb-field">
            <label htmlFor="liq-token-a">Token A</label>
            <TokenSelect
              id="liq-token-a"
              label="Token A"
              placeholder="select a held asset…"
              value={tokenA}
              options={holdings.map((h) => ({
                value: h.policyAnchorB32 ?? '',
                ticker: h.ticker,
                iconUrl: h.iconUrl,
                note: h.anchorFingerprint,
              }))}
              onChange={setTokenA}
            />
          </div>
          <div className="sb-field">
            <label htmlFor="liq-reserve-a">Reserve A</label>
            <input id="liq-reserve-a" type="number" min="0" className="sb-input sb-input--small sb-input--mono" value={reserveA} onChange={(e) => setReserveA(e.target.value)} placeholder="0" />
          </div>
          <div className="sb-field">
            <label htmlFor="liq-token-b">Token B</label>
            <TokenSelect
              id="liq-token-b"
              label="Token B"
              placeholder="select a held asset…"
              value={tokenB}
              options={holdings
                .filter((h) => h.policyAnchorB32 !== tokenA)
                .map((h) => ({
                  value: h.policyAnchorB32 ?? '',
                  ticker: h.ticker,
                  iconUrl: h.iconUrl,
                  note: h.anchorFingerprint,
                }))}
              onChange={setTokenB}
            />
          </div>
          <div className="sb-field">
            <label htmlFor="liq-reserve-b">Reserve B</label>
            <input id="liq-reserve-b" type="number" min="0" className="sb-input sb-input--small sb-input--mono" value={reserveB} onChange={(e) => setReserveB(e.target.value)} placeholder="0" />
          </div>
          <div className="sb-field">
            <label htmlFor="liq-fee">Fee (bps)</label>
            <input id="liq-fee" type="number" min="0" max="9999" className="sb-input sb-input--small sb-input--mono" value={feeBps} onChange={(e) => setFeeBps(e.target.value)} />
          </div>
          <div className="sb-actions" style={{ marginBottom: 0 }}>
            <button type="button" className="sb-btn" onClick={() => setShowCreate(false)} disabled={phase === 'creating' || phase === 'publishing'}>Cancel</button>
            <button
              type="button"
              className="sb-btn sb-btn--primary"
              onClick={() => setShowConfirm(true)}
              disabled={!formValid || phase === 'creating' || phase === 'publishing'}
            >
              {phase === 'creating' ? 'Creating\u2026' : phase === 'publishing' ? 'Publishing\u2026' : 'Create'}
            </button>
          </div>
        </div>
      )}

      <ConfirmModal
        visible={showConfirm}
        title="Create AMM vault"
        message={`Create vault ${tickerFor(tokenA)} / ${tickerFor(tokenB)} with reserves ${reserveA} / ${reserveB} at ${feeBps} bps fee?`}
        onConfirm={() => { setShowConfirm(false); void handleCreate(); }}
        onCancel={() => setShowConfirm(false)}
      />

      <ConfirmModal
        visible={confirmClose !== null}
        title="Withdraw all and close vault"
        message={
          confirmClose
            ? `Return ${confirmClose.reserveA.toString()} ${confirmClose.tokenATicker} and ` +
              `${confirmClose.reserveB.toString()} ${confirmClose.tokenBTicker} to your balance and ` +
              'retire this vault? This cannot be undone — the vault id is single-use, and providing ' +
              'liquidity again means creating a new vault.'
            : ''
        }
        onConfirm={() => {
          const v = confirmClose;
          setConfirmClose(null);
          if (v) void handleClose(v);
        }}
        onCancel={() => setConfirmClose(null)}
      />
    </ScreenFrame>
  );
}
