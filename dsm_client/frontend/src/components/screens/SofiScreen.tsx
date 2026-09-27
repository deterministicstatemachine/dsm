// SPDX-License-Identifier: Apache-2.0
// path: src/components/screens/SofiScreen.tsx
// SoFi (SoFi §27) on the StateBoy frame: swap one token for another through
// sovereign liquidity, create and close liquidity of your own, set up with
// it, resolve a pending position. A token is named by its policy commit, the CPTA anchor the
// wallet's balances carry (the SDK renders policy_anchor_b32 from those same
// 32 bytes); the app sends intent only and Core decides.

import React, { useCallback, useMemo, useState } from 'react';
import * as sofi from '../../dsm/sofi';
import { decodeBase32Crockford, encodeBase32Crockford } from '../../utils/textId';
import { useWallet } from '../../contexts/WalletContext';
import { Disclosure, Notice, ScreenFrame, ScreenTabs, middleTruncate } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';
import { TokenSelect, type TokenOption } from '../common/TokenSelect';
import { useFx } from '../fx/FxProvider';
import { copyText } from '../../utils/anchorDisplay';

type SofiTab = 'swap' | 'liquidity';

const TABS: ReadonlyArray<{ id: SofiTab; label: string }> = [
  { id: 'swap', label: 'Swap' },
  { id: 'liquidity', label: 'Liquidity' },
];

type Status = { kind: 'info' | 'success' | 'error'; text: string };

function id32(label: string, text: string): Uint8Array {
  const bytes = decodeBase32Crockford(text.trim());
  if (!bytes || bytes.length !== 32) throw new Error(`${label} must be a 32-byte base32 id`);
  return bytes;
}

/** Bytewise order, as the pair is ordered (§28). */
function bytesLess(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return a.length < b.length;
}

function amount(label: string, text: string): bigint {
  const t = text.trim();
  if (!/^\d+$/.test(t)) throw new Error(`${label} must be a whole number of base units`);
  return BigInt(t);
}

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Where a trade, close or resolve left the device's position, in words. */
export function describePosition(r: sofi.PositionResult): string {
  switch (r.state) {
    case 'realized': return `Realized at position ${r.position}`;
    case 'void': return 'Void: another trade won the race; nothing moved';
    case 'invalid': return 'Invalid: the trade does not validate';
    case 'retriesExhausted': return 'Network retries ran out; resolve again later';
  }
}

export default function SofiScreen(): React.JSX.Element {
  const { balances, refreshBalances } = useWallet();
  const fx = useFx();
  const [tab, setTab] = useState<SofiTab>('swap');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status | null>(null);

  // What the pickers offer: the held tokens that carry an anchor. The value is
  // the anchor itself, which is the policy commit SoFi names a token by. A
  // ticker is display only, so each row also carries the anchor's fingerprint:
  // two tokens can share a ticker, never an anchor.
  const tokenOptions: TokenOption[] = useMemo(
    () => balances
      .filter((b) => !!b.policyAnchorB32)
      .map((b) => ({ value: b.policyAnchorB32 as string, ticker: b.symbol, iconUrl: b.iconUrl, note: b.anchorFingerprint })),
    [balances],
  );
  const held = useCallback(
    (anchor: string) => balances.find((b) => b.policyAnchorB32 === anchor) ?? null,
    [balances],
  );
  const nameOf = useCallback(
    (anchor: string) => held(anchor)?.symbol ?? middleTruncate(anchor, 6, 4),
    [held],
  );

  // --- Swap ---
  const [tokenIn, setTokenInState] = useState('');
  const [tokenOut, setTokenOutState] = useState('');
  const [tokenOutAnchor, setTokenOutAnchorState] = useState('');
  const [amountIn, setAmountInState] = useState('');
  const [minOut, setMinOut] = useState('');
  const [quote, setQuote] = useState<sofi.Hop[] | null>(null);

  // A quote is for one set of inputs: any change puts it away.
  const setTokenIn = (v: string) => { setTokenInState(v); setQuote(null); };
  const setTokenOut = (v: string) => { setTokenOutState(v); setQuote(null); };
  const setTokenOutAnchor = (v: string) => { setTokenOutAnchorState(v); setQuote(null); };
  const setAmountIn = (v: string) => { setAmountInState(v); setQuote(null); };
  const effectiveTokenOut = tokenOutAnchor.trim() || tokenOut;
  const inBalance = tokenIn ? held(tokenIn) : null;

  // --- Liquidity ---
  const [tokenA, setTokenA] = useState('');
  const [tokenB, setTokenB] = useState('');
  const [reserveA, setReserveA] = useState('');
  const [reserveB, setReserveB] = useState('');
  const [feeBps, setFeeBps] = useState('30');
  const [createdVault, setCreatedVault] = useState<string | null>(null);
  const [vaultId, setVaultId] = useState('');
  const [relayGenesis, setRelayGenesis] = useState('');
  const [relayDevice, setRelayDevice] = useState('');
  const [relayPosition, setRelayPosition] = useState('');

  const run = useCallback(
    async (what: string, f: () => Promise<string>, kind: 'success' | 'info' = 'success') => {
      setBusy(true);
      setStatus({ kind: 'info', text: `${what}…` });
      try {
        const text = await f();
        setStatus({ kind, text });
        await refreshBalances();
      } catch (e: unknown) {
        setStatus({ kind: 'error', text: `${what} failed: ${messageOf(e)}` });
      } finally {
        setBusy(false);
      }
    },
    [refreshBalances],
  );

  /** The outcome of a position, as a scene and as words. */
  const showPosition = useCallback((what: string, r: sofi.PositionResult, coin?: { ticker: string; iconUrl?: string }): string => {
    const text = describePosition(r);
    if (r.state === 'realized') {
      fx.play({ anim: 'confirm', title: `${what} realized`, caption: `Position ${r.position}`, coin });
    } else if (r.state === 'void') {
      fx.play({ anim: 'trace', title: `${what} void`, caption: text, tone: 'neutral', okLabel: 'OK' });
    } else {
      fx.play({ anim: 'fail', title: `${what} not realized`, caption: text, tone: 'bad', okLabel: 'Back' });
    }
    return text;
  }, [fx]);

  const onQuote = () => run('Quote', async () => {
    const hops = await sofi.findRoute({
      tokenIn: id32('token in', tokenIn),
      tokenOut: id32('token out', effectiveTokenOut),
      amountIn: amount('amount in', amountIn),
    });
    if (hops.length === 0) {
      setQuote(null);
      throw new Error('no liquidity trades between these two tokens');
    }
    setQuote(hops);
    const out = hops[hops.length - 1].amountOut;
    setMinOut(out.toString());
    return `Quoted: ${out.toString()} ${nameOf(effectiveTokenOut)} over ${hops.length} hop${hops.length === 1 ? '' : 's'}`;
  }, 'info');

  const onTrade = () => run('Trade', async () => {
    if (!quote || quote.length === 0) throw new Error('quote first');
    const tin = id32('token in', tokenIn);
    const ain = amount('amount in', amountIn);
    const min = amount('minimum out', minOut);
    const r = quote.length === 1
      ? await sofi.trade({ vaultId: quote[0].vaultId, tokenIn: tin, amountIn: ain, minAmountOut: min })
      : await sofi.route({ vaultIds: quote.map((h) => h.vaultId), tokenIn: tin, amountIn: ain, minAmountOut: min });
    setQuote(null);
    const coin = inBalance ? { ticker: inBalance.symbol, iconUrl: inBalance.iconUrl } : undefined;
    return showPosition('Trade', r, coin);
  });

  const onCreate = () => run('Create liquidity vault', async () => {
    const a = id32('token A', tokenA);
    const b = id32('token B', tokenB);
    // The pair is ordered bytewise (§28); order it for the user.
    const [lo, hi, rLo, rHi] = bytesLess(a, b)
      ? [a, b, amount('reserve A', reserveA), amount('reserve B', reserveB)]
      : [b, a, amount('reserve B', reserveB), amount('reserve A', reserveA)];
    const r = await sofi.createVault({
      tokenA: lo,
      tokenB: hi,
      reserveA: rLo,
      reserveB: rHi,
      feeBps: Number(amount('fee', feeBps)),
    });
    const id = encodeBase32Crockford(r.vaultId);
    setCreatedVault(id);
    setVaultId(id);
    fx.play({
      anim: 'vault',
      title: 'Liquidity vault created',
      caption: `${nameOf(tokenA)} / ${nameOf(tokenB)} · position ${r.position}`,
    });
    return `Vault created: ${id}`;
  });

  const onSetup = () => run('Set up', async () => {
    const r = await sofi.setup(id32('vault', vaultId));
    return `Set up with the vault (position ${r.position})`;
  });

  const onClose = () => run('Close', async () => showPosition('Close', await sofi.close(id32('vault', vaultId))));

  const onResolve = () => run('Resolve', async () => showPosition('Resolve', await sofi.resolve()));

  const onRelay = () => run('Relay', async () => {
    const r = await sofi.relay({
      traderGenesis: id32('trader genesis', relayGenesis),
      traderDeviceId: id32('trader device', relayDevice),
      position: amount('position', relayPosition),
    });
    return `Relayed: ${r.cellsWritten} cell${r.cellsWritten === 1 ? '' : 's'} written`;
  });

  const quoteOut = quote && quote.length > 0 ? quote[quote.length - 1].amountOut : null;

  return (
    <ScreenFrame
      title="SoFi"
      className="sofi-screen"
      info={(
        <InfoTip title="SoFi">
          <p>Sovereign finance: sovereign liquidity and trades that settle between devices, with no exchange in the middle.</p>
          <p><b>Swap</b> trades one token for another through sovereign liquidity at its price. Quote first: you see the exact amount before you confirm. A trade lands at a position, or is void if another trade won the race, and then nothing moved.</p>
          <p>Your fee can increase if the trade needs a hop through a second vault to be secured: each vault takes its own fee. The quote shows it before you confirm.</p>
          <p><b>Liquidity</b> puts two of your tokens into a liquidity vault of your own: sovereign liquidity. Every trade against it pays the fee you set, and you can close it and take the reserves back.</p>
          <p><b>Resolve</b> advances a position this device still has pending, after a trade that did not finish.</p>
        </InfoTip>
      )}
      actions={(
        <button
          type="button"
          className="sb-btn sb-btn--small"
          onClick={onResolve}
          disabled={busy}
          title="Resolve and advance this device's pending position"
        >
          Resolve
        </button>
      )}
      tabs={<ScreenTabs tabs={TABS} active={tab} onChange={setTab} ariaLabel="SoFi sections" />}
      banner={status ? (
        <Notice banner kind={status.kind} onClose={() => setStatus(null)}>{status.text}</Notice>
      ) : null}
    >
      {tab === 'swap' && (
        <div className="swap-tab">
          <section className="sb-card">
            <div className="sb-field">
              <label htmlFor="sofi-amount-in">You pay</label>
              <div className="sb-input-row">
                <input
                  id="sofi-amount-in"
                  type="text"
                  inputMode="numeric"
                  className="sb-input sb-input--mono"
                  placeholder="0"
                  value={amountIn}
                  onChange={(e) => setAmountIn(e.target.value)}
                />
                <TokenSelect
                  label="Token in"
                  className="sb-tokensel--inline"
                  value={tokenIn}
                  options={tokenOptions}
                  onChange={setTokenIn}
                  placeholder="Token"
                />
              </div>
              <div className="sb-hint sb-hint--tight">
                {inBalance
                  ? `Available: ${inBalance.displayAmount} ${inBalance.symbol}. Amounts here are base units (${inBalance.decimals} decimals).`
                  : tokenOptions.length === 0
                    ? 'No token here carries an anchor to trade by yet.'
                    : 'Pick the token you pay with. Amounts are base units.'}
              </div>
            </div>

            <div className="sb-field">
              <label htmlFor="sofi-token-out-anchor">You get</label>
              <TokenSelect
                label="Token out"
                value={tokenOut}
                options={tokenOptions}
                onChange={setTokenOut}
                placeholder="A token you hold…"
              />
              <input
                id="sofi-token-out-anchor"
                type="text"
                className="sb-input sb-input--mono sb-input--small"
                style={{ marginTop: 6 }}
                placeholder="or paste a token's policy anchor"
                aria-label="Token out anchor"
                value={tokenOutAnchor}
                onChange={(e) => setTokenOutAnchor(e.target.value)}
                spellCheck={false}
              />
            </div>

            <button
              type="button"
              className="sb-btn sb-btn--primary sb-btn--block"
              onClick={onQuote}
              disabled={busy || !tokenIn || !effectiveTokenOut || !amountIn.trim()}
            >
              Quote
            </button>
            <p className="sb-hint sb-hint--tight">Your fee can increase if the trade needs a hop to be secured. The quote shows it.</p>
          </section>

          {quote && quoteOut !== null && (
            <section className="sb-card sb-card--dark" aria-label="Quote">
              <div className="sb-card__title">
                <span>Quote</span>
                <span className="sb-tag">{quote.length} hop{quote.length === 1 ? '' : 's'}</span>
              </div>
              <div className="sb-hero__label">You get</div>
              <div className="sb-hero__value">
                {quoteOut.toString()}
                <span className="sb-hero__unit">{nameOf(effectiveTokenOut)}</span>
              </div>
              {quote.map((h, i) => (
                <div className="sb-kv" key={`${encodeBase32Crockford(h.vaultId)}-${i}`}>
                  <span className="sb-kv__k">Hop {i + 1}</span>
                  <span className="sb-kv__v sb-kv__v--mono">
                    {middleTruncate(encodeBase32Crockford(h.vaultId), 8, 6)} · {h.amountIn.toString()} {nameOf(encodeBase32Crockford(h.tokenIn))} → {h.amountOut.toString()} {nameOf(encodeBase32Crockford(h.tokenOut))}
                  </span>
                </div>
              ))}
              <div className="sb-field" style={{ marginTop: 10, marginBottom: 6 }}>
                <label htmlFor="sofi-min-out">Minimum out</label>
                <input
                  id="sofi-min-out"
                  type="text"
                  inputMode="numeric"
                  className="sb-input sb-input--mono"
                  value={minOut}
                  onChange={(e) => setMinOut(e.target.value)}
                />
              </div>
              {quote.length > 1 && <p className="sb-hint sb-hint--tight">Two hops: each vault took its own fee.</p>}
              <p className="sb-hint">A fill below this is refused. Once it lands there is no undo.</p>
              <div className="sb-actions" style={{ margin: 0 }}>
                <button type="button" className="sb-btn" onClick={() => setQuote(null)} disabled={busy}>Cancel</button>
                <button type="button" className="sb-btn sb-btn--primary" onClick={onTrade} disabled={busy || !minOut.trim()}>Trade</button>
              </div>
            </section>
          )}
        </div>
      )}

      {tab === 'liquidity' && (
        <div className="liquidity-tab">
          {createdVault && (
            <section className="sb-card sb-card--dark" role="status" aria-label="Liquidity vault created">
              <div className="sb-card__title">Liquidity vault created</div>
              <div className="sb-kv">
                <span className="sb-kv__k">Vault</span>
                <span className="sb-kv__v sb-kv__v--mono">{createdVault}</span>
              </div>
              <div className="sb-actions" style={{ margin: '8px 0 0' }}>
                <button type="button" className="sb-btn" onClick={() => void copyText(createdVault)}>Copy id</button>
                <button type="button" className="sb-btn sb-btn--primary" onClick={() => setCreatedVault(null)}>OK</button>
              </div>
            </section>
          )}

          <section className="sb-card">
            <div className="sb-card__title">Create a liquidity vault</div>
            <div className="sb-field">
              <label htmlFor="sofi-reserve-a">Token A and its reserve</label>
              <div className="sb-input-row">
                <input
                  id="sofi-reserve-a"
                  type="text"
                  inputMode="numeric"
                  className="sb-input sb-input--mono"
                  placeholder="0"
                  value={reserveA}
                  onChange={(e) => setReserveA(e.target.value)}
                />
                <TokenSelect label="Token A" className="sb-tokensel--inline" value={tokenA} options={tokenOptions} onChange={setTokenA} placeholder="Token" />
              </div>
            </div>
            <div className="sb-field">
              <label htmlFor="sofi-reserve-b">Token B and its reserve</label>
              <div className="sb-input-row">
                <input
                  id="sofi-reserve-b"
                  type="text"
                  inputMode="numeric"
                  className="sb-input sb-input--mono"
                  placeholder="0"
                  value={reserveB}
                  onChange={(e) => setReserveB(e.target.value)}
                />
                <TokenSelect label="Token B" className="sb-tokensel--inline" value={tokenB} options={tokenOptions} onChange={setTokenB} placeholder="Token" />
              </div>
            </div>
            <div className="sb-field">
              <label htmlFor="sofi-fee">Fee, in basis points</label>
              <input
                id="sofi-fee"
                type="text"
                inputMode="numeric"
                className="sb-input sb-input--mono"
                value={feeBps}
                onChange={(e) => setFeeBps(e.target.value)}
              />
            </div>
            <p className="sb-hint">Both reserves leave your balance into the vault, in base units. Every trade against it pays this fee.</p>
            <button
              type="button"
              className="sb-btn sb-btn--primary sb-btn--block"
              onClick={onCreate}
              disabled={busy || !tokenA || !tokenB || !reserveA.trim() || !reserveB.trim() || !feeBps.trim()}
            >
              Create Liquidity Vault
            </button>
          </section>

          <section className="sb-card">
            <div className="sb-card__title">A liquidity vault by id</div>
            <div className="sb-field">
              <label htmlFor="sofi-vault">Vault id</label>
              <input
                id="sofi-vault"
                type="text"
                className="sb-input sb-input--mono"
                placeholder="32-byte base32 id"
                value={vaultId}
                onChange={(e) => setVaultId(e.target.value)}
                spellCheck={false}
              />
            </div>
            <div className="sb-actions" style={{ margin: 0 }}>
              <button type="button" className="sb-btn" onClick={onSetup} disabled={busy || !vaultId.trim()}>Set up</button>
              <button type="button" className="sb-btn" onClick={onClose} disabled={busy || !vaultId.trim()}>Close</button>
            </div>
            <p className="sb-hint sb-hint--tight">Set up once with a liquidity vault before trading against it. Close is for a vault of your own.</p>
          </section>

          <Disclosure summary="Advanced: relay a fulfillment">
            <p className="sb-hint">Complete someone else&apos;s registered fulfillment: their genesis, their device id, and the position.</p>
            <div className="sb-field">
              <label htmlFor="sofi-relay-genesis">Trader genesis</label>
              <input id="sofi-relay-genesis" type="text" className="sb-input sb-input--mono sb-input--small" value={relayGenesis} onChange={(e) => setRelayGenesis(e.target.value)} spellCheck={false} />
            </div>
            <div className="sb-field">
              <label htmlFor="sofi-relay-device">Trader device id</label>
              <input id="sofi-relay-device" type="text" className="sb-input sb-input--mono sb-input--small" value={relayDevice} onChange={(e) => setRelayDevice(e.target.value)} spellCheck={false} />
            </div>
            <div className="sb-field">
              <label htmlFor="sofi-relay-position">Position</label>
              <input id="sofi-relay-position" type="text" inputMode="numeric" className="sb-input sb-input--mono sb-input--small" value={relayPosition} onChange={(e) => setRelayPosition(e.target.value)} />
            </div>
            <button
              type="button"
              className="sb-btn sb-btn--block"
              onClick={onRelay}
              disabled={busy || !relayGenesis.trim() || !relayDevice.trim() || !relayPosition.trim()}
            >
              Relay
            </button>
          </Disclosure>
        </div>
      )}
    </ScreenFrame>
  );
}
