// SPDX-License-Identifier: Apache-2.0
// path: src/components/screens/SofiScreen.tsx
// SoFi (SoFi §27): create a vault, set up with one, trade, and resolve.
// Tokens and vaults are entered by base32 id; the app sends intent only.

import React, { useCallback, useState } from 'react';
import * as sofi from '../../dsm/sofi';
import { decodeBase32Crockford, encodeBase32Crockford } from '../../utils/textId';
import { useWallet } from '../../contexts/WalletContext';

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
  if (!/^\d+$/.test(t)) throw new Error(`${label} must be a whole number`);
  return BigInt(t);
}

export default function SofiScreen(): React.JSX.Element {
  const { refreshBalances } = useWallet();
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string>('');

  const [tokenA, setTokenA] = useState('');
  const [tokenB, setTokenB] = useState('');
  const [reserveA, setReserveA] = useState('');
  const [reserveB, setReserveB] = useState('');
  const [feeBps, setFeeBps] = useState('30');

  const [vaultId, setVaultId] = useState('');
  const [tokenIn, setTokenIn] = useState('');
  const [amountIn, setAmountIn] = useState('');
  const [minOut, setMinOut] = useState('');

  const run = useCallback(
    async (what: string, f: () => Promise<string>) => {
      setBusy(true);
      setStatus(`${what}…`);
      try {
        setStatus(await f());
        await refreshBalances();
      } catch (e: any) {
        setStatus(`${what} failed: ${e?.message ?? String(e)}`);
      } finally {
        setBusy(false);
      }
    },
    [refreshBalances],
  );

  const describe = (r: sofi.PositionResult) =>
    r.state === 'realized'
      ? `Realized at position ${r.position}`
      : r.state === 'void'
        ? 'Void: another trade won the race; nothing moved'
        : r.state === 'invalid'
          ? 'Invalid: the trade does not validate'
          : 'Network retries ran out; resolve again later';

  return (
    <div className="screen sofi-screen">
      <h2>SoFi</h2>

      <section>
        <h3>Create a vault</h3>
        <input placeholder="token A id" value={tokenA} onChange={(e) => setTokenA(e.target.value)} />
        <input placeholder="token B id" value={tokenB} onChange={(e) => setTokenB(e.target.value)} />
        <input placeholder="reserve A" value={reserveA} onChange={(e) => setReserveA(e.target.value)} />
        <input placeholder="reserve B" value={reserveB} onChange={(e) => setReserveB(e.target.value)} />
        <input placeholder="fee (bps)" value={feeBps} onChange={(e) => setFeeBps(e.target.value)} />
        <button
          disabled={busy}
          onClick={() =>
            run('Create vault', async () => {
              const a = id32('token A', tokenA);
              const b = id32('token B', tokenB);
              // The pair is ordered bytewise (§28); order it for the user.
              const [lo, hi, rLo, rHi] =
                bytesLess(a, b)
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
              setVaultId(id);
              return `Vault created: ${id}`;
            })
          }
        >
          Create
        </button>
      </section>

      <section>
        <h3>Trade</h3>
        <input placeholder="vault id" value={vaultId} onChange={(e) => setVaultId(e.target.value)} />
        <button
          disabled={busy}
          onClick={() =>
            run('Set up', async () => {
              await sofi.setup(id32('vault', vaultId));
              return 'Set up with the vault';
            })
          }
        >
          Set up
        </button>
        <input placeholder="token in id" value={tokenIn} onChange={(e) => setTokenIn(e.target.value)} />
        <input placeholder="amount in" value={amountIn} onChange={(e) => setAmountIn(e.target.value)} />
        <input placeholder="minimum out" value={minOut} onChange={(e) => setMinOut(e.target.value)} />
        <button
          disabled={busy}
          onClick={() =>
            run('Trade', async () =>
              describe(
                await sofi.trade({
                  vaultId: id32('vault', vaultId),
                  tokenIn: id32('token in', tokenIn),
                  amountIn: amount('amount in', amountIn),
                  minAmountOut: amount('minimum out', minOut),
                }),
              ),
            )
          }
        >
          Trade
        </button>
        <button disabled={busy} onClick={() => run('Resolve', async () => describe(await sofi.resolve()))}>
          Resolve
        </button>
      </section>

      {status ? <p className="sofi-status">{status}</p> : null}
    </div>
  );
}
