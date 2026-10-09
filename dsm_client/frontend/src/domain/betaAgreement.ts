// SPDX-License-Identifier: Apache-2.0
// What a new user agrees to before using this pre-release wallet. Each point
// is ticked on its own; the agreement is kept under its version, so changing
// the points asks everyone again. Plain-language acknowledgements, to be
// reviewed by counsel before a public release.

/** Bump when the points change: everyone is asked again. */
export const AGREEMENT_VERSION = 'beta-agreement-2026-10-09';

export const AGREEMENT_POINTS: readonly { id: string; text: string }[] = [
  {
    id: 'experimental',
    text: 'This is experimental pre-release software. It can have bugs, change without notice, or stop working.',
  },
  {
    id: 'no_value',
    text: 'Tokens in this wallet, ERA and dBTC included, have no real-world value during the beta.',
  },
  {
    id: 'no_real_crypto',
    text: 'I will not send real Bitcoin, real cryptocurrency, or anything of value to this wallet. Anything of value sent to it may be lost for good.',
  },
  {
    id: 'resets',
    text: 'Balances, tokens, contacts and history can be reset or lost during the beta.',
  },
  {
    id: 'recovery',
    text: 'My recovery phrase is the only way to restore my wallet. If I lose it, nobody, the DSM team included, can restore the wallet for me.',
  },
  {
    id: 'no_advice',
    text: 'Nothing in this app is financial, investment, legal or tax advice.',
  },
  {
    id: 'own_risk',
    text: 'The software is provided as is, without warranty of any kind, and I use it at my own risk.',
  },
];
