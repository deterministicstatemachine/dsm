// SPDX-License-Identifier: Apache-2.0
//! Display amounts are carried, not computed.
//!
//! This file used to test a hardcoded decimals table and bigint conversion
//! helpers living in TypeScript. Both are deleted. The table listed dBTC and
//! BTC at 8 decimals and answered 0 for everything else, so a CPTA token
//! created with 2 decimals rendered as whole units in the transfer dialog, the
//! transaction list and contact history — 25000 where the protocol moved
//! 250.00. It could not have been otherwise: the table could not know about
//! tokens created after it was written.
//!
//! Rust owns the conversion in both directions and every amount-bearing wire
//! message now carries its rendered form. What is left here is presentation.

import { presentDisplayAmount, presentSignedDisplayAmount } from '../tokenMeta';

describe('presentDisplayAmount', () => {
  it('prints what Rust rendered', () => {
    expect(presentDisplayAmount('1000.00', 100000n)).toBe('1000.00');
  });

  it('does not second-guess a rendering it disagrees with', () => {
    // The base units are the authority for VALUE; the string is the authority
    // for DISPLAY. If they ever diverge that is a Rust bug to fix at the
    // source, not something to paper over by recomputing here.
    expect(presentDisplayAmount('0.50', 100000n)).toBe('0.50');
  });

  it('falls back to base units rather than inventing a scale', () => {
    expect(presentDisplayAmount(undefined, 100000n)).toBe('100000');
    expect(presentDisplayAmount('', 42n)).toBe('42');
  });
});

describe('presentSignedDisplayAmount', () => {
  it('prints the signed string Rust rendered', () => {
    expect(presentSignedDisplayAmount('-250.00', -25000n)).toBe('-250.00');
    expect(presentSignedDisplayAmount('250.00', 25000n)).toBe('250.00');
  });

  it('keeps the sign when falling back', () => {
    expect(presentSignedDisplayAmount(undefined, -25000n)).toBe('-25000');
    expect(presentSignedDisplayAmount(undefined, 25000n)).toBe('25000');
    expect(presentSignedDisplayAmount(undefined, 0n)).toBe('0');
  });
});
