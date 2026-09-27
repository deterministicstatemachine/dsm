// SPDX-License-Identifier: MIT OR Apache-2.0

import { bridgeEvents } from '../bridge/bridgeEvents';

export type DeterministicSafetyDetail = {
  classification: string;
  message: string;
};

/** Rust's source tag on `DsmError::DeterministicSafety` (`dsm_sdk/src/wire/mod.rs`). */
export const DETERMINISTIC_SAFETY_SOURCE_TAG = 11;

/** The wire `Error` fields this reads. */
export type WireErrorLike = {
  sourceTag: number;
  message: string;
  context: Uint8Array;
};

/**
 * A deterministic-safety refusal is what Rust tagged as one, never what a message
 * happens to say. Rust's context for that error is
 * `classification=<Class> message=<text>`; the class is read from there.
 */
export function deterministicSafetyFromError(err: WireErrorLike): DeterministicSafetyDetail | null {
  if (err.sourceTag !== DETERMINISTIC_SAFETY_SOURCE_TAG) return null;
  const context = new TextDecoder().decode(err.context);
  const match = context.match(/^classification=(\S+) message=([\s\S]*)$/);
  if (!match) return { classification: '', message: err.message };
  return { classification: match[1], message: match[2] };
}

export function emitDeterministicSafetyForError(err: WireErrorLike): boolean {
  const detail = deterministicSafetyFromError(err);
  if (!detail) return false;
  try {
    bridgeEvents.emit('dsm.deterministicSafety', detail);
  } catch {
    // a listener's failure is its own
  }
  return true;
}
