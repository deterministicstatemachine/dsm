// SPDX-License-Identifier: MIT OR Apache-2.0
// Why an identity was not answered. A leaf module: the callers that branch on
// the reason (the wallet store, diagnostics) need the contract, not the
// transport behind `getIdentity`.

/** As the native session and the bridge report it. */
export type IdentityUnavailableState = 'missing' | 'runtime_not_ready' | 'read_failed';

/**
 * The identity was not answered, and why. `missing` is Rust's word (the native
 * session) that this device has no identity: a state, not a failure.
 * `runtime_not_ready` is the native session not reporting ready within the
 * cold-start window; `read_failed` is a session that reports ready whose
 * headers still could not be read. The three used to be one `null`.
 */
export class IdentityUnavailableError extends Error {
  readonly state: IdentityUnavailableState;

  constructor(state: IdentityUnavailableState, message: string) {
    super(message);
    this.name = 'IdentityUnavailableError';
    this.state = state;
  }
}

/** Recognised by shape, so a copy of this module in another registry still counts. */
export function isIdentityUnavailable(e: unknown): e is IdentityUnavailableError {
  return e instanceof Error && e.name === 'IdentityUnavailableError' && typeof (e as { state?: unknown }).state === 'string';
}
