/* eslint-disable @typescript-eslint/no-explicit-any, no-console */
import { nativeSessionStore } from '../runtime/nativeSessionStore';

/**
 * Three-state identity result.
 * - READY: Identity exists and is fully initialized
 * - NO_IDENTITY: No persisted identity (safe to show genesis flow)
 * - RUNTIME_NOT_READY: Bridge/router not warmed up yet (do NOT allow genesis)
 */
export type IdentityState = 'READY' | 'NO_IDENTITY' | 'RUNTIME_NOT_READY';

/**
 * Check identity state with proper 3-state logic.
 * This prevents accidental genesis creation when the runtime is not ready.
 */
export async function checkIdentityState(): Promise<IdentityState> {
  try {
    const session = nativeSessionStore.getSnapshot();
    if (!session.received || session.identity_status === 'runtime_not_ready') {
      return 'RUNTIME_NOT_READY';
    }
    if (session.identity_status === 'ready') {
      return 'READY';
    }
    if (session.identity_status === 'missing') {
      return 'NO_IDENTITY';
    }
    return 'RUNTIME_NOT_READY';
  } catch (e) {
    console.warn('[checkIdentityState] Error checking identity:', e);
    return 'RUNTIME_NOT_READY';
  }
}

/** Returns true only if identity is READY.
 * Superseded by checkIdentityState() for proper 3-state handling.
 */
export async function hasIdentity(): Promise<boolean> {
  const state = await checkIdentityState();
  return state === 'READY';
}
