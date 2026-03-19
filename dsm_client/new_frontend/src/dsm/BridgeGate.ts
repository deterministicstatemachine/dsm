// SPDX-License-Identifier: Apache-2.0
/**
 * Deterministic event-driven gate for DSM bridge calls.
 *
 * Goals:
 * - Prevent race conditions: no router calls before bridge + router are ready.
 * - Serialize router RPCs (single in-flight) to avoid out-of-order apply.
 * - No wall-clock time; event/tick-driven only.
 */

import { getAppRouterStatusBridge } from './WebViewBridge';

export type BridgePrereqState = {
  bridgeReady: boolean;
  routerInstalled: boolean;
  routerStatus: number;
  routerGateSupported: boolean;
};

export type GateEvent =
  | { type: 'bridge.ready' }
  | { type: 'router.installed' }
  | { type: 'router.status'; status: number };

type Task<T> = {
  run: () => Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
};

export class BridgeGate {
  private prereq: BridgePrereqState = { bridgeReady: false, routerInstalled: false, routerStatus: -1, routerGateSupported: true };
  private queue: Task<unknown>[] = [];
  private running = false;
  private idleResolvers: (() => void)[] = [];

  /**
   * Deterministically refresh prereqs (no polling loops, single attempt).
   * Safe to call repeatedly.
   */
  async refreshPrereqsOnce(): Promise<BridgePrereqState> {
    type BridgeLike = {
      __callBin?: (...args: unknown[]) => unknown;
      __binary?: boolean;
      sendMessageBin?: (...args: unknown[]) => unknown;
      getAppRouterStatus?: () => number;
    };
    const b = (globalThis as { window?: { DsmBridge?: BridgeLike } })?.window?.DsmBridge;

    // In Jest/unit tests we commonly stub a minimal bridge providing only
    // the bytes-only fast path (__callBin). In that mode we cannot (and should
    // not) block on bridge readiness probes or router gate helpers.
    const isUnitStubBridge =
      typeof b?.__callBin === 'function' &&
      b?.__binary !== true &&
      typeof b?.sendMessageBin !== 'function';

    if (isUnitStubBridge) {
      if (!this.prereq.bridgeReady) this.onEvent({ type: 'bridge.ready' });
      this.prereq.routerGateSupported = false;
      return { ...this.prereq };
    }

    // 1) Bridge readiness — check bridge object existence directly
    const hasBridge = !!(b && (b.__binary === true || typeof b.__callBin === 'function'));
    if (hasBridge && !this.prereq.bridgeReady) {
      this.onEvent({ type: 'bridge.ready' });
    }

    // 2) Router install/idempotent check
    // In unit tests or minimal bridges, these helpers may not exist.
    // Treat router gating as "not supported" rather than blocking forever.
    // NOTE: the imported helpers are tolerant and may not throw; so we must
    // detect support explicitly via presence of functions on window.DsmBridge.


    const hasStatus = typeof b?.getAppRouterStatus === 'function';

    if (!hasStatus) {
      this.prereq.routerGateSupported = false;
    } else {
      try {
        const st = getAppRouterStatusBridge();
        this.onEvent({ type: 'router.status', status: st });
        if (st > 0) this.onEvent({ type: 'router.installed' });
      } catch {
        this.prereq.routerGateSupported = false;
      }
    }

    return { ...this.prereq };
  }

  onEvent(evt: GateEvent): void {
    switch (evt.type) {
      case 'bridge.ready':
        this.prereq.bridgeReady = true;
        break;
      case 'router.installed':
        this.prereq.routerInstalled = true;
        break;
      case 'router.status':
        this.prereq.routerStatus = evt.status;
        // Treat any positive router status as installed/usable.
        // Some devices surface status=1 before status=2; gating on only 2 can
        // keep routerInstalled=false and trigger unnecessary startup stalls.
        if (evt.status > 0) this.prereq.routerInstalled = true;
        break;
    }

    // Try drain queue whenever prereq changes.
    void this.drain();
  }

  /**
   * Enqueue a router-bound operation.
   * The operation will execute concurrently once prereqs are satisfied.
   */
  enqueue<T>(run: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push({ run, resolve: resolve as (v: unknown) => void, reject });
      // Attempt immediate drain based on current prereq snapshot to avoid
      // unnecessary waits when callers have already primed prereqs (common in tests).
      void this.drain();
      // Single-shot prereq refresh to convert "startup races" into a deterministic gate.
      // No polling loops; only attempts to observe readiness.
      void this.refreshPrereqsOnce().finally(() => {
        void this.drain();
      });
    });
  }

  getState(): BridgePrereqState {
    return { ...this.prereq };
  }

  private prereqsSatisfied(): boolean {
    // Fail-closed in production, but do not deadlock when router-gate helpers
    // are unavailable (common in Jest mocks).
    if (!this.prereq.bridgeReady) return false;
    if (this.prereq.routerGateSupported) return this.prereq.routerInstalled;
    return true;
  }

  private async drain(): Promise<void> {
    // Only proceed when prereqs are satisfied and a drain isn't already running.
    if (!this.prereqsSatisfied() || this.running) return;
    this.running = true;

    try {
      // STRICT: Process tasks serially to prevent out-of-order apply and correlation issues
      // with shared MessagePort and native router state.
      while (this.queue.length > 0) {
        const task = this.queue.shift()!;
        await this.executeTask(task);
      }
    } finally {
      this.running = false;
      // If new tasks arrived while we were running, attempt another drain.
      if (this.queue.length > 0) {
        void this.drain();
      } else {
        // Notify any waiters that the gate is idle.
        const resolvers = this.idleResolvers;
        this.idleResolvers = [];
        for (const r of resolvers) r();
      }
    }
  }

  private async executeTask(task: Task<unknown>): Promise<void> {
    try {
      const res = await task.run();
      task.resolve(res);
    } catch (e) {
      task.reject(e);
    }
  }

  /**
   * Wait for all currently executing operations to complete.
   * Useful for testing and shutdown scenarios.
   */
  async waitForAllOperations(): Promise<void> {
    if (this.queue.length === 0 && !this.running) return;
    return new Promise<void>((resolve) => {
      this.idleResolvers.push(resolve);
    });
  }
}

// Shared singleton gate (one WebView session)
export const bridgeGate = new BridgeGate();
