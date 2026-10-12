// SPDX-License-Identifier: Apache-2.0
/**
 * Event-driven gate for DSM bridge calls.
 *
 * - No bridge call runs before the native bridge object is installed.
 * - Bridge calls are serialized (one in flight) so nothing applies out of
 *   order over the shared MessagePort.
 * - No wall-clock time: readiness is observed, never waited for by timer.
 */

export type BridgePrereqState = {
  bridgeReady: boolean;
};

export type GateEvent = { type: 'bridge.ready' };

type Task<T> = {
  run: () => Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
};

export class BridgeGate {
  private prereq: BridgePrereqState = { bridgeReady: false };
  private queue: Task<unknown>[] = [];
  private running = false;
  private idleResolvers: (() => void)[] = [];

  /**
   * Observes once whether the native bridge object is installed
   * (`window.DsmBridge`, bytes-only). Safe to call repeatedly.
   */
  refreshPrereqsOnce(): BridgePrereqState {
    const b = (globalThis as { window?: { DsmBridge?: { __binary?: boolean } } }).window?.DsmBridge;
    const installed = b?.__binary === true;
    if (installed && !this.prereq.bridgeReady) {
      this.onEvent({ type: 'bridge.ready' });
    }
    return { ...this.prereq };
  }

  onEvent(evt: GateEvent): void {
    switch (evt.type) {
      case 'bridge.ready':
        this.prereq.bridgeReady = true;
        break;
    }
    void this.drain();
  }

  /** Enqueue a bridge-bound operation; it runs once the bridge is installed. */
  enqueue<T>(run: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push({ run, resolve: resolve as (v: unknown) => void, reject });
      this.refreshPrereqsOnce();
      void this.drain();
    });
  }

  getState(): BridgePrereqState {
    return { ...this.prereq };
  }

  private async drain(): Promise<void> {
    if (!this.prereq.bridgeReady || this.running) return;
    this.running = true;
    try {
      // Serially: one bridge call in flight over the shared MessagePort.
      while (this.queue.length > 0) {
        const task = this.queue.shift()!;
        await this.executeTask(task);
      }
    } finally {
      this.running = false;
      if (this.queue.length > 0) {
        void this.drain();
      } else {
        const resolvers = this.idleResolvers;
        this.idleResolvers = [];
        for (const r of resolvers) r();
      }
    }
  }

  private async executeTask(task: Task<unknown>): Promise<void> {
    try {
      task.resolve(await task.run());
    } catch (e) {
      task.reject(e);
    }
  }

  /** Resolves once every queued operation has run. */
  async waitForAllOperations(): Promise<void> {
    if (this.queue.length === 0 && !this.running) return;
    return new Promise<void>((resolve) => {
      this.idleResolvers.push(resolve);
    });
  }
}

// Shared singleton gate (one WebView session)
export const bridgeGate = new BridgeGate();
