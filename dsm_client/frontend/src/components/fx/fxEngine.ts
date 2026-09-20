// SPDX-License-Identifier: Apache-2.0
/**
 * StateBoy FX engine bridge.
 *
 * The engine is a plain web component (`<fx-canvas>`) shipped as a static
 * asset under public/images/animations/animations/. It is not bundled; this
 * module injects it once on demand and mirrors the app's sound setting into
 * the engine's global mute flag.
 */

export const FX_ENGINE_SRC = 'images/animations/animations/fx-canvas.js';

/** Scene names the engine knows. */
export type FxAnim =
  | 'confirm'
  | 'fail'
  | 'intro'
  | 'trace'
  | 'lock'
  | 'vault'
  | 'pair'
  | 'tamper'
  | 'seal';

export const FX_ANIMS: readonly FxAnim[] = [
  'confirm',
  'fail',
  'intro',
  'trace',
  'lock',
  'vault',
  'pair',
  'tamper',
  'seal',
];

declare global {
  interface Window {
    /** Engine-wide mute flag read by every fx-canvas instance. */
    STATEBOY_MUTED?: boolean;
    /** Optional override for the directory the engine loads its sprites from. */
    STATEBOY_FX_BASE?: string;
    StateBoyFX?: {
      play: (name: string, opts?: { amount?: string }) => void;
      list: () => string[];
      mute: (muted: boolean) => void;
    };
  }
}

let pending: Promise<boolean> | null = null;

/** True once the engine has registered the `fx-canvas` element. */
export function isFxEngineReady(): boolean {
  return typeof customElements !== 'undefined' && Boolean(customElements.get('fx-canvas'));
}

/**
 * Loads the engine script once. Resolves true when `fx-canvas` is defined,
 * false when the script failed or did not register within `timeoutMs`.
 * Elements rendered before the script lands are upgraded by the browser, so
 * callers need not wait for this before rendering `<fx-canvas>`.
 */
export function loadFxEngine(timeoutMs = 8000): Promise<boolean> {
  if (isFxEngineReady()) return Promise.resolve(true);
  if (pending) return pending;
  pending = new Promise<boolean>((resolve) => {
    if (typeof document === 'undefined') {
      resolve(false);
      return;
    }
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined = undefined;
    const done = () => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      const ok = isFxEngineReady();
      if (!ok) pending = null; // allow a later retry
      resolve(ok);
    };
    const existing = document.querySelector<HTMLScriptElement>('script[data-fx-engine]');
    const script = existing ?? document.createElement('script');
    script.addEventListener('load', done, { once: true });
    script.addEventListener('error', done, { once: true });
    timer = setTimeout(done, timeoutMs);
    if (!existing) {
      script.async = true;
      script.dataset.fxEngine = '1';
      script.src = FX_ENGINE_SRC;
      (document.head || document.body || document.documentElement).appendChild(script);
    }
  });
  return pending;
}

/** Mirrors the app's sound toggle into the engine (SFX are 8-bit tones). */
export function setFxMuted(muted: boolean): void {
  if (typeof window === 'undefined') return;
  window.STATEBOY_MUTED = muted;
}

/** Clamp a caption for the engine's 17-column dialog box. */
export function fxAmountLabel(amount: string | undefined, sign?: '+' | '-'): string | undefined {
  const raw = (amount ?? '').trim();
  if (!raw) return undefined;
  const text = sign && !/^[+-]/.test(raw) ? `${sign}${raw}` : raw;
  return text.length > 17 ? text.slice(0, 17) : text;
}
