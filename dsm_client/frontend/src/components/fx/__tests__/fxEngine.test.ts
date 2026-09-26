// SPDX-License-Identifier: Apache-2.0
import { FX_ENGINE_SRC, fxAmountLabel, isFxEngineReady, loadFxEngine, setFxMuted } from '../fxEngine';

describe('fxEngine', () => {
  afterEach(() => {
    document.querySelectorAll('script[data-fx-engine]').forEach((el) => el.remove());
  });

  it('injects the engine script once, from the app assets', async () => {
    const promise = loadFxEngine(50);
    const scripts = document.querySelectorAll('script[data-fx-engine]');
    expect(scripts).toHaveLength(1);
    expect(scripts[0].getAttribute('src')).toBe(FX_ENGINE_SRC);

    void loadFxEngine(50);
    expect(document.querySelectorAll('script[data-fx-engine]')).toHaveLength(1);

    // jsdom does not execute the script, so the element never registers.
    await expect(promise).resolves.toBe(false);
    expect(isFxEngineReady()).toBe(false);
  });

  it('mirrors the sound setting onto the engine-wide mute flag', () => {
    setFxMuted(true);
    expect(window.STATEBOY_MUTED).toBe(true);
    setFxMuted(false);
    expect(window.STATEBOY_MUTED).toBe(false);
  });

  it('signs and clamps amount captions for the 17-column dialog', () => {
    expect(fxAmountLabel('12.5 ERA', '+')).toBe('+12.5 ERA');
    expect(fxAmountLabel('12.5 ERA', '-')).toBe('-12.5 ERA');
    expect(fxAmountLabel('-3 ERA', '+')).toBe('-3 ERA');
    expect(fxAmountLabel('  ')).toBeUndefined();
    expect(fxAmountLabel(undefined)).toBeUndefined();
    expect(fxAmountLabel('123456789012345678901 TOKEN', '+')).toHaveLength(17);
  });
});
