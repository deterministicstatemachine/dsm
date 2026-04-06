// SPDX-License-Identifier: Apache-2.0
import { SFX_FILE_MAP, type SfxKey } from '../audio';

describe('audio SFX_FILE_MAP', () => {
  const keys = Object.keys(SFX_FILE_MAP) as SfxKey[];

  it('maps every SfxKey to a non-empty filename where defined', () => {
    for (const k of keys) {
      const name = SFX_FILE_MAP[k];
      expect(name).toBeTruthy();
      expect(name!.length).toBeGreaterThan(0);
      expect(name).toMatch(/\.(mp3|ogg|wav)$/i);
    }
  });

  it('covers all logical dpad and button keys', () => {
    expect(SFX_FILE_MAP['dpad-up']).toBe('dpad_up.mp3');
    expect(SFX_FILE_MAP['button-a']).toBe('button_a.mp3');
    expect(SFX_FILE_MAP.start).toBe('start.mp3');
    expect(SFX_FILE_MAP.select).toBe('select.mp3');
  });
});
