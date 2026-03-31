/* eslint-disable @typescript-eslint/no-explicit-any */
import { binStringToUint8Array, toUint8Array, uint8ArrayToBinString } from '../binary';

describe('binary helpers', () => {
  it('round-trips Uint8Array <-> bin string', () => {
    const bytes = new Uint8Array([0, 1, 2, 255, 128, 64]);
    const s = uint8ArrayToBinString(bytes);
    const out = binStringToUint8Array(s);
    expect(out).toEqual(bytes);
  });

  it('preserves view offsets when converting ArrayBufferView', () => {
    const backing = new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17]);
    const view = new Uint8Array(backing.buffer, 2, 3); // [12, 13, 14]
    const out = toUint8Array(view);
    expect(out.length).toBe(3);
    expect(Array.from(out)).toEqual([12, 13, 14]);

    const s = uint8ArrayToBinString(out);
    const back = binStringToUint8Array(s);
    expect(Array.from(back)).toEqual([12, 13, 14]);
  });

  it('converts ArrayBuffer to Uint8Array safely', () => {
    const buf = new Uint8Array([7, 8, 9]).buffer;
    const out = toUint8Array(buf);
    expect(out).toEqual(new Uint8Array([7, 8, 9]));
  });
});
