import { decodeFramedEnvelopeV3 } from '../decoding';

function makeGarbageBytes(): Uint8Array {
  return new Uint8Array([0xff, 0x00, 0xab, 0xcd, 0xef, 0x42, 0x13]);
}

describe('decoding worst-case behavior', () => {
  test('decodeFramedEnvelopeV3 throws for garbage bytes', () => {
    const bytes = makeGarbageBytes();
    expect(() => decodeFramedEnvelopeV3(bytes)).toThrow();
  });

  test('decodeFramedEnvelopeV3 enforces minimum framing size', () => {
    const bytes = makeGarbageBytes();
    expect(() => decodeFramedEnvelopeV3(bytes.slice(0, 1))).toThrow(/at least 2 bytes/i);
  });
});
