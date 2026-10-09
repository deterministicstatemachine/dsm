// SPDX-License-Identifier: Apache-2.0
import {
  COIN_FRAMES,
  COIN_FRAME_DELAY_CS,
  COIN_SOURCE_PREFIX,
  MASK_SIZE,
  coinAngle,
  coinGifsFor,
  decodeCoinSource,
  encodeCoinGifs,
  encodeCoinSource,
  renderCoinShades,
  silhouetteFromRgba,
  tickerMask,
} from '../coinArtwork';
import { COIN_RAMPS } from '../coinRamps';
import { encodeBase32Crockford } from '../textId';
import { getAvailableThemes } from '../theme';

/** A GIF89a reader written from the format, independent of the encoder under test. */
function readGif(gif: Uint8Array) {
  let at = 0;
  const byte = () => gif[at++];
  const u16 = () => byte() | (byte() << 8);
  const ascii = (n: number) => String.fromCharCode(...gif.slice(at, (at += n)));
  const subBlocks = () => {
    const out: number[] = [];
    for (let size = byte(); size > 0; size = byte()) for (let i = 0; i < size; i++) out.push(byte());
    return out;
  };
  expect(ascii(6)).toBe('GIF89a');
  const width = u16(), height = u16(), packed = byte();
  byte();
  byte();
  const palette: number[][] = [];
  if (packed & 0x80) for (let i = 0; i < 1 << ((packed & 7) + 1); i++) palette.push([byte(), byte(), byte()]);
  const frames: Uint8Array[] = [];
  const delays: number[] = [];
  const transparent: number[] = [];
  let loops = false;
  for (;;) {
    const kind = byte();
    if (kind === 0x3b) break;
    if (kind === 0x21) {
      const label = byte();
      if (label === 0xf9) {
        byte();
        const flags = byte();
        delays.push(u16());
        const index = byte();
        transparent.push(flags & 1 ? index : -1);
        byte();
      } else if (label === 0xff) {
        byte();
        loops = ascii(11) === 'NETSCAPE2.0';
        subBlocks();
      } else {
        subBlocks();
      }
    } else if (kind === 0x2c) {
      u16();
      u16();
      const w = u16(), h = u16();
      byte();
      const minCodeSize = byte();
      frames.push(lzwDecode(Uint8Array.from(subBlocks()), minCodeSize, w * h));
    } else {
      throw new Error(`unexpected block 0x${kind.toString(16)}`);
    }
  }
  return { width, height, palette, frames, delays, transparent, loops };
}

function lzwDecode(data: Uint8Array, minCodeSize: number, pixels: number): Uint8Array {
  const clear = 1 << minCodeSize, end = clear + 1;
  let codeSize = minCodeSize + 1;
  let table: number[][] = [];
  const reset = () => {
    table = [];
    for (let i = 0; i < clear; i++) table.push([i]);
    table.push([], []);
    codeSize = minCodeSize + 1;
  };
  reset();
  const out: number[] = [];
  let bit = 0;
  let previous: number[] | null = null;
  for (;;) {
    let code = 0;
    for (let i = 0; i < codeSize; i++, bit++) {
      if (bit >> 3 >= data.length) throw new Error('truncated LZW data');
      code |= ((data[bit >> 3] >> (bit & 7)) & 1) << i;
    }
    if (code === clear) {
      reset();
      previous = null;
      continue;
    }
    if (code === end) break;
    let entry: number[];
    if (code < table.length) entry = table[code];
    else if (code === table.length && previous) entry = [...previous, previous[0]];
    else throw new Error(`invalid LZW code ${code}`);
    out.push(...entry);
    if (previous && table.length < 4096) table.push([...previous, entry[0]]);
    previous = entry;
    if (table.length === 1 << codeSize && codeSize < 12) codeSize++;
  }
  expect(out.length).toBe(pixels);
  return Uint8Array.from(out);
}

const cutCells = (mask: Uint8Array) => mask.reduce((n, v) => n + (v >= 128 ? 1 : 0), 0);
const binary = (mask: Uint8Array) => Uint8Array.from(mask, (v) => (v >= 128 ? 255 : 0));

describe('coin artwork source (the policy icon value)', () => {
  it('round-trips a mask through its canonical one-bit form', () => {
    const mask = tickerMask('ERA')!;
    const source = encodeCoinSource(mask);
    expect(source.startsWith(COIN_SOURCE_PREFIX)).toBe(true);
    expect(source.length - COIN_SOURCE_PREFIX.length).toBe(Math.ceil((MASK_SIZE * MASK_SIZE) / 8 * 8 / 5));
    expect(decodeCoinSource(source)).toEqual(binary(mask));
  });

  it('refuses every value that is not canonical coin artwork', () => {
    const body = encodeCoinSource(tickerMask('GOLD')!).slice(COIN_SOURCE_PREFIX.length);
    expect(decodeCoinSource(undefined)).toBeNull();
    expect(decodeCoinSource('')).toBeNull();
    expect(decodeCoinSource('https://example.com/icon.png')).toBeNull();
    expect(decodeCoinSource(COIN_SOURCE_PREFIX)).toBeNull();
    // One byte short of a mask.
    expect(decodeCoinSource(COIN_SOURCE_PREFIX + encodeBase32Crockford(new Uint8Array(MASK_SIZE * MASK_SIZE / 8 - 1)))).toBeNull();
    // Lower case decodes to the same bytes, but it is not the canonical spelling.
    expect(decodeCoinSource(COIN_SOURCE_PREFIX + body.toLowerCase())).toBeNull();
    expect(decodeCoinSource(COIN_SOURCE_PREFIX + body.slice(0, -1) + 'U')).toBeNull();
    expect(decodeCoinSource('dsm:coin:v2:' + body)).toBeNull();
  });
});

describe('ticker lettering', () => {
  it('draws every ticker character, the same way every time', () => {
    for (const c of 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') {
      const mask = tickerMask(c);
      expect(mask).not.toBeNull();
      expect(cutCells(mask!)).toBeGreaterThan(50);
    }
    expect(tickerMask('era')).toEqual(tickerMask('ERA'));
    expect(tickerMask('RIGB8')).toEqual(tickerMask('RIGB8'));
    expect(tickerMask('ERA')).not.toEqual(tickerMask('ARE'));
  });

  it('has no coin for a ticker with nothing to draw', () => {
    expect(tickerMask('')).toBeNull();
    expect(tickerMask('$%')).toBeNull();
  });
});

describe('logo silhouette', () => {
  const image = (width: number, height: number, paint: (x: number, y: number) => [number, number, number, number]) => {
    const rgba = new Uint8ClampedArray(width * height * 4);
    for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) rgba.set(paint(x, y), (y * width + x) * 4);
    return rgba;
  };
  const square = (x: number, y: number) => x >= 20 && x < 60 && y >= 20 && y < 60;

  it('cuts out a logo drawn on a plain background, and the same logo on transparency', () => {
    const opaque = silhouetteFromRgba(image(80, 80, (x, y) => (square(x, y) ? [20, 20, 20, 255] : [250, 250, 250, 255])), 80, 80);
    const clear = silhouetteFromRgba(image(80, 80, (x, y) => (square(x, y) ? [200, 40, 40, 255] : [0, 0, 0, 0])), 80, 80);
    expect(binary(opaque)).toEqual(binary(clear));
    // The box is fitted inside the mask's inscribed circle: its centre is cut, the corners are not.
    const centre = (MASK_SIZE / 2) * MASK_SIZE + MASK_SIZE / 2;
    expect(opaque[centre]).toBe(255);
    expect(opaque[0]).toBe(0);
    expect(opaque[MASK_SIZE * MASK_SIZE - 1]).toBe(0);
  });

  it('can cut out the background instead, and refuses an image with no logo', () => {
    const rgba = image(80, 80, (x, y) => (square(x, y) ? [20, 20, 20, 255] : [250, 250, 250, 255]));
    expect(binary(silhouetteFromRgba(rgba, 80, 80, { invert: true }))).not.toEqual(binary(silhouetteFromRgba(rgba, 80, 80)));
    expect(() => silhouetteFromRgba(image(20, 20, () => [128, 128, 128, 255]), 20, 20)).toThrow(/stands out/);
    expect(() => silhouetteFromRgba(new Uint8ClampedArray(10), 2, 2)).toThrow(/Invalid image/);
  });
});

describe('coin render', () => {
  it('eases through edge-on to the back face and holds there', () => {
    const turn = Math.round(COIN_FRAMES * (80 / 105));
    expect(coinAngle(0, COIN_FRAMES)).toBe(0);
    expect(coinAngle(turn / 2, COIN_FRAMES)).toBeCloseTo(Math.PI / 2, 5);
    for (let f = turn; f < COIN_FRAMES; f++) expect(coinAngle(f, COIN_FRAMES)).toBe(Math.PI);
  });

  it('cuts the logo through the face and reads the right way round from behind', () => {
    const frames = renderCoinShades(tickerMask('L')!, { size: 64, frames: 21 });
    expect(frames).toHaveLength(21);
    const first = frames[0], last = frames[20];
    expect(first[0]).toBe(0); // outside the coin
    expect(first.some((v) => v > 0)).toBe(true);
    const holes = (frame: Uint8Array) => {
      // Transparent cells inside the coin's face, i.e. the cut-out.
      const out: number[] = [];
      for (let y = 16; y < 48; y++) for (let x = 16; x < 48; x++) if (frame[y * 64 + x] === 0) out.push(y * 64 + x);
      return out;
    };
    expect(holes(first).length).toBeGreaterThan(20);
    // The hold shows the back face; an L that read mirrored there would not line up with the front.
    expect(holes(last)).toEqual(holes(first));
  });
});

describe('coin GIFs', () => {
  it('decode, in every theme, to exactly the rendered frames in that theme\'s colours', () => {
    const shades = renderCoinShades(tickerMask('ERA')!, { size: 32, frames: 6 });
    const gifs = encodeCoinGifs(shades, 32);
    expect(Object.keys(gifs).sort()).toEqual([...getAvailableThemes()].sort());
    for (const theme of getAvailableThemes()) {
      const gif = readGif(gifs[theme]);
      expect([gif.width, gif.height]).toEqual([32, 32]);
      expect(gif.loops).toBe(true);
      expect(gif.frames).toEqual(shades);
      expect(gif.delays.every((d) => d === COIN_FRAME_DELAY_CS)).toBe(true);
      expect(gif.transparent.every((t) => t === 0)).toBe(true);
      expect(gif.palette.slice(1, 17)).toEqual(COIN_RAMPS[theme].map((c) => [...c]));
    }
  });

  it('keep a frame intact across a full LZW dictionary', () => {
    const shades = renderCoinShades(tickerMask('DSM')!, { size: 160, frames: 2 });
    const gif = readGif(encodeCoinGifs(shades, 160).stateboy);
    expect(gif.frames).toEqual(shades);
  });

  it('draw policy artwork when there is some, the ticker when not, and nothing for neither', () => {
    const artwork = encodeCoinSource(tickerMask('XY')!);
    const withArtwork = coinGifsFor(artwork, 'ERA', 24);
    const withTicker = coinGifsFor(undefined, 'ERA', 24);
    expect(withArtwork).not.toBeNull();
    expect(withTicker).not.toBeNull();
    expect(withArtwork!.stateboy).not.toEqual(withTicker!.stateboy);
    // A URL or a damaged value is not artwork: the ticker is drawn.
    expect(coinGifsFor('https://example.com/icon.png', 'ERA', 24)!.stateboy).toEqual(withTicker!.stateboy);
    expect(coinGifsFor(undefined, 'ERA', 24)).toBe(withTicker);
    expect(coinGifsFor(undefined, '$%', 24)).toBeNull();
  });
});
