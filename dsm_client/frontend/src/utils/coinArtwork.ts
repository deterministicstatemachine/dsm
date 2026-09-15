// SPDX-License-Identifier: Apache-2.0
// Spinning coin artwork for user-created tokens, drawn in the look of the built-in token GIFs
// (public/images/logos/era_token_gb*.gif): a thick, top-lit coin with a raised rim and a milled edge,
// the logo cut through the face so the screen shows through it, a half turn that eases through
// edge-on and then holds face-on, dithered into each theme's colour ramp. Presentation only: nothing
// here takes part in token identity, policy or balances.

import type { ThemeName } from './theme';
import { COIN_RAMPS } from './coinRamps';
import { decodeBase32Crockford, encodeBase32Crockford } from './textId';

/** Side of the square logo mask, in cells. The logo is fitted inside the mask's inscribed circle. */
export const MASK_SIZE = 128;
/** Frames and frame delay of the built-in token GIFs (105 frames at 50 fps). */
export const COIN_FRAMES = 105;
export const COIN_FRAME_DELAY_CS = 2;
/** Rendered GIF side in pixels. The wallet shows token GIFs at 60 CSS px. */
export const COIN_SIZE = 240;

const SHADE_LEVELS = 16;
/** Radius, on the coin face, that the mask's inscribed circle covers (the ERA lettering spans 0.7). */
const LOGO_RADIUS = 0.72;
/** Coin thickness in coin radii, pitch of the view, and the screen half-extent in coin radii. */
const THICKNESS = 0.4;
const PITCH = (4 * Math.PI) / 180;
const VIEW = 1.08;
/** Share of the loop spent turning; the rest holds face-on. */
const TURN_SHARE = 80 / 105;

export interface SilhouetteOptions {
  /** Cut out the background instead of the logo (for a dark logo drawn on a light square, or the reverse). */
  invert?: boolean;
}

/**
 * The logo's silhouette, as MASK_SIZE x MASK_SIZE coverage (0 = coin face, 255 = cut out), fitted so its
 * bounding box sits inside the mask's inscribed circle. Artwork with transparency uses its alpha; opaque
 * artwork uses how far each pixel is from the colour its border shows.
 */
export function silhouetteFromRgba(
  rgba: ArrayLike<number>,
  width: number,
  height: number,
  options: SilhouetteOptions = {},
): Uint8Array {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0 || rgba.length !== width * height * 4) {
    throw new Error('Invalid image data.');
  }
  return fitCoverage(coverageFromRgba(rgba, width, height, options), width, height);
}

/** How much of each pixel is logo, 0 to 1. */
function coverageFromRgba(rgba: ArrayLike<number>, width: number, height: number, options: SilhouetteOptions): Float32Array {
  const count = width * height;
  const coverage = new Float32Array(count);
  let translucent = 0;
  for (let i = 0; i < count; i++) if (rgba[i * 4 + 3] < 128) translucent++;
  if (translucent > count * 0.02) {
    for (let i = 0; i < count; i++) coverage[i] = rgba[i * 4 + 3] / 255;
  } else {
    const bg = borderColour(rgba, width, height);
    const distance = new Float32Array(count);
    let furthest = 0;
    for (let i = 0; i < count; i++) {
      const dr = rgba[i * 4] - bg[0], dg = rgba[i * 4 + 1] - bg[1], db = rgba[i * 4 + 2] - bg[2];
      distance[i] = Math.sqrt(dr * dr + dg * dg + db * db);
      if (distance[i] > furthest) furthest = distance[i];
    }
    if (furthest < 24) throw new Error('The image has no logo that stands out from its background.');
    const low = furthest * 0.2, high = furthest * 0.45;
    for (let i = 0; i < count; i++) coverage[i] = Math.min(1, Math.max(0, (distance[i] - low) / (high - low)));
  }
  if (options.invert) for (let i = 0; i < count; i++) coverage[i] = 1 - coverage[i];

  return coverage;
}

/** Fit the covered area's bounding box inside the mask's inscribed circle and resample it to MASK_SIZE cells. */
function fitCoverage(coverage: Float32Array, width: number, height: number): Uint8Array {
  let x0 = width, y0 = height, x1 = -1, y1 = -1;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if (coverage[y * width + x] >= 0.5) {
        if (x < x0) x0 = x;
        if (x > x1) x1 = x;
        if (y < y0) y0 = y;
        if (y > y1) y1 = y;
      }
    }
  }
  if (x1 < 0) throw new Error('The image has no visible logo.');
  const boxWidth = x1 - x0 + 1, boxHeight = y1 - y0 + 1;
  const scale = MASK_SIZE / 2 / Math.hypot(boxWidth / 2, boxHeight / 2);
  const centreX = x0 + boxWidth / 2, centreY = y0 + boxHeight / 2;
  const mask = new Uint8Array(MASK_SIZE * MASK_SIZE);

  if (scale < 1) {
    // Shrinking: every source pixel lands in one mask cell, and a cell is the mean of what landed in it.
    const sum = new Float32Array(MASK_SIZE * MASK_SIZE);
    const hits = new Uint32Array(MASK_SIZE * MASK_SIZE);
    for (let y = 0; y < height; y++) {
      const my = Math.floor((y + 0.5 - centreY) * scale + MASK_SIZE / 2);
      if (my < 0 || my >= MASK_SIZE) continue;
      for (let x = 0; x < width; x++) {
        const mx = Math.floor((x + 0.5 - centreX) * scale + MASK_SIZE / 2);
        if (mx < 0 || mx >= MASK_SIZE) continue;
        sum[my * MASK_SIZE + mx] += coverage[y * width + x];
        hits[my * MASK_SIZE + mx]++;
      }
    }
    for (let i = 0; i < mask.length; i++) mask[i] = hits[i] ? Math.round((sum[i] / hits[i]) * 255) : 0;
  } else {
    // Enlarging: each mask cell averages four by four samples of the source.
    for (let my = 0; my < MASK_SIZE; my++) {
      for (let mx = 0; mx < MASK_SIZE; mx++) {
        let sum = 0;
        for (let sy = 0; sy < 4; sy++) {
          for (let sx = 0; sx < 4; sx++) {
            const px = Math.floor(centreX + (mx + (sx + 0.5) / 4 - MASK_SIZE / 2) / scale);
            const py = Math.floor(centreY + (my + (sy + 0.5) / 4 - MASK_SIZE / 2) / scale);
            if (px >= 0 && py >= 0 && px < width && py < height) sum += coverage[py * width + px];
          }
        }
        mask[my * MASK_SIZE + mx] = Math.round((sum / 16) * 255);
      }
    }
  }
  return mask;
}

function borderColour(rgba: ArrayLike<number>, width: number, height: number): [number, number, number] {
  const channels: number[][] = [[], [], []];
  const take = (x: number, y: number) => {
    const o = (y * width + x) * 4;
    channels[0].push(rgba[o]);
    channels[1].push(rgba[o + 1]);
    channels[2].push(rgba[o + 2]);
  };
  for (let x = 0; x < width; x++) {
    take(x, 0);
    take(x, height - 1);
  }
  for (let y = 1; y < height - 1; y++) {
    take(0, y);
    take(width - 1, y);
  }
  const median = (values: number[]) => values.sort((a, b) => a - b)[values.length >> 1];
  return [median(channels[0]), median(channels[1]), median(channels[2])];
}

export interface CoinRenderOptions {
  size?: number;
  frames?: number;
}

/** Coin rotation for a frame: a half turn with eased ends, then a face-on hold. Faces read unmirrored on both sides. */
export function coinAngle(frame: number, frames: number): number {
  const turnFrames = Math.max(1, Math.round(frames * TURN_SHARE));
  if (frame >= turnFrames) return Math.PI;
  return (Math.PI / 2) * (1 - Math.cos((Math.PI * frame) / turnFrames));
}

/** Slope of the face relief at radius r: the step up to the rim, a shallow groove in it, and the rounded outer lip. */
function reliefSlope(r: number): number {
  if (r >= 0.76 && r < 0.8) return 3;
  if (r >= 0.89 && r < 0.905) return -2.5;
  if (r >= 0.905 && r < 0.92) return 2.5;
  if (r >= 0.95) return -5;
  return 0;
}

function sampleMask(mask: Uint8Array, u: number, v: number): number {
  const x = u * MASK_SIZE - 0.5, y = v * MASK_SIZE - 0.5;
  const ix = Math.floor(x), iy = Math.floor(y);
  const fx = x - ix, fy = y - iy;
  const at = (cx: number, cy: number) => (cx < 0 || cy < 0 || cx >= MASK_SIZE || cy >= MASK_SIZE ? 0 : mask[cy * MASK_SIZE + cx]);
  const top = at(ix, iy) * (1 - fx) + at(ix + 1, iy) * fx;
  const bottom = at(ix, iy + 1) * (1 - fx) + at(ix + 1, iy + 1) * fx;
  return (top * (1 - fy) + bottom * fy) / 255;
}

function lattice(ix: number, iy: number): number {
  const h = Math.sin(ix * 127.1 + iy * 311.7) * 43758.5453;
  return h - Math.floor(h);
}

function valueNoise(x: number, y: number): number {
  const ix = Math.floor(x), iy = Math.floor(y);
  const fx = x - ix, fy = y - iy;
  const sx = fx * fx * (3 - 2 * fx), sy = fy * fy * (3 - 2 * fy);
  const top = lattice(ix, iy) + (lattice(ix + 1, iy) - lattice(ix, iy)) * sx;
  const bottom = lattice(ix, iy + 1) + (lattice(ix + 1, iy + 1) - lattice(ix, iy + 1)) * sx;
  return top + (bottom - top) * sy;
}

/** Worn metal: blotches, faint streaks and fine mottling at fixed positions, so every render of a logo is identical. */
function wear(x: number, y: number): number {
  return (
    (valueNoise(x * 3.5 + 7, y * 3.5) - 0.5) * 0.08 +
    (valueNoise(x * 12 + 3, y * 3) - 0.5) * 0.04 +
    (valueNoise(x * 24, y * 24 + 11) - 0.5) * 0.05
  );
}

const BAYER = [0.125, 0.625, 0.875, 0.375];

/**
 * One indexed frame per step of the spin: 0 is transparent, 1..16 index the theme ramp from darkest to brightest.
 */
export function renderCoinShades(mask: Uint8Array, options: CoinRenderOptions = {}): Uint8Array[] {
  const size = options.size ?? COIN_SIZE;
  const frames = options.frames ?? COIN_FRAMES;
  if (mask.length !== MASK_SIZE * MASK_SIZE) throw new Error('Invalid logo mask.');
  if (!Number.isInteger(size) || size < 16 || size > 1024 || !Number.isInteger(frames) || frames < 2 || frames > 256) {
    throw new Error('Invalid coin render size.');
  }
  const cp = Math.cos(PITCH), sp = Math.sin(PITCH);
  const halfT = THICKNESS / 2;
  const lightLength = Math.hypot(0, 0.75, 0.66);
  const lx = 0, ly = 0.75 / lightLength, lz = 0.66 / lightLength;
  // The outline is decided per block, which gives the built-in coins their stepped silhouette.
  const block = Math.max(1, Math.round(size / 80));
  const blocks = Math.ceil(size / block);
  const result: Uint8Array[] = [];

  for (let f = 0; f < frames; f++) {
    const theta = coinAngle(f, frames);
    const ct = Math.cos(theta), st = Math.sin(theta);
    // Orthographic ray toward -z in camera space, carried into coin space (yaw about y, then the camera pitch about x).
    const dx = cp * st, dy = -sp, dz = -cp * ct;
    // Object-space normal to camera space (yaw, then pitch), as the lighting term.
    const lit = (nx: number, ny: number, nz: number) => {
      const wx = nx * ct + nz * st, wz = -nx * st + nz * ct;
      const cy = ny * cp - wz * sp, cz = ny * sp + wz * cp;
      const length = Math.hypot(wx, cy, cz) || 1;
      return Math.max(0, (wx * lx + cy * ly + cz * lz) / length);
    };
    // What the ray through screen point (u, v) hits: 0 nothing, 1 front face, 2 back face, 3 edge; the point is hit[1..3].
    const hit = [0, 0, 0, 0];
    const trace = (u: number, v: number): number => {
      const wy = v * cp + 10 * sp, wz = -v * sp + 10 * cp;
      const ox = u * ct - wz * st, oy = wy, oz = u * st + wz * ct;
      let best = Infinity;
      hit[0] = 0;
      if (Math.abs(dz) > 1e-6) {
        for (const face of [halfT, -halfT]) {
          const s = (face - oz) / dz;
          if (s <= 0 || s >= best) continue;
          const x = ox + s * dx, y = oy + s * dy;
          if (x * x + y * y <= 1) {
            best = s;
            hit[0] = face > 0 ? 1 : 2;
            hit[1] = x;
            hit[2] = y;
            hit[3] = face;
          }
        }
      }
      const a = dx * dx + dy * dy;
      if (a > 1e-9) {
        const b = 2 * (ox * dx + oy * dy), c = ox * ox + oy * oy - 1;
        const disc = b * b - 4 * a * c;
        if (disc >= 0) {
          const s = (-b - Math.sqrt(disc)) / (2 * a);
          const z = oz + s * dz;
          if (s > 0 && s < best && Math.abs(z) <= halfT) {
            hit[0] = 3;
            hit[1] = ox + s * dx;
            hit[2] = oy + s * dy;
            hit[3] = z;
          }
        }
      }
      return hit[0];
    };
    const blockCentre = (index: number) => ((index * block + block / 2) * 2) / size - 1;
    const covered = new Uint8Array(blocks * blocks);
    for (let by = 0; by < blocks; by++) {
      for (let bx = 0; bx < blocks; bx++) {
        covered[by * blocks + bx] = trace(blockCentre(bx) * VIEW, -blockCentre(by) * VIEW) === 0 ? 0 : 1;
      }
    }
    const pixels = new Uint8Array(size * size);

    for (let py = 0; py < size; py++) {
      const v = (1 - (2 * (py + 0.5)) / size) * VIEW;
      const falloff = Math.pow(Math.min(1, Math.max(0, v / VIEW + 0.5)), 0.9);
      const by = Math.floor(py / block);
      for (let px = 0; px < size; px++) {
        const bx = Math.floor(px / block);
        if (!covered[by * blocks + bx]) continue;
        let kind = trace(((2 * (px + 0.5)) / size - 1) * VIEW, v);
        // Inside a covered block but just past the true outline: shade it as the block centre.
        if (kind === 0) kind = trace(blockCentre(bx) * VIEW, -blockCentre(by) * VIEW);
        const hx = hit[1], hy = hit[2], hz = hit[3];

        let shade: number;
        if (kind === 3) {
          // Milled edge: ridges tilt the normal along the circumference; the corners round toward the faces.
          const around = Math.atan2(hy, hx);
          const ridge = Math.sin(around * 120) * 0.28;
          const corner = Math.abs(hz) / halfT;
          const nz = corner > 0.8 ? Math.sign(hz) * (corner - 0.8) * 4 : 0;
          shade = 0.5 * lit(hx - ridge * hy, hy + ridge * hx, nz) * falloff + 0.01 + wear(around * 3, hz * 6) * 1.2;
        } else {
          const r = Math.hypot(hx, hy) || 1e-6;
          const slope = reliefSlope(r) * 0.35;
          const side = kind === 1 ? 1 : -1;
          // The back face mirrors x so the logo reads the right way round from behind.
          const faceX = hx * side;
          const cut = sampleMask(mask, 0.5 + faceX / (2 * LOGO_RADIUS), 0.5 - hy / (2 * LOGO_RADIUS));
          if (cut >= 0.5) continue;
          shade = 0.5 * lit((-slope * hx) / r, (-slope * hy) / r, side) * falloff + 0.01 + wear(faceX, hy);
          if (cut > 0.12) {
            // Lit fringe round the cut; brightest where the cut lies above (its wall faces the light).
            const above = sampleMask(mask, 0.5 + faceX / (2 * LOGO_RADIUS), 0.5 - (hy + 0.025) / (2 * LOGO_RADIUS));
            shade += 0.22 * ((cut - 0.12) / 0.38) + (above > cut ? 0.12 : 0);
          }
        }
        const level = Math.floor(Math.min(1, Math.max(0, shade)) * (SHADE_LEVELS - 1) + BAYER[((py & 1) << 1) | (px & 1)]);
        pixels[py * size + px] = 1 + Math.min(SHADE_LEVELS - 1, Math.max(0, level));
      }
    }
    result.push(pixels);
  }
  return result;
}

/** GIF LZW for one frame of indices (minimum code size 5), after the GIF89a reference encoder's code-size rule. */
function lzw(indices: Uint8Array): Uint8Array {
  const minCodeSize = 5;
  const clear = 1 << minCodeSize, end = clear + 1;
  let codeSize = minCodeSize + 1, next = end + 1;
  let table = new Map<number, number>();
  const out: number[] = [];
  let buffer = 0, bits = 0;
  const emit = (code: number) => {
    buffer |= code << bits;
    bits += codeSize;
    while (bits >= 8) {
      out.push(buffer & 0xff);
      buffer >>>= 8;
      bits -= 8;
    }
  };
  emit(clear);
  let current = indices[0];
  for (let i = 1; i < indices.length; i++) {
    const k = indices[i];
    const key = (current << 8) | k;
    const found = table.get(key);
    if (found !== undefined) {
      current = found;
      continue;
    }
    emit(current);
    if (next === 4096) {
      emit(clear);
      table = new Map();
      codeSize = minCodeSize + 1;
      next = end + 1;
    } else {
      if (next >= 1 << codeSize) codeSize++;
      table.set(key, next++);
    }
    current = k;
  }
  emit(current);
  emit(end);
  if (bits > 0) out.push(buffer & 0xff);
  return Uint8Array.from(out);
}

export type CoinGifs = Record<ThemeName, Uint8Array>;

/** One looping GIF per theme. The frames are compressed once; only the colour table differs between themes. */
export function encodeCoinGifs(frames: Uint8Array[], size: number): CoinGifs {
  const body: number[] = [];
  const push = (...values: number[]) => {
    for (const value of values) body.push(value);
  };
  const u16 = (value: number) => push(value & 0xff, value >> 8);
  for (const frame of frames) {
    if (frame.length !== size * size) throw new Error('Invalid coin frame.');
    push(0x21, 0xf9, 4, 0x09); // graphic control: restore to background, index 0 transparent
    u16(COIN_FRAME_DELAY_CS);
    push(0, 0);
    push(0x2c);
    u16(0);
    u16(0);
    u16(size);
    u16(size);
    push(0, 5);
    const data = lzw(frame);
    for (let i = 0; i < data.length; i += 255) {
      const block = data.subarray(i, i + 255);
      push(block.length);
      for (const byte of block) body.push(byte);
    }
    push(0);
  }
  push(0x3b);

  const gifs = {} as CoinGifs;
  for (const theme of Object.keys(COIN_RAMPS) as ThemeName[]) {
    const head: number[] = [];
    for (const c of 'GIF89a') head.push(c.charCodeAt(0));
    head.push(size & 0xff, size >> 8, size & 0xff, size >> 8, 0xf4, 0, 0);
    const ramp = COIN_RAMPS[theme];
    for (let i = 0; i < 32; i++) {
      const colour = i === 0 ? ramp[0] : ramp[i - 1] ?? ramp[ramp.length - 1];
      head.push(colour[0], colour[1], colour[2]);
    }
    head.push(0x21, 0xff, 11);
    for (const c of 'NETSCAPE2.0') head.push(c.charCodeAt(0));
    head.push(3, 1, 0, 0, 0);
    const gif = new Uint8Array(head.length + body.length);
    gif.set(head, 0);
    gif.set(body, head.length);
    gifs[theme] = gif;
  }
  return gifs;
}

/** The logo's spinning coin for every theme. */
export function renderCoinGifs(mask: Uint8Array, options: CoinRenderOptions = {}): CoinGifs {
  const size = options.size ?? COIN_SIZE;
  return encodeCoinGifs(renderCoinShades(mask, { ...options, size }), size);
}

/** Prefix of the canonical coin artwork value carried in a token policy's icon field. */
export const COIN_SOURCE_PREFIX = 'dsm:coin:v1:';
const PACKED_MASK_BYTES = (MASK_SIZE * MASK_SIZE) / 8;

/**
 * The canonical icon value for a logo mask: one bit per cell (cut out where the mask is at least half
 * covered), rows top to bottom, most significant bit first, in Base32 Crockford after the prefix.
 */
export function encodeCoinSource(mask: Uint8Array): string {
  if (mask.length !== MASK_SIZE * MASK_SIZE) throw new Error('Invalid logo mask.');
  const packed = new Uint8Array(PACKED_MASK_BYTES);
  for (let i = 0; i < mask.length; i++) if (mask[i] >= 128) packed[i >> 3] |= 0x80 >> (i & 7);
  return COIN_SOURCE_PREFIX + encodeBase32Crockford(packed);
}

/** The mask a canonical icon value carries; null for anything else (a URL, another format, a damaged or non-canonical value). */
export function decodeCoinSource(iconUrl: string | undefined): Uint8Array | null {
  if (!iconUrl || !iconUrl.startsWith(COIN_SOURCE_PREFIX)) return null;
  const body = iconUrl.slice(COIN_SOURCE_PREFIX.length);
  let packed: Uint8Array;
  try {
    packed = decodeBase32Crockford(body);
  } catch {
    return null;
  }
  if (packed.length !== PACKED_MASK_BYTES || encodeBase32Crockford(packed) !== body) return null;
  const mask = new Uint8Array(MASK_SIZE * MASK_SIZE);
  for (let i = 0; i < mask.length; i++) mask[i] = packed[i >> 3] & (0x80 >> (i & 7)) ? 255 : 0;
  return mask;
}

type Stroke = ReadonlyArray<readonly [number, number]>;
const RING: Stroke = [[1, 0], [3, 0], [4, 1], [4, 5], [3, 6], [1, 6], [0, 5], [0, 1], [1, 0]];
const BOWL: Stroke = [[0, 6], [0, 0], [3, 0], [4, 1], [4, 2], [3, 3], [0, 3]];

/** Ticker glyphs as strokes on a 4 x 6 grid (y down), drawn hollow like ERA's lettering. Built in, so every wallet draws the same shape. */
const GLYPHS: Readonly<Record<string, readonly Stroke[]>> = {
  A: [[[0, 6], [2, 0], [4, 6]], [[1, 4], [3, 4]]],
  B: [[[0, 0], [0, 6], [3, 6], [4, 5], [4, 4], [3, 3], [0, 3]], [[0, 0], [3, 0], [4, 1], [4, 2], [3, 3]]],
  C: [[[4, 0], [1, 0], [0, 1], [0, 5], [1, 6], [4, 6]]],
  D: [[[0, 0], [0, 6], [2, 6], [4, 4], [4, 2], [2, 0], [0, 0]]],
  E: [[[4, 0], [0, 0], [0, 6], [4, 6]], [[0, 3], [3, 3]]],
  F: [[[4, 0], [0, 0], [0, 6]], [[0, 3], [3, 3]]],
  G: [[[4, 1], [3, 0], [1, 0], [0, 1], [0, 5], [1, 6], [3, 6], [4, 5], [4, 3], [2, 3]]],
  H: [[[0, 0], [0, 6]], [[4, 0], [4, 6]], [[0, 3], [4, 3]]],
  I: [[[1, 0], [3, 0]], [[2, 0], [2, 6]], [[1, 6], [3, 6]]],
  J: [[[4, 0], [4, 5], [3, 6], [1, 6], [0, 5]]],
  K: [[[0, 0], [0, 6]], [[4, 0], [0, 3.5]], [[1.5, 2.5], [4, 6]]],
  L: [[[0, 0], [0, 6], [4, 6]]],
  M: [[[0, 6], [0, 0], [2, 3], [4, 0], [4, 6]]],
  N: [[[0, 6], [0, 0], [4, 6], [4, 0]]],
  O: [RING],
  P: [BOWL],
  Q: [RING, [[2.5, 4.5], [4, 6]]],
  R: [BOWL, [[2, 3], [4, 6]]],
  S: [[[4, 1], [3, 0], [1, 0], [0, 1], [0, 2], [1, 3], [3, 3], [4, 4], [4, 5], [3, 6], [1, 6], [0, 5]]],
  T: [[[0, 0], [4, 0]], [[2, 0], [2, 6]]],
  U: [[[0, 0], [0, 5], [1, 6], [3, 6], [4, 5], [4, 0]]],
  V: [[[0, 0], [2, 6], [4, 0]]],
  W: [[[0, 0], [1, 6], [2, 3], [3, 6], [4, 0]]],
  X: [[[0, 0], [4, 6]], [[4, 0], [0, 6]]],
  Y: [[[0, 0], [2, 3], [4, 0]], [[2, 3], [2, 6]]],
  Z: [[[0, 0], [4, 0], [0, 6], [4, 6]]],
  '0': [RING, [[3.5, 0.5], [0.5, 5.5]]],
  '1': [[[1, 1], [2, 0], [2, 6]], [[1, 6], [3, 6]]],
  '2': [[[0, 1], [1, 0], [3, 0], [4, 1], [4, 2], [0, 6], [4, 6]]],
  '3': [[[0, 1], [1, 0], [3, 0], [4, 1], [4, 2], [3, 3], [1.5, 3]], [[3, 3], [4, 4], [4, 5], [3, 6], [1, 6], [0, 5]]],
  '4': [[[3, 6], [3, 0], [0, 4], [4, 4]]],
  '5': [[[4, 0], [0, 0], [0, 3], [3, 3], [4, 4], [4, 5], [3, 6], [0, 6]]],
  '6': [[[4, 0], [1, 0], [0, 1], [0, 5], [1, 6], [3, 6], [4, 5], [4, 4], [3, 3], [0, 3]]],
  '7': [[[0, 0], [4, 0], [1.5, 6]]],
  '8': [[[1, 0], [3, 0], [4, 1], [4, 2], [3, 3], [1, 3], [0, 2], [0, 1], [1, 0]], [[1, 3], [0, 4], [0, 5], [1, 6], [3, 6], [4, 5], [4, 4], [3, 3]]],
  '9': [[[4, 3], [1, 3], [0, 2], [0, 1], [1, 0], [3, 0], [4, 1], [4, 5], [3, 6], [0, 6]]],
};

function segmentDistance(px: number, py: number, ax: number, ay: number, bx: number, by: number): number {
  const vx = bx - ax, vy = by - ay;
  const lengthSq = vx * vx + vy * vy;
  const t = lengthSq === 0 ? 0 : Math.max(0, Math.min(1, ((px - ax) * vx + (py - ay) * vy) / lengthSq));
  return Math.hypot(px - ax - t * vx, py - ay - t * vy);
}

/** The ticker as hollow strokes, fitted like a logo. Null when no character of it can be drawn. */
export function tickerMask(ticker: string): Uint8Array | null {
  const glyphs: (readonly Stroke[])[] = [];
  for (const c of ticker.trim().toUpperCase().slice(0, 8)) {
    const glyph = GLYPHS[c];
    if (glyph) glyphs.push(glyph);
  }
  if (glyphs.length === 0) return null;
  const unit = 12, pad = 12, advance = 6 * unit;
  const outer = 0.62 * unit, inner = 0.2 * unit;
  const width = pad * 2 + (glyphs.length - 1) * advance + 4 * unit;
  const height = pad * 2 + 6 * unit;
  const coverage = new Float32Array(width * height);
  glyphs.forEach((strokes, index) => {
    const left = pad + index * advance;
    const segments: [number, number, number, number][] = [];
    for (const stroke of strokes) {
      for (let i = 1; i < stroke.length; i++) {
        const [ax, ay] = stroke[i - 1], [bx, by] = stroke[i];
        segments.push([left + ax * unit, pad + ay * unit, left + bx * unit, pad + by * unit]);
      }
    }
    const x0 = Math.max(0, Math.floor(left - outer - 1));
    const x1 = Math.min(width - 1, Math.ceil(left + 4 * unit + outer + 1));
    for (let y = 0; y < height; y++) {
      for (let x = x0; x <= x1; x++) {
        let nearest = Infinity;
        for (const [ax, ay, bx, by] of segments) nearest = Math.min(nearest, segmentDistance(x + 0.5, y + 0.5, ax, ay, bx, by));
        if (nearest <= outer && nearest > inner) coverage[y * width + x] = 1;
      }
    }
  });
  return fitCoverage(coverage, width, height);
}

const gifCache = new Map<string, CoinGifs | null>();
const GIF_CACHE_LIMIT = 48;

/**
 * Every theme's coin for a token: the coin artwork its policy carries, otherwise its ticker cut out like
 * ERA's lettering; null when neither can be drawn. Rendered once per (artwork, ticker, size).
 */
export function coinGifsFor(iconUrl: string | undefined, ticker: string, size: number = COIN_SIZE): CoinGifs | null {
  const key = `${size}|${ticker}|${iconUrl ?? ''}`;
  const cached = gifCache.get(key);
  if (cached !== undefined) return cached;
  const mask = decodeCoinSource(iconUrl) ?? tickerMask(ticker);
  const gifs = mask ? renderCoinGifs(mask, { size }) : null;
  if (gifCache.size >= GIF_CACHE_LIMIT) {
    const oldest = gifCache.keys().next();
    if (!oldest.done) gifCache.delete(oldest.value);
  }
  gifCache.set(key, gifs);
  return gifs;
}
