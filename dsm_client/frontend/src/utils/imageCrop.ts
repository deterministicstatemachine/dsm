// SPDX-License-Identifier: Apache-2.0
// A picture the owner chose: read and checked (same accepted types and limits
// as the coin artwork), then the part they framed cut out at the size it is
// kept at, as a JPEG data URL.

import { ACCEPTED_TYPES, MAX_FILE_BYTES, MAX_PIXELS } from './imageRgba';

/** The chosen file as an image, checked against the accepted types and limits; `release` frees it once done. */
export async function loadImageFile(file: File): Promise<{ image: HTMLImageElement; release: () => void }> {
  if (!ACCEPTED_TYPES.includes(file.type)) throw new Error('Choose a PNG, JPEG or WebP image.');
  if (file.size > MAX_FILE_BYTES) throw new Error('Choose an image of at most 5 MB.');
  const url = URL.createObjectURL(file);
  const release = () => URL.revokeObjectURL(url);
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    const pixels = image.naturalWidth * image.naturalHeight;
    if (!pixels || pixels > MAX_PIXELS) throw new Error('Choose an image of at most 16 megapixels.');
    return { image, release };
  } catch (e: unknown) {
    release();
    throw e;
  }
}

/** The region (sx, sy, sw, sh, in the image's own pixels) at `width` x `height`, as a JPEG data URL. */
export function cropRegion(
  image: HTMLImageElement,
  region: { sx: number; sy: number; sw: number; sh: number },
  width: number,
  height: number,
): string {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext('2d');
  if (!context) throw new Error('Images cannot be drawn on this device.');
  context.imageSmoothingQuality = 'high';
  context.drawImage(image, region.sx, region.sy, region.sw, region.sh, 0, 0, width, height);
  return canvas.toDataURL('image/jpeg', 0.85);
}
