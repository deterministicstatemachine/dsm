// SPDX-License-Identifier: Apache-2.0
// A picture the owner chose, cut to the shape it is shown in and made small
// enough to keep: the middle of the image, scaled to cover `width` x `height`,
// as a JPEG data URL. Same accepted types and limits as the coin artwork.

import { ACCEPTED_TYPES, MAX_FILE_BYTES, MAX_PIXELS } from './imageRgba';

export async function cropToDataUrl(file: File, width: number, height: number): Promise<string> {
  if (!ACCEPTED_TYPES.includes(file.type)) throw new Error('Choose a PNG, JPEG or WebP image.');
  if (file.size > MAX_FILE_BYTES) throw new Error('Choose an image of at most 5 MB.');
  const url = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    const sw = image.naturalWidth, sh = image.naturalHeight;
    if (!sw || !sh || sw * sh > MAX_PIXELS) throw new Error('Choose an image of at most 16 megapixels.');
    // The largest middle part of the image with the target's shape.
    const scale = Math.max(width / sw, height / sh);
    const cw = width / scale, ch = height / scale;
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext('2d');
    if (!context) throw new Error('Images cannot be read on this device.');
    context.drawImage(image, (sw - cw) / 2, (sh - ch) / 2, cw, ch, 0, 0, width, height);
    return canvas.toDataURL('image/jpeg', 0.85);
  } finally {
    URL.revokeObjectURL(url);
  }
}
