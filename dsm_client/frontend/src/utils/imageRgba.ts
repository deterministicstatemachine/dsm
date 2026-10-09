// SPDX-License-Identifier: Apache-2.0

const ACCEPTED_TYPES = ['image/png', 'image/jpeg', 'image/webp'];
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_PIXELS = 16_000_000;

/** Decode an uploaded image to RGBA pixels: PNG, JPEG or WebP, at most 5 MB and 16 megapixels. */
export async function readImageRgba(file: File): Promise<{ rgba: Uint8ClampedArray; width: number; height: number }> {
  if (!ACCEPTED_TYPES.includes(file.type)) throw new Error('Choose a PNG, JPEG or WebP image.');
  if (file.size > MAX_FILE_BYTES) throw new Error('Choose an image of at most 5 MB.');
  const url = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    const width = image.naturalWidth, height = image.naturalHeight;
    if (!width || !height || width * height > MAX_PIXELS) throw new Error('Choose an image of at most 16 megapixels.');
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext('2d');
    if (!context) throw new Error('Images cannot be read on this device.');
    context.drawImage(image, 0, 0);
    return { rgba: context.getImageData(0, 0, width, height).data, width, height };
  } finally {
    URL.revokeObjectURL(url);
  }
}
