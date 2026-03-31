/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/storage/objectPreviewService.ts
// SPDX-License-Identifier: Apache-2.0
// Object preview helpers (binary/text) for storage UI.

export type ObjectPreview =
  | { kind: 'binary'; size: number; hexPreview: string }
  | { kind: 'text'; size: number; textPreview: string };

export function buildObjectPreview(data: Uint8Array, contentType?: string): ObjectPreview {
  const size = data.length;
  const isBinary = contentType?.includes('protobuf') || contentType?.includes('application/octet-stream');
  if (isBinary) {
    const hexPreview = Array.from(data.slice(0, 64))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ') + (size > 64 ? '…' : '');
    return { kind: 'binary', size, hexPreview };
  }

  try {
    const decoder = new TextDecoder('utf-8');
    const text = decoder.decode(data);
    const textPreview = text.slice(0, 2000) + (text.length > 2000 ? '\n... (truncated)' : '');
    return { kind: 'text', size, textPreview };
  } catch {
    const hexPreview = Array.from(data.slice(0, 64))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ') + (size > 64 ? '…' : '');
    return { kind: 'binary', size, hexPreview };
  }
}
