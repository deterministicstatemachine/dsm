/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/storage/objectBrowserService.ts
// SPDX-License-Identifier: Apache-2.0
// Storage object browser helpers to keep binary handling out of UI.

import { storageNodeService } from '../storageNodeService';
import { buildObjectPreview, type ObjectPreview } from './objectPreviewService';

export async function fetchObjectForBrowser(key: string): Promise<{
  blob: Blob;
  contentType?: string;
  preview: ObjectPreview;
} | null> {
  const result = await storageNodeService.getObject(key);
  if (!result) return null;
  const preview = buildObjectPreview(result.data, result.contentType);
  const blob = new Blob([result.data as any], { type: result.contentType ?? 'application/octet-stream' });
  return { blob, contentType: result.contentType, preview };
}
