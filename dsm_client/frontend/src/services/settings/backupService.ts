/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/settings/backupService.ts
// SPDX-License-Identifier: Apache-2.0
// Backup import/export helpers to keep binary handling out of UI.

export interface BackupClient {
  exportStateBackup?: () => Promise<Uint8Array | ArrayBuffer | Blob | string>;
  importStateBackup?: (backup: Uint8Array) => Promise<{ success: boolean; message?: string }>;
}

export async function exportStateBackupFile(client: BackupClient): Promise<{
  ok: boolean;
  blob?: Blob;
  filename?: string;
  message?: string;
}> {
  if (typeof client.exportStateBackup === 'function') {
    const backupBlob = await client.exportStateBackup();
    const blob = new Blob([backupBlob as any], { type: 'application/octet-stream' });
    return { ok: true, blob, filename: 'dsm-backup.bin', message: 'Backup exported successfully' };
  }

  const mod = await import('../../dsm/index');
  const path = typeof mod.createBackup === 'function' ? await mod.createBackup() : '';
  if (path) return { ok: true, message: `Backup created at ${path}` };
  return { ok: false, message: 'Backup export not supported on this build' };
}

export async function importStateBackupFile(client: BackupClient, file: File): Promise<{ ok: boolean; message: string }>
{
  const arrayBuffer = await file.arrayBuffer();
  const backupBlob = new Uint8Array(arrayBuffer);
  if (typeof client.importStateBackup !== 'function') {
    return { ok: false, message: 'Import not supported on this build' };
  }
  const result = await client.importStateBackup(backupBlob);
  return { ok: Boolean(result?.success), message: result?.success ? 'Backup imported successfully' : `Import failed: ${result?.message ?? 'unknown'}` };
}
