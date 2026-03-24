// SPDX-License-Identifier: Apache-2.0

import type { NfcBackupStatus } from './nfcRecoveryService';

export type NfcBackupUiState = 'not_set' | 'disabled' | 'waiting' | 'armed';

export type NfcBackupUiModel = {
  state: NfcBackupUiState;
  backupLabel: string;
  writeStateLabel: string;
  nextActionLabel: string;
  compactSummary: string;
  detailSummary: string;
};

function latestCapsuleText(status: NfcBackupStatus): string {
  return status.capsuleCount > 0 ? ` Latest local capsule: #${status.lastCapsuleIndex}.` : '';
}

export function getNfcBackupUiModel(status: NfcBackupStatus): NfcBackupUiModel {
  const latest = latestCapsuleText(status);

  if (!status.configured) {
    return {
      state: 'not_set',
      backupLabel: 'NOT SET',
      writeStateLabel: '--',
      nextActionLabel: 'SET UP',
      compactSummary: 'Not configured. Add a mnemonic before this phone can arm a recovery capsule.',
      detailSummary:
        'Set up a recovery mnemonic first. After that, you can arm a capsule in Rust and write it to the ring.',
    };
  }

  if (!status.enabled) {
    return {
      state: 'disabled',
      backupLabel: 'OFF',
      writeStateLabel: '--',
      nextActionLabel: 'ENABLE',
      compactSummary: `Configured but disabled.${latest}`,
      detailSummary:
        `Backup is configured but disabled. This phone will not arm new capsules until you enable it again.${latest}`,
    };
  }

  if (status.pendingCapsule) {
    return {
      state: 'armed',
      backupLabel: 'ON',
      writeStateLabel: 'ARMED',
      nextActionLabel: 'WRITE',
      compactSummary: `A capsule is armed and ready to write.${latest}`,
      detailSummary:
        `A capsule is armed locally and ready to write. Press write, then hold the ring to the phone until it vibrates.${latest}`,
    };
  }

  return {
    state: 'waiting',
    backupLabel: 'ON',
    writeStateLabel: 'WAITING',
    nextActionLabel: 'REBUILD',
    compactSummary: `Enabled, but nothing is armed right now.${latest}`,
    detailSummary:
      `Backup is enabled, but nothing is armed right now. The next accepted state change will arm a capsule, or you can rebuild one now with your mnemonic.${latest}`,
  };
}
