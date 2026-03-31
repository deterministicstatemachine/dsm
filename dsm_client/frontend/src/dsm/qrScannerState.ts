// SPDX-License-Identifier: Apache-2.0

export const NATIVE_QR_SCANNER_ACTIVE_EVENT = 'dsm-native-qr-scanner-active';

export function dispatchNativeQrScannerActive(active: boolean): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(
    new CustomEvent(NATIVE_QR_SCANNER_ACTIVE_EVENT, {
      detail: { active },
    }),
  );
}
