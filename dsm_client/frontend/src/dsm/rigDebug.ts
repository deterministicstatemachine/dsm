// SPDX-License-Identifier: MIT OR Apache-2.0

// Rig-only host hook: lets the CDP driver run READ-ONLY router queries and
// read the decoded `AppStateResponse.value` back as a string. Pure plumbing —
// no business logic, no state, queries only (the invoke surface is
// deliberately not exposed): the two-device end-to-end proof asks both
// devices `dlv.composeVault` through this hook and compares the answers
// byte-for-byte.

import { routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';

declare global {
  interface Window {
    __dsmRigQuery?: (path: string, params?: string) => Promise<string>;
  }
}

export function installRigQueryHook(): void {
  window.__dsmRigQuery = async (path: string, params?: string): Promise<string> => {
    const bytes = await routerQueryBin(
      path,
      params ? new TextEncoder().encode(params) : undefined,
    );
    const env = decodeFramedEnvelopeV3(bytes);
    if (env.payload.case === 'appStateResponse') {
      return env.payload.value.value ?? '';
    }
    throw new Error(`rig query ${path}: unexpected payload ${env.payload.case}`);
  };
}
