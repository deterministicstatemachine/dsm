// SPDX-License-Identifier: Apache-2.0
// Restoring a wallet from its 24 words, over the production transport: the
// real flow, the real stores, and a phone that answers `restoreFromPhrase` the
// way Kotlin forwards Rust's answer. It answers no other wallet method, so a
// flow that reached for wallet creation instead would come back refused.

import { act, renderHook } from '@testing-library/react';
import * as pb from '../../proto/dsm_app_pb';
import { appRuntimeStore } from '../../runtime/appRuntimeStore';
import { installScriptedPhone, removeScriptedPhone } from '../../tests/helpers/scriptedPhone';
import { useGenesisFlow } from '../useGenesisFlow';

const WORDS = Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(' ');

/** A framed envelope, as Kotlin forwards Rust's answer to the page. */
function framed(payload: pb.Envelope['payload']): Uint8Array {
  const env = new pb.Envelope({ version: 3, payload }).toBinary();
  const out = new Uint8Array(1 + env.length);
  out[0] = 0x03;
  out.set(env, 1);
  return out;
}

function restoreFlow() {
  return renderHook(() =>
    useGenesisFlow({
      appState: appRuntimeStore.getSnapshot().appState,
      setAppState: appRuntimeStore.setAppState,
      setError: appRuntimeStore.setError,
      setSecuringProgress: appRuntimeStore.setSecuringProgress,
    }),
  ).result.current.restore;
}

beforeEach(() => {
  act(() => {
    appRuntimeStore.setAppState('needs_genesis');
    appRuntimeStore.setError(null);
  });
});

afterEach(() => removeScriptedPhone());

describe('restoring a wallet from its 24 words', () => {
  it('RESTORE WALLET opens the words screen', () => {
    const restore = restoreFlow();
    act(() => restore.begin());
    expect(appRuntimeStore.getSnapshot().appState).toBe('restore_phrase');
    expect(appRuntimeStore.getSnapshot().error).toBeNull();
  });

  it('restores through restoreFromPhrase and waits for the session to show the wallet', async () => {
    installScriptedPhone({}, {
      restoreFromPhrase: framed({
        case: 'genesisCreatedResponse',
        value: new pb.GenesisCreated({ deviceId: new Uint8Array(32).fill(7) }),
      }),
    });
    const restore = restoreFlow();
    act(() => restore.begin());
    await act(async () => {
      await restore.submit(WORDS);
    });
    expect(appRuntimeStore.getSnapshot().error).toBeNull();
    expect(appRuntimeStore.getSnapshot().appState).toBe('restore_phrase');
  });

  it('keeps the words screen with the reason a restore was refused', async () => {
    const reason = 'system.restoreFromPhrase: no wallet made from these words is on the network';
    installScriptedPhone({}, {
      restoreFromPhrase: framed({ case: 'error', value: new pb.Error({ code: 8, message: reason }) }),
    });
    const restore = restoreFlow();
    act(() => restore.begin());
    await act(async () => {
      await restore.submit(WORDS);
    });
    expect(appRuntimeStore.getSnapshot().appState).toBe('restore_phrase');
    expect(appRuntimeStore.getSnapshot().error).toBe(reason);
  });

  it('Back leaves the restore for setup', () => {
    const restore = restoreFlow();
    act(() => restore.begin());
    act(() => restore.cancel());
    expect(appRuntimeStore.getSnapshot().appState).toBe('needs_genesis');
  });
});
