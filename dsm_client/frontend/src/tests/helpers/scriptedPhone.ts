// SPDX-License-Identifier: Apache-2.0
// A phone for screen tests, spoken to over the production transport: it
// answers the bridge the way Kotlin and Rust answer it for the router routes a
// test scripts, records each `setScreenGuards` byte the page sends, and
// answers every other call with the dispatcher's error for a method it does
// not handle.

import * as pb from '../../proto/dsm_app_pb';
import { setBridgeInstance } from '../../bridge/BridgeRegistry';

export type Answer = pb.Envelope['payload'];

export type ScriptedPhone = {
  /** The guard bits the page asked for, in the order it asked. */
  guards: number[];
};

function response(result: pb.BridgeRpcResponse['result']): Uint8Array {
  return new pb.BridgeRpcResponse({ result }).toBinary();
}

function success(data: Uint8Array): Uint8Array {
  return response({ case: 'success', value: new pb.BytesPayload({ data: new Uint8Array(data) }) });
}

function failure(message: string): Uint8Array {
  return response({ case: 'error', value: new pb.ErrorResponse({ errorCode: 8, message }) });
}

function framed(payload: Answer): Uint8Array {
  const env = new pb.Envelope({ version: 3, payload }).toBinary();
  const out = new Uint8Array(1 + env.length);
  out[0] = 0x03;
  out.set(env, 1);
  return out;
}

/** An AppStateResponse carrying `value`, as the router answers a recovery route. */
export function appState(value: string): Answer {
  return { case: 'appStateResponse', value: new pb.AppStateResponse({ key: 'value', value }) };
}

type BridgeHolder = { DsmBridge: unknown };

/**
 * Installs the phone as `window.DsmBridge`: `routes` maps a router route to
 * what it answers, `methods` a bridge method to the bytes Kotlin answers it with.
 */
export function installScriptedPhone(routes: Record<string, Answer>, methods: Record<string, Uint8Array> = {}): ScriptedPhone {
  const phone: ScriptedPhone = { guards: [] };
  const answers = new Map(Object.entries(routes));
  const methodAnswers = new Map(Object.entries(methods));
  (window as unknown as BridgeHolder).DsmBridge = {
    sendMessageBin: async (requestBytes: Uint8Array): Promise<Uint8Array> => {
      const request = pb.BridgeRpcRequest.fromBinary(requestBytes);
      const data = request.payload.case === 'bytes' ? request.payload.value.data : new Uint8Array(0);
      if (request.method === 'setScreenGuards') {
        if (data.length !== 1) return failure(`setScreenGuards: one byte of guards, not ${data.length}`);
        phone.guards.push(data[0]);
        return success(new Uint8Array(0));
      }
      if (request.method === 'nativeBoundaryIngress') {
        const operation = pb.IngressRequest.fromBinary(data).operation;
        const route = operation.case === 'routerQuery' || operation.case === 'routerInvoke' ? operation.value.method : '';
        const answer = answers.get(route);
        if (answer === undefined) return failure(`this test's phone answers no route ${route}`);
        return success(new pb.IngressResponse({ result: { case: 'okBytes', value: framed(answer) } }).toBinary());
      }
      const bytes = methodAnswers.get(request.method);
      if (bytes !== undefined) return success(bytes);
      return failure(`Unknown binary RPC method: ${request.method}`);
    },
  };
  return phone;
}

/** Takes the phone away again: the next test installs its own. */
export function removeScriptedPhone(): void {
  (window as unknown as BridgeHolder).DsmBridge = {};
  setBridgeInstance(undefined);
}

/** Lets every answer the page is waiting on arrive. */
export async function settle(): Promise<void> {
  for (let round = 0; round < 8; round += 1) {
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
}
