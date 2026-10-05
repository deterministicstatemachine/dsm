// SPDX-License-Identifier: Apache-2.0
//
// The app's bridge for tests that cannot run Rust. It answers the native
// ingress from a record of Rust's own answers (each request as the WebView
// frames it, and the bytes the JNI handed back), and answers anything else
// with an error naming it. It logs every request that reached it, so a test can
// tell a request the practice sandbox stopped from one that crossed.

import { readFileSync } from 'fs';
import * as pb from '../../proto/dsm_app_pb';

export type RecordedAnswer = { request: Uint8Array; response: Uint8Array };

/** What reached the bridge: the bridge method, and the route, host request or preference it carried. */
export type Arrival = { method: string; carried: string };

/** A record: length-prefixed pairs of an IngressRequest and the IngressResponse the JNI handed back. */
export function readRustRecord(path: string): RecordedAnswer[] {
  const bytes = new Uint8Array(readFileSync(path));
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 0;
  const part = (): Uint8Array => {
    const length = view.getUint32(at);
    const out = bytes.slice(at + 4, at + 4 + length);
    at += 4 + length;
    return out;
  };
  const answers: RecordedAnswer[] = [];
  while (at < bytes.length) answers.push({ request: part(), response: part() });
  return answers;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((v, i) => v === b[i]);

function carriedBy(method: string, payload: Uint8Array): string {
  if (method === 'nativeBoundaryIngress') {
    const operation = pb.IngressRequest.fromBinary(payload).operation;
    return operation.case === 'routerQuery' || operation.case === 'routerInvoke'
      ? operation.value.method
      : String(operation.case);
  }
  if (method === 'nativeHostRequest') return pb.NativeHostRequestKind[pb.NativeHostRequest.fromBinary(payload).kind];
  if (method === 'setPreference' || method === 'getPreference') return pb.PreferencePayload.fromBinary(payload).key;
  return method;
}

/**
 * Installs the bridge, answering the native ingress from the record at `path`
 * and nothing else from Rust, and returns the log of what reached it. A
 * request Rust answered more than once (a list read again after a write) is
 * answered as Rust answered it, in order: each recorded answer once, then the
 * last of them again.
 */
export function answerFromRustRecord(path: string): Arrival[] {
  const record = readRustRecord(path);
  const given = new Set<number>();
  const arrivals: Arrival[] = [];
  window.DsmBridge = {
    sendMessageBin: async (bytes: Uint8Array): Promise<Uint8Array> => {
      const call = pb.BridgeRpcRequest.fromBinary(bytes);
      const payload = call.payload.case === 'bytes' ? call.payload.value.data : new Uint8Array(0);
      arrivals.push({ method: call.method, carried: carriedBy(call.method, payload) });
      const asked = call.method === 'nativeBoundaryIngress'
        ? record.flatMap((recorded, at) => (sameBytes(recorded.request, payload) ? [at] : []))
        : [];
      const at = asked.find((i) => !given.has(i)) ?? asked[asked.length - 1];
      const answer = at === undefined ? undefined : record[at];
      if (at !== undefined) given.add(at);
      if (!answer) {
        const message = `Rust has no recorded answer to this ${call.method} request`;
        return new pb.BridgeRpcResponse({ result: { case: 'error', value: { errorCode: 1, message } } }).toBinary();
      }
      return new pb.BridgeRpcResponse({
        result: { case: 'success', value: { data: new Uint8Array(answer.response) } },
      }).toBinary();
    },
  };
  return arrivals;
}
