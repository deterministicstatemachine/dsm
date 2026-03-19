/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// Small helpers around ES-generated protobufs (protoc-gen-es)

import * as pb from './dsm_app_pb';

/**
 * Extract GenesisCreated from a canonical Envelope v3 payload.
 */
export function extractGenesisCreated(env: pb.Envelope): pb.GenesisCreated {
  if (!env || typeof env !== 'object') {
    throw new Error('no genesisCreatedResponse in envelope (invalid envelope)');
  }
  const payload: any = (env as any).payload;
  if (payload && typeof payload === 'object' && payload.case === 'genesisCreatedResponse') {
    return payload.value as pb.GenesisCreated;
  }
  const shape = payload && typeof payload === 'object'
    ? (payload.case ?? Object.keys(payload).join(','))
    : 'none';
  throw new Error(`no genesisCreatedResponse in envelope (payload shape: ${String(shape)})`);
}

/**
 * Extract SystemGenesisResponse from a UniversalRx envelope.
 * This is the standard response for a `system.genesis` query.
 */
export function extractSystemGenesisResponse(env: pb.Envelope): pb.SystemGenesisResponse {
  let innerEnv = env;

  // Check if the payload is a BatchEnvelope and extract the first envelope
  if (env?.payload?.case === 'batchEnvelope' && env.payload.value.envelopes.length > 0) {
    innerEnv = env.payload.value.envelopes[0];
  }

  if (!innerEnv?.payload || (innerEnv.payload as any).case !== 'universalRx') {
    throw new Error('no universalRx in envelope');
  }
  const urx = (innerEnv.payload as any).value as pb.UniversalRx;
  const firstResult = urx?.results?.[0];
  if (firstResult?.error) {
    throw new Error(firstResult.error.message || 'system.genesis failed in UniversalRx');
  }
  const pack = firstResult?.result;
  if (!pack?.body) {
    throw new Error('system.genesis: missing result body in UniversalRx');
  }
  return pb.SystemGenesisResponse.fromBinary(pack.body);
}
