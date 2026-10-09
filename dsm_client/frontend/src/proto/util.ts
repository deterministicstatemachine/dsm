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
