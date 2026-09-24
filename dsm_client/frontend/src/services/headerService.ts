/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/headerService.ts
// SPDX-License-Identifier: Apache-2.0
// DSM Header Service (protobuf-only, binary-string bridge)

import * as pb from '../proto/dsm_app_pb';
import { queryTransportHeadersV3 } from '../dsm/WebViewBridge';
import { checkIdentityState } from '../utils/identity';

/** The sender of an addressed envelope: this device's id and genesis hash. */
export interface TransportHeaders {
  deviceId: Uint8Array;
  genesisHash: Uint8Array;
}

function cloneU8(src: Uint8Array): Uint8Array {
  const out = new Uint8Array(src.length);
  out.set(src);
  return out;
}

// TS lib types: some generators expect Uint8Array<ArrayBuffer> rather than Uint8Array<ArrayBufferLike>.
// Create a fresh ArrayBuffer-backed view to satisfy the stricter type.
type U8AB = Uint8Array<ArrayBuffer>;
function toU8AB(src: Uint8Array): U8AB {
  const out = new Uint8Array(src.length); // new ArrayBuffer (not SharedArrayBuffer)
  out.set(src);
  return out as unknown as U8AB;
}

class HeaderService {
  private cached: TransportHeaders | null = null;
  private invalidated = true;

  isBridgeAvailable(): boolean {
    const b = (globalThis as any)?.DsmBridge;
    return !!(
      b &&
      (b.__binary === true || typeof b.__callBin === 'function')
    );
  }

  ensureBridge(): void {
    const b: any = (globalThis as any)?.DsmBridge;
    const ok = !!(
      b && (
        b.__binary === true || typeof b.__callBin === 'function'
      )
    );
    if (!ok) throw new Error('DSM bridge not available');
  }

  invalidateCache(): void {
    this.invalidated = true;
    this.cached = null;
  }

  async fetchHeaders(): Promise<TransportHeaders> {
    if (this.cached && !this.invalidated) return this.cached;

    // Wait for identity to be ready before trying to get transport headers
    const identityState = await checkIdentityState();
    if (identityState !== 'READY') {
      throw new Error(`DSM: identity not ready (state: ${identityState})`);
    }
    
    const headerBytes = await queryTransportHeadersV3();
    if (!headerBytes?.length) throw new Error('DSM: empty transport headers');

    // protoc-gen-es style:
    const headers = pb.Headers.fromBinary(headerBytes);

    if (!headers.deviceId || headers.deviceId.length !== 32) {
      throw new Error('DSM: invalid deviceId length');
    }
    if (!headers.genesisHash || headers.genesisHash.length !== 32) {
      throw new Error('DSM: invalid genesisHash length');
    }

    const dto: TransportHeaders = {
      deviceId: cloneU8(headers.deviceId as Uint8Array),
      genesisHash: cloneU8(headers.genesisHash as Uint8Array),
    };

    this.cached = dto;
    this.invalidated = false;
    return dto;
  }

  createPbHeaders(h: TransportHeaders): pb.Headers {
    // Construct via class ctor (no .create() in protoc-gen-es)
    return new pb.Headers({
      deviceId: toU8AB(h.deviceId),
      genesisHash: toU8AB(h.genesisHash),
    });
  }
}

export const headerService = new HeaderService();
