/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';

export function ab(len: number): Uint8Array {
  return new Uint8Array(len);
}

export function zeroHash32(): pb.Hash32 {
  // Cast to any to satisfy Uint8Array<ArrayBuffer> vs ArrayBufferLike
  return new pb.Hash32({ v: ab(32) as any });
}

export function zeroBytes32(): Uint8Array {
  return ab(32);
}

// Oneof helper for protobuf-ts style
export function mkOneof<T>(caseName: string, value: T): any {
  return { case: caseName as any, value } as any;
}

export function codecProto(): number {
  const anyPb: any = pb;
  // Codec.PROTO is an enum value (0).
  // If it's exposed directly on pb namespace or requires pb.Codec.PROTO access
  if (typeof anyPb.Codec?.PROTO === 'number') return anyPb.Codec.PROTO;
  if (anyPb.CodecProto && typeof anyPb.CodecProto.PROTO === 'number')
    return anyPb.CodecProto.PROTO;
  return 0;
}
