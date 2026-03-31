/* eslint-disable @typescript-eslint/no-explicit-any */
import { extractSystemGenesisResponse } from '../../proto/util';
import * as pb from '../../proto/dsm_app_pb';

describe('extractSystemGenesisResponse', () => {
  const mkHash32 = () => new pb.Hash32({ v: new Uint8Array(32) });

  test('extracts from batch envelope wrapping universalRx', () => {
    const sys = new pb.SystemGenesisResponse({ genesisHash: mkHash32(), publicKey: new Uint8Array([1,2,3]) });
    const pack = new pb.ResultPack({ schemaHash: mkHash32(), codec: pb.Codec.PROTO, body: sys.toBinary() });
    const urx = new pb.UniversalRx({ results: [ new pb.OpResult({ accepted: true, result: pack }) ] });
    const inner = new pb.Envelope({ version: 3, payload: { case: 'universalRx', value: urx } as any });
    const batch = new pb.BatchEnvelope({ envelopes: [ inner ] });
    const outer = new pb.Envelope({ version: 3, payload: { case: 'batchEnvelope', value: batch } as any });
    const out = extractSystemGenesisResponse(outer as any);
    expect(out).toBeInstanceOf(pb.SystemGenesisResponse);
    expect(out.publicKey).toBeInstanceOf(Uint8Array);
    expect((out.publicKey as Uint8Array).length).toBe(3);
  });

  test('throws when universalRx contains an error', () => {
    const err = new pb.Error({ message: 'boom' });
    const urx = new pb.UniversalRx({ results: [ new pb.OpResult({ error: err }) ] });
    const env = new pb.Envelope({ version: 3, payload: { case: 'universalRx', value: urx } as any });
    expect(() => extractSystemGenesisResponse(env as any)).toThrow(/boom/);
  });

  test('throws when missing universalRx', () => {
    const env = new pb.Envelope({ version: 3 });
    expect(() => extractSystemGenesisResponse(env as any)).toThrow(/no universalRx/);
  });
});
