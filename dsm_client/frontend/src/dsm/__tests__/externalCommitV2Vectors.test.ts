/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
// ExternalCommit v2 vector suite (frontend, protobuf/transport only)
// - No removed `source` string surface
// - Binary roundtrip stability
// - Bit-flip sensitivity in transport bytes
// - Removed source field ignored on decode
// - Envelope v3 framing roundtrip

declare const describe: any;
declare const test: any;
declare const expect: any;

import * as pb from '../../proto/dsm_app_pb';

const sidA = new Uint8Array(32).fill(0xa5);
const sidB = new Uint8Array(32).fill(0x11);
const commitA = new Uint8Array(32).fill(0x42);

const payloadSmall = () => new Uint8Array([1, 2, 3, 4, 5, 250, 251, 252]);
const payloadEmpty = () => new Uint8Array([]);
const payloadLarge = () => {
  const v = new Uint8Array(4096);
  for (let i = 0; i < v.length; i += 1) {
    v[i] = (i * 73 + 41) & 0xff;
  }
  return v;
};

const evidencePreimage = () =>
  new pb.Evidence({
    kind: {
      case: 'preimage',
      value: new pb.EvidencePreimage({ preimage: payloadSmall() as any }),
    },
  });

const flipOneBit = (u8: Uint8Array) => {
  const v = new Uint8Array(u8);
  if (v.length === 0) {
    return new Uint8Array([1]);
  }
  v[0] ^= 0x01;
  return v;
};

const wrapExternalCommit = (ec: pb.ExternalCommit) => {
  const op = new pb.UniversalOp({
    opId: new pb.Hash32({ v: new Uint8Array(32) as any }),
    actor: new Uint8Array(32) as any,
    genesisHash: new Uint8Array(32) as any,
    kind: { case: 'externalCommit', value: ec } as any,
  });
  const tx = new pb.UniversalTx({ ops: [op], atomic: true });
  return new pb.Envelope({
    version: 3,
    headers: new pb.Headers({
      deviceId: new Uint8Array(32) as any,
      chainTip: new Uint8Array(32) as any,
      genesisHash: new Uint8Array(32) as any,
      seq: 1n,
    }),
    messageId: new Uint8Array(16) as any,
    payload: { case: 'universalTx', value: tx } as any,
  });
};

describe('ExternalCommit v2 vectors (frontend)', () => {
  test('ExternalCommit has no removed source field', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadSmall() as any,
      evidence: evidencePreimage(),
      commitId: new pb.Hash32({ v: commitA as any }),
    });

    expect(Object.prototype.hasOwnProperty.call(ec as any, 'source')).toBe(false);
    expect((ec as any).source).toBeUndefined();
  });

  test('removed source field bytes are ignored on decode', () => {
    // Protobuf wire: tag = (field_number << 3) | wire_type = (4 << 3) | 2 = 0x22
    const removedFieldBytes = new Uint8Array([0x22, 0x06, 0x6c, 0x65, 0x67, 0x61, 0x63, 0x79]); // tag-4 sample bytes
    const decoded = pb.ExternalCommit.fromBinary(removedFieldBytes);
    expect(decoded.sourceId).toBeUndefined();
    expect(decoded.payload.length).toBe(0);
    expect(decoded.commitId).toBeUndefined();
  });

  test('binary roundtrip preserves fields', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadSmall() as any,
      evidence: evidencePreimage(),
      commitId: new pb.Hash32({ v: commitA as any }),
    });

    const bin = ec.toBinary();
    const decoded = pb.ExternalCommit.fromBinary(bin);
    const bin2 = decoded.toBinary();

    expect(bin).toEqual(bin2);
    expect(decoded.sourceId?.v).toEqual(sidA);
    expect(decoded.payload).toEqual(payloadSmall());
    expect(decoded.commitId?.v).toEqual(commitA);
  });

  test('bit flip in source_id changes encoded bytes', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadEmpty() as any,
      evidence: undefined,
      commitId: new pb.Hash32({ v: commitA as any }),
    });
    const ec2 = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: flipOneBit(sidA) as any }),
      payload: payloadEmpty() as any,
      evidence: undefined,
      commitId: new pb.Hash32({ v: commitA as any }),
    });

    expect(ec.toBinary()).not.toEqual(ec2.toBinary());
  });

  test('bit flip in payload changes encoded bytes', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadSmall() as any,
      evidence: undefined,
      commitId: new pb.Hash32({ v: commitA as any }),
    });
    const ec2 = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: flipOneBit(payloadSmall()) as any,
      evidence: undefined,
      commitId: new pb.Hash32({ v: commitA as any }),
    });

    expect(ec.toBinary()).not.toEqual(ec2.toBinary());
  });

  test('bit flip in evidence bytes changes encoded bytes', () => {
    const ev = evidencePreimage();
    const ev2 = new pb.Evidence({
      kind: {
        case: 'preimage',
        value: new pb.EvidencePreimage({ preimage: flipOneBit(payloadSmall()) as any }),
      },
    });

    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadSmall() as any,
      evidence: ev,
      commitId: new pb.Hash32({ v: commitA as any }),
    });
    const ec2 = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadSmall() as any,
      evidence: ev2,
      commitId: new pb.Hash32({ v: commitA as any }),
    });

    expect(ec.toBinary()).not.toEqual(ec2.toBinary());
  });

  test('handles empty payload deterministically', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidB as any }),
      payload: payloadEmpty() as any,
      evidence: undefined,
      commitId: new pb.Hash32({ v: commitA as any }),
    });
    const bin = ec.toBinary();
    const decoded = pb.ExternalCommit.fromBinary(bin);
    expect(decoded.payload).toEqual(payloadEmpty());
  });

  test('handles large payload deterministically', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadLarge() as any,
      evidence: evidencePreimage(),
      commitId: new pb.Hash32({ v: commitA as any }),
    });
    const bin = ec.toBinary();
    const decoded = pb.ExternalCommit.fromBinary(bin);
    expect(decoded.payload).toEqual(payloadLarge());
  });

  test('Envelope v3 framing roundtrip for ExternalCommit', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadSmall() as any,
      evidence: evidencePreimage(),
      commitId: new pb.Hash32({ v: commitA as any }),
    });

    const env = wrapExternalCommit(ec);
    const envBytes = env.toBinary();
    const framed = new Uint8Array(envBytes.length + 1);
    framed[0] = 0x03;
    framed.set(envBytes, 1);

    expect(framed[0]).toBe(0x03);
    const decoded = pb.Envelope.fromBinary(framed.slice(1));
    const re = decoded.toBinary();
    const reframed = new Uint8Array(re.length + 1);
    reframed[0] = 0x03;
    reframed.set(re, 1);

    expect(framed).toEqual(reframed);
  });
});
