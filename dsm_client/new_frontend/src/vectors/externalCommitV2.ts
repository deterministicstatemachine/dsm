/* eslint-disable @typescript-eslint/no-explicit-any */
// ExternalCommit v2 runtime vector harness (protobuf/transport only)

import * as pb from '../proto/dsm_app_pb';

type VectorResult = {
  name: string;
  passed: boolean;
  message?: string;
};

type VectorRunReport = {
  passed: number;
  failed: number;
  results: VectorResult[];
};

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

const eqBytes = (a?: Uint8Array, b?: Uint8Array) => {
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
};

function runCase(name: string, fn: () => void): VectorResult {
  try {
    fn();
    return { name, passed: true };
  } catch (e: any) {
    return { name, passed: false, message: e?.message ?? String(e) };
  }
}

export async function runExternalCommitV2Vectors(): Promise<VectorRunReport> {
  const results: VectorResult[] = [];

  results.push(runCase('no removed source field', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadSmall() as any,
      evidence: evidencePreimage(),
      commitId: new pb.Hash32({ v: commitA as any }),
    });
    if (Object.prototype.hasOwnProperty.call(ec as any, 'source')) {
      throw new Error('removed source field present');
    }
    if ((ec as any).source !== undefined) {
      throw new Error('removed source field not undefined');
    }
  }));

  results.push(runCase('removed source bytes ignored', () => {
    const removedFieldBytes = new Uint8Array([0x22, 0x06, 0x6c, 0x65, 0x67, 0x61, 0x63, 0x79]);
    const decoded = pb.ExternalCommit.fromBinary(removedFieldBytes);
    if (decoded.sourceId !== undefined) {
      throw new Error('sourceId populated from removed-field bytes');
    }
    if (decoded.payload.length !== 0) {
      throw new Error('payload should be empty');
    }
    if (decoded.commitId !== undefined) {
      throw new Error('commitId populated from removed-field bytes');
    }
  }));

  results.push(runCase('binary roundtrip preserves fields', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadSmall() as any,
      evidence: evidencePreimage(),
      commitId: new pb.Hash32({ v: commitA as any }),
    });
    const bin = ec.toBinary();
    const decoded = pb.ExternalCommit.fromBinary(bin);
    const bin2 = decoded.toBinary();
    if (!eqBytes(bin, bin2)) {
      throw new Error('binary roundtrip mismatch');
    }
    if (!eqBytes(decoded.sourceId?.v as any, sidA)) {
      throw new Error('sourceId mismatch');
    }
    if (!eqBytes(decoded.payload as any, payloadSmall())) {
      throw new Error('payload mismatch');
    }
    if (!eqBytes(decoded.commitId?.v as any, commitA)) {
      throw new Error('commitId mismatch');
    }
  }));

  results.push(runCase('bit flip in source_id changes bytes', () => {
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
    if (eqBytes(ec.toBinary(), ec2.toBinary())) {
      throw new Error('sourceId flip did not change bytes');
    }
  }));

  results.push(runCase('bit flip in payload changes bytes', () => {
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
    if (eqBytes(ec.toBinary(), ec2.toBinary())) {
      throw new Error('payload flip did not change bytes');
    }
  }));

  results.push(runCase('bit flip in evidence changes bytes', () => {
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
    if (eqBytes(ec.toBinary(), ec2.toBinary())) {
      throw new Error('evidence flip did not change bytes');
    }
  }));

  results.push(runCase('empty payload deterministic', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidB as any }),
      payload: payloadEmpty() as any,
      evidence: undefined,
      commitId: new pb.Hash32({ v: commitA as any }),
    });
    const bin = ec.toBinary();
    const decoded = pb.ExternalCommit.fromBinary(bin);
    if (!eqBytes(decoded.payload as any, payloadEmpty())) {
      throw new Error('empty payload mismatch');
    }
  }));

  results.push(runCase('large payload deterministic', () => {
    const ec = new pb.ExternalCommit({
      sourceId: new pb.Hash32({ v: sidA as any }),
      payload: payloadLarge() as any,
      evidence: evidencePreimage(),
      commitId: new pb.Hash32({ v: commitA as any }),
    });
    const bin = ec.toBinary();
    const decoded = pb.ExternalCommit.fromBinary(bin);
    if (!eqBytes(decoded.payload as any, payloadLarge())) {
      throw new Error('large payload mismatch');
    }
  }));

  results.push(runCase('Envelope v3 framing roundtrip', () => {
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

    if (framed[0] !== 0x03) {
      throw new Error('frame prefix mismatch');
    }

    const decoded = pb.Envelope.fromBinary(framed.slice(1));
    const re = decoded.toBinary();
    const reframed = new Uint8Array(re.length + 1);
    reframed[0] = 0x03;
    reframed.set(re, 1);

    if (!eqBytes(framed, reframed)) {
      throw new Error('framed roundtrip mismatch');
    }
  }));

  let passed = 0;
  let failed = 0;
  for (const r of results) {
    if (r.passed) passed += 1;
    else failed += 1;
  }

  return { passed, failed, results };
}
