// SPDX-License-Identifier: Apache-2.0

jest.mock('../WebViewBridge', () => ({
  routerQueryBin: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { getVaultStateAnchor } from '../vaultState';
import { routerQueryBin } from '../WebViewBridge';
import { encodeBase32Crockford } from '../../utils/textId';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

function appStateEnvelope(value: string): Uint8Array {
  return frameEnvelope(
    new pb.Envelope({
      version: 3,
      payload: {
        case: 'appStateResponse',
        value: new pb.AppStateResponse({ value }),
      },
    }),
  );
}

function errorEnvelope(message: string): Uint8Array {
  return frameEnvelope(
    new pb.Envelope({
      version: 3,
      payload: { case: 'error', value: new pb.Error({ message }) },
    }),
  );
}

describe('getVaultStateAnchor', () => {
  beforeEach(() => jest.resetAllMocks());

  it('returns null when storage has no anchor yet', async () => {
    (routerQueryBin as jest.Mock).mockResolvedValue(appStateEnvelope(''));
    const r = await getVaultStateAnchor('AAAAAAAA');
    expect(r.success).toBe(true);
    expect(r.anchor).toBeNull();
  });

  it('decodes a published VaultStateAnchorV1 happy path', async () => {
    const anchor = new pb.VaultStateAnchorV1({
      vaultId: new Uint8Array(32).fill(0x11),
      sequence: 7n,
      reservesDigest: new Uint8Array(32).fill(0x22),
      ownerPublicKey: new Uint8Array([1, 2, 3]),
      ownerSignature: new Uint8Array([4, 5, 6]),
    });
    const value = encodeBase32Crockford(anchor.toBinary());
    (routerQueryBin as jest.Mock).mockResolvedValue(appStateEnvelope(value));
    const r = await getVaultStateAnchor('AAAAAAAA');
    expect(r.success).toBe(true);
    expect(r.anchor?.sequence).toBe(7n);
    expect(r.anchor?.reservesDigest).toEqual(new Uint8Array(32).fill(0x22));
    expect(r.anchor?.ownerPublicKey).toEqual(new Uint8Array([1, 2, 3]));
    expect(r.anchor?.ownerSignature).toEqual(new Uint8Array([4, 5, 6]));
    expect(r.anchor?.vaultIdBase32).toBe(
      encodeBase32Crockford(new Uint8Array(32).fill(0x11)),
    );
  });

  it('surfaces error envelopes verbatim', async () => {
    (routerQueryBin as jest.Mock).mockResolvedValue(
      errorEnvelope('vault id wrong length'),
    );
    const r = await getVaultStateAnchor('AAAAAAAA');
    expect(r.success).toBe(false);
    expect(r.error).toContain('vault id wrong length');
  });
});
