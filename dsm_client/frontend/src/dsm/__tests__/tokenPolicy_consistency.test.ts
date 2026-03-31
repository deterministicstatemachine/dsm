jest.mock('../WebViewBridge', () => {
  const actual = jest.requireActual('../WebViewBridge');
  return {
    ...actual,
    publishTokenPolicyBytes: jest.fn(),
    getTokenPolicyBytes: jest.fn(),
    listCachedTokenPolicies: jest.fn(),
  };
});

import * as pb from '../../proto/dsm_app_pb';
import {
  getTokenPolicyBytes,
  listPolicies,
  publishTokenPolicyBytes,
} from '../policies';
import {
  getTokenPolicyBytes as getTokenPolicyBytesBridge,
  listCachedTokenPolicies,
  publishTokenPolicyBytes as publishTokenPolicyBytesBridge,
} from '../WebViewBridge';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

describe('token policy publish/get consistency', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (global as any).fetch = jest.fn();
  });

  test('policy routes use native wrappers and cached list envelope, without frontend fetch', async () => {
    const policyBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const anchorBytes = new Uint8Array(32).fill(0xab);

    (publishTokenPolicyBytesBridge as jest.Mock).mockResolvedValue(anchorBytes);
    (getTokenPolicyBytesBridge as jest.Mock).mockResolvedValue(policyBytes);
    (listCachedTokenPolicies as jest.Mock).mockResolvedValue(
      frameEnvelope(new pb.Envelope({
        version: 3,
        payload: {
          case: 'tokenPolicyListResponse',
          value: new pb.TokenPolicyListResponse({
            policies: [
              new pb.TokenPolicyCacheEntry({
                policyCommit: anchorBytes,
                policyBytes,
                ticker: 'TST',
                alias: 'Test Token',
                decimals: 6,
                maxSupply: '1000',
              }),
            ],
          }),
        },
      })),
    );

    const published = await publishTokenPolicyBytes(policyBytes);
    const fetched = await getTokenPolicyBytes(anchorBytes);
    const listed = await listPolicies();

    expect(published.anchorBytes).toEqual(anchorBytes);
    expect(fetched).toEqual(policyBytes);
    expect(listed).toEqual([
      {
        policy_commit: anchorBytes,
        policy_bytes: policyBytes,
        metadata: {
          ticker: 'TST',
          alias: 'Test Token',
          decimals: 6,
          maxSupply: '1000',
        },
      },
    ]);
    expect((global as any).fetch).not.toHaveBeenCalled();
  });
});
