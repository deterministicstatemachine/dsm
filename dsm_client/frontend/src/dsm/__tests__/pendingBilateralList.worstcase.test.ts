import * as pb from '../../proto/dsm_app_pb';
import { getPendingBilateralListStrict } from '../index';

jest.mock('../WebViewBridge', () => {
  const actual = jest.requireActual('../WebViewBridge');
  return {
    ...actual,
    getPendingBilateralListStrictBridge: jest.fn(),
  };
});

const getPendingBilateralListStrictBridge = jest.requireMock('../WebViewBridge').getPendingBilateralListStrictBridge as jest.Mock;

describe('getPendingBilateralListStrict worst-case', () => {
  beforeEach(() => {
    getPendingBilateralListStrictBridge.mockReset();
  });

  test('throws on Error envelope response', async () => {
    const env = new pb.Envelope({
      version: 3,
      payload: {
        case: 'error',
        value: new pb.Error({ code: 460, message: 'pending-list failed' }),
      } as any,
    } as any);

    // Return with framing byte (0x03) as expected by strict bridge
    const framed = new Uint8Array([0x03, ...env.toBinary()]);
    getPendingBilateralListStrictBridge.mockResolvedValueOnce(framed);

    await expect(getPendingBilateralListStrict()).rejects.toThrow(/pending-list failed/i);
  });
});
