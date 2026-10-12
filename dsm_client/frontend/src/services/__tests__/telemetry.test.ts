// SPDX-License-Identifier: MIT OR Apache-2.0

jest.mock('../../dsm/WebViewBridge', () => ({
  callBin: jest.fn(),
}));

import { callBin } from '../../dsm/WebViewBridge';
import { DIAGNOSTICS_LOG_METHOD, sendDiagnostics } from '../telemetry';

describe('sendDiagnostics', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('sends nothing without consent', async () => {
    await sendDiagnostics('report', false);
    expect(callBin).not.toHaveBeenCalled();
  });

  it('writes the report bytes into the bridge log with consent', async () => {
    (callBin as jest.Mock).mockResolvedValue(new Uint8Array(0));
    await sendDiagnostics('report', true);
    expect(callBin).toHaveBeenCalledWith(DIAGNOSTICS_LOG_METHOD, new TextEncoder().encode('report'));
  });

  // The hook shows the failure; a swallowed one read as "saved".
  it('a bridge failure is the caller’s to show, not swallowed', async () => {
    (callBin as jest.Mock).mockRejectedValue(new Error('Bridge not initialized'));
    await expect(sendDiagnostics('report', true)).rejects.toThrow('Bridge not initialized');
  });
});
