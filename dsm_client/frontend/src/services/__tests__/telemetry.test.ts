/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

const mockCallBin = jest.fn();
const mockGetPreference = jest.fn();
const mockGetDiagnosticsLogStrict = jest.fn();

jest.mock('../../dsm/WebViewBridge', () => ({
  callBin: (...args: any[]) => mockCallBin(...args),
  getPreference: (...args: any[]) => mockGetPreference(...args),
  getDiagnosticsLogStrict: (...args: any[]) => mockGetDiagnosticsLogStrict(...args),
}));

// Lazily mock proto only when the fallback path is reached
const mockPbToBinary = jest.fn(() => new Uint8Array([99]));
jest.mock('../../proto/dsm_app_pb', () => ({
  BridgeRpcRequest: jest.fn().mockImplementation(() => ({
    toBinary: mockPbToBinary,
  })),
  BytesPayload: jest.fn().mockImplementation((args: any) => args),
}));

import { sendDiagnostics, hasUserConsentFromPrefs, exportDiagnosticsReport, DIAGNOSTICS_LOG_METHOD } from '../telemetry';

beforeEach(() => {
  mockCallBin.mockReset();
  mockGetPreference.mockReset();
  mockGetDiagnosticsLogStrict.mockReset();
  mockPbToBinary.mockClear();
  delete (window as any).DsmBridge;
  delete (window as any).dsmBridge;
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('DIAGNOSTICS_LOG_METHOD', () => {
  it('exports the correct method name', () => {
    expect(DIAGNOSTICS_LOG_METHOD).toBe('diagnosticsLog');
  });
});

describe('sendDiagnostics', () => {
  it('returns immediately when consent is false', async () => {
    await sendDiagnostics('test payload', false);
    expect(mockCallBin).not.toHaveBeenCalled();
  });

  it('returns immediately when consent defaults (no second arg)', async () => {
    await sendDiagnostics('test payload');
    expect(mockCallBin).not.toHaveBeenCalled();
  });

  it('sends via callBin when available and consent is true', async () => {
    mockCallBin.mockResolvedValue(undefined);
    await sendDiagnostics('diagnostic data', true);

    expect(mockCallBin).toHaveBeenCalledTimes(1);
    expect(mockCallBin.mock.calls[0][0]).toBe(DIAGNOSTICS_LOG_METHOD);
    const sentBytes = mockCallBin.mock.calls[0][1];
    expect(new TextDecoder().decode(sentBytes)).toBe('diagnostic data');
  });

  it('falls back to DsmBridge.__callBin when callBin is unavailable', async () => {
    // Make callBin throw to trigger fallback
    mockCallBin.mockImplementation(() => { throw new Error('not available'); });

    const mockBridgeCallBin = jest.fn().mockResolvedValue(undefined);
    (window as any).DsmBridge = { __callBin: mockBridgeCallBin };

    await sendDiagnostics('data', true);

    expect(mockBridgeCallBin).toHaveBeenCalled();
  });

  it('falls back to postMessage when __callBin is unavailable', async () => {
    mockCallBin.mockImplementation(() => { throw new Error('not available'); });

    const mockPostMessage = jest.fn();
    (window as any).DsmBridge = { postMessage: mockPostMessage };

    await sendDiagnostics('data', true);

    expect(mockPostMessage).toHaveBeenCalled();
  });

  it('silently swallows all errors', async () => {
    mockCallBin.mockImplementation(() => { throw new Error('fail'); });
    (window as any).DsmBridge = {
      __callBin: () => { throw new Error('also fail'); },
    };

    // Should not throw
    await sendDiagnostics('data', true);
  });

  it('encodes null payload as empty string bytes', async () => {
    mockCallBin.mockResolvedValue(undefined);
    await sendDiagnostics(null, true);

    const bytesArg = mockCallBin.mock.calls[0][1] as Uint8Array;
    expect(new TextDecoder().decode(bytesArg)).toBe('');
  });
});

describe('hasUserConsentFromPrefs', () => {
  it('returns true when preference is "1"', async () => {
    mockGetPreference.mockResolvedValue('1');
    expect(await hasUserConsentFromPrefs()).toBe(true);
  });

  it('returns true when preference is "true"', async () => {
    mockGetPreference.mockResolvedValue('true');
    expect(await hasUserConsentFromPrefs()).toBe(true);
  });

  it('returns false when preference is "0"', async () => {
    mockGetPreference.mockResolvedValue('0');
    expect(await hasUserConsentFromPrefs()).toBe(false);
  });

  it('returns false when preference is null', async () => {
    mockGetPreference.mockResolvedValue(null);
    expect(await hasUserConsentFromPrefs()).toBe(false);
  });

  it('returns false on error', async () => {
    mockGetPreference.mockRejectedValue(new Error('bridge error'));
    expect(await hasUserConsentFromPrefs()).toBe(false);
  });
});

describe('exportDiagnosticsReport', () => {
  it('returns bytes from getDiagnosticsLogStrict', async () => {
    const logBytes = new Uint8Array([10, 20, 30]);
    mockGetDiagnosticsLogStrict.mockReturnValue(logBytes);

    const result = await exportDiagnosticsReport();

    expect(result).toEqual(logBytes);
  });

  it('returns empty array when getDiagnosticsLogStrict is unavailable', async () => {
    // Dynamic import will return the mock, but getDiagnosticsLogStrict throws
    mockGetDiagnosticsLogStrict.mockImplementation(() => { throw new Error('not available'); });

    const result = await exportDiagnosticsReport();

    expect(result).toEqual(new Uint8Array(0));
  });
});
