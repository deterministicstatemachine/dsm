jest.mock('../WebViewBridge', () => ({
  appRouterQueryBin: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { getDbrwStatus } from '../dbrw';
import { appRouterQueryBin } from '../WebViewBridge';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

function makeDbrwStatusResponse(overrides: Record<string, unknown> = {}): pb.DbrwStatusResponse {
  return new pb.DbrwStatusResponse({
    enrolled: true,
    bindingKeyPresent: true,
    verifierKeypairPresent: true,
    storageBaseDirSet: true,
    observeOnly: false,
    accessMode: 'full',
    enrollmentRevision: 3,
    arenaBytes: 4096,
    probes: 9,
    stepsPerProbe: 512,
    histogramBins: 64,
    rotationBits: 16,
    epsilonIntra: 0.05,
    meanHistogramLen: 42,
    referenceAnchorPrefix: new Uint8Array(8).fill(0xAA),
    bindingKeyPrefix: new Uint8Array(8).fill(0xBB),
    verifierPublicKeyPrefix: new Uint8Array(8).fill(0xCC),
    verifierPublicKeyLen: 1952,
    storageBaseDir: '/data/dbrw',
    statusNote: 'healthy',
    runtimeMetricsPresent: true,
    runtimeAccessLevel: 'full',
    runtimeTrustScore: 0.95,
    runtimeHealthCheckRan: true,
    runtimeHealthCheckPassed: true,
    runtimeHHat: 0.98,
    runtimeRhoHat: 0.02,
    runtimeLHat: 4.5,
    runtimeMatchScore: 0.99,
    runtimeW1Distance: 0.01,
    runtimeW1Threshold: 0.05,
    runtimeAnchorPrefix: new Uint8Array(8).fill(0xDD),
    runtimeError: '',
    runtimeH0Eff: 0.96,
    runtimeRecommendedN: 1024,
    runtimeResonantStatus: 'PASS',
    ...overrides,
  } as any);
}

describe('dbrw.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('getDbrwStatus', () => {
    test('maps all DbrwStatusResponse fields', async () => {
      const resp = makeDbrwStatusResponse();
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'dbrwStatusResponse', value: resp },
      });
      (appRouterQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const status = await getDbrwStatus();
      expect(status.enrolled).toBe(true);
      expect(status.bindingKeyPresent).toBe(true);
      expect(status.verifierKeypairPresent).toBe(true);
      expect(status.storageBaseDirSet).toBe(true);
      expect(status.observeOnly).toBe(false);
      expect(status.accessMode).toBe('full');
      expect(status.enrollmentRevision).toBe(3);
      expect(status.arenaBytes).toBe(4096);
      expect(status.probes).toBe(9);
      expect(status.stepsPerProbe).toBe(512);
      expect(status.histogramBins).toBe(64);
      expect(status.rotationBits).toBe(16);
      expect(status.verifierPublicKeyLen).toBe(1952);
      expect(status.storageBaseDir).toBe('/data/dbrw');
      expect(status.statusNote).toBe('healthy');
      expect(status.runtimeMetricsPresent).toBe(true);
      expect(status.runtimeResonantStatus).toBe('PASS');
      expect(status.runtimeError).toBe('');
    });

    test('passes "live" params when live=true', async () => {
      const resp = makeDbrwStatusResponse();
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'dbrwStatusResponse', value: resp },
      });
      (appRouterQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await getDbrwStatus(true);
      const [route, params] = (appRouterQueryBin as jest.Mock).mock.calls[0];
      expect(route).toBe('dbrw.status');
      expect(new TextDecoder().decode(params)).toBe('live');
    });

    test('passes empty params when live=false', async () => {
      const resp = makeDbrwStatusResponse();
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'dbrwStatusResponse', value: resp },
      });
      (appRouterQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await getDbrwStatus(false);
      const [, params] = (appRouterQueryBin as jest.Mock).mock.calls[0];
      expect(params.length).toBe(0);
    });

    test('throws on empty response', async () => {
      (appRouterQueryBin as jest.Mock).mockResolvedValue(new Uint8Array(0));
      await expect(getDbrwStatus()).rejects.toThrow(/empty response/);
    });

    test('throws on null response', async () => {
      (appRouterQueryBin as jest.Mock).mockResolvedValue(null);
      await expect(getDbrwStatus()).rejects.toThrow(/empty response/);
    });

    test('throws on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ message: 'dbrw not enrolled' }) },
      });
      (appRouterQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getDbrwStatus()).rejects.toThrow(/dbrw not enrolled/);
    });

    test('throws on unexpected payload case', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse() },
      });
      (appRouterQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getDbrwStatus()).rejects.toThrow(/unexpected payload/);
    });

    test('returns default values when dbrwStatusResponse payload has no fields', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'dbrwStatusResponse', value: new pb.DbrwStatusResponse() },
      });
      (appRouterQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const status = await getDbrwStatus();
      expect(status.enrolled).toBe(false);
      expect(status.accessMode).toBe('');
      expect(status.arenaBytes).toBe(0);
    });

    test('maps unenrolled status correctly', async () => {
      const resp = makeDbrwStatusResponse({
        enrolled: false,
        runtimeMetricsPresent: false,
        runtimeResonantStatus: 'FAIL',
      });
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'dbrwStatusResponse', value: resp },
      });
      (appRouterQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const status = await getDbrwStatus();
      expect(status.enrolled).toBe(false);
      expect(status.runtimeMetricsPresent).toBe(false);
      expect(status.runtimeResonantStatus).toBe('FAIL');
    });
  });
});
