jest.mock('../WebViewBridge', () => ({
  routerQueryBin: jest.fn(),
  captureCdbrwOrbitTimings: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { getDbrwStatus } from '../dbrw';
import { captureCdbrwOrbitTimings, routerQueryBin } from '../WebViewBridge';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

function makeDbrwStatusResponse(overrides: Record<string, unknown> = {}): pb.DbrwStatusResponse {
  const trustExplicit = 'trust' in overrides;
  const trustOverride = overrides.trust as pb.CdbrwTrustSnapshot | undefined;
  const baseOverrides = { ...overrides };
  delete baseOverrides.trust;
  const trust = trustExplicit
    ? trustOverride
    : new pb.CdbrwTrustSnapshot({
          accessLevel: pb.CdbrwAccessLevel.CDBRW_ACCESS_FULL_ACCESS,
          resonantStatus: pb.CdbrwResonantStatus.CDBRW_RESONANT_PASS,
          trustScore: 0.95,
          hHat: 0.98,
          rhoHat: 0.02,
          lHat: 4.5,
          h0Eff: 0.96,
          recommendedN: 1024,
          w1Distance: 0.01,
          w1Threshold: 0.05,
          note: '',
        })
      : (trustOverride);
  return new pb.DbrwStatusResponse({
    enrolled: true,
    bindingKeyPresent: true,
    verifierKeypairPresent: true,
    storageBaseDirSet: true,
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
    trust,
    ...baseOverrides,
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
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const status = await getDbrwStatus();
      expect(status.enrolled).toBe(true);
      expect(status.bindingKeyPresent).toBe(true);
      expect(status.verifierKeypairPresent).toBe(true);
      expect(status.storageBaseDirSet).toBe(true);
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

    test('uses enrolled histogram bins for live trust measurement', async () => {
      const statusResp = makeDbrwStatusResponse({ histogramBins: 64 });
      const statusEnv = new pb.Envelope({
        version: 3,
        payload: { case: 'dbrwStatusResponse', value: statusResp },
      });
      const trustEnv = new pb.Envelope({
        version: 3,
        payload: {
          case: 'cdbrwTrustSnapshot',
          value: new pb.CdbrwTrustSnapshot({
            accessLevel: pb.CdbrwAccessLevel.CDBRW_ACCESS_PIN_REQUIRED,
            resonantStatus: pb.CdbrwResonantStatus.CDBRW_RESONANT_ADAPTED,
            trustScore: 0.42,
            hHat: 0.5,
            rhoHat: 0.1,
            lHat: 0.2,
            w1Distance: 0.3,
            w1Threshold: 0.2,
            note: 'live trust',
            h0Eff: 0.45,
            recommendedN: 16384,
          }),
        },
      });
      (routerQueryBin as jest.Mock)
        .mockResolvedValueOnce(frameEnvelope(statusEnv))
        .mockResolvedValueOnce(frameEnvelope(trustEnv));
      (captureCdbrwOrbitTimings as jest.Mock).mockResolvedValue(
        new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]),
      );

      await getDbrwStatus(true);
      expect((routerQueryBin as jest.Mock).mock.calls[0][0]).toBe('dbrw.status');
      expect((routerQueryBin as jest.Mock).mock.calls[1][0]).toBe('cdbrw.measure_trust');

      const trustReq = pb.CdbrwMeasureTrustRequest.fromBinary(
        (routerQueryBin as jest.Mock).mock.calls[1][1],
      );
      expect(trustReq.histogramBins).toBe(64);
      expect(trustReq.orbit?.timings.length).toBe(1);
    });

    test('passes empty params when live=false', async () => {
      const resp = makeDbrwStatusResponse();
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'dbrwStatusResponse', value: resp },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await getDbrwStatus(false);
      const [, params] = (routerQueryBin as jest.Mock).mock.calls[0];
      expect(params.length).toBe(0);
    });

    test('throws on empty response', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(new Uint8Array(0));
      await expect(getDbrwStatus()).rejects.toThrow(/empty response/);
    });

    test('throws on null response', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(null);
      await expect(getDbrwStatus()).rejects.toThrow(/empty response/);
    });

    test('throws on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ message: 'dbrw not enrolled' }) },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getDbrwStatus()).rejects.toThrow(/dbrw not enrolled/);
    });

    test('throws on unexpected payload case', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse() },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getDbrwStatus()).rejects.toThrow(/unexpected payload/);
    });

    test('returns default values when dbrwStatusResponse payload has no fields', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'dbrwStatusResponse', value: new pb.DbrwStatusResponse() },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const status = await getDbrwStatus();
      expect(status.enrolled).toBe(false);
      expect(status.arenaBytes).toBe(0);
    });

    test('maps unenrolled status correctly', async () => {
      const resp = makeDbrwStatusResponse({
        enrolled: false,
        trust: undefined,
      });
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'dbrwStatusResponse', value: resp },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const status = await getDbrwStatus();
      expect(status.enrolled).toBe(false);
      expect(status.runtimeMetricsPresent).toBe(false);
      expect(status.runtimeResonantStatus).toBe('UNSPECIFIED');
    });
  });
});
