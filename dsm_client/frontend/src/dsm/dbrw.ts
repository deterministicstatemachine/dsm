import { routerQueryBin, captureCdbrwOrbitTimings } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import {
  CdbrwAccessLevel,
  CdbrwMeasureTrustRequest,
  CdbrwOrbitTrial,
  CdbrwResonantStatus,
} from '../proto/dsm_app_pb';
import type { CdbrwTrustSnapshot } from '../proto/dsm_app_pb';

export type DbrwStatus = {
  enrolled: boolean;
  bindingKeyPresent: boolean;
  verifierKeypairPresent: boolean;
  storageBaseDirSet: boolean;
  enrollmentRevision: number;
  arenaBytes: number;
  probes: number;
  stepsPerProbe: number;
  histogramBins: number;
  rotationBits: number;
  epsilonIntra: number;
  meanHistogramLen: number;
  referenceAnchorPrefix: Uint8Array;
  bindingKeyPrefix: Uint8Array;
  verifierPublicKeyPrefix: Uint8Array;
  verifierPublicKeyLen: number;
  storageBaseDir: string;
  statusNote: string;
  runtimeMetricsPresent: boolean;
  runtimeAccessLevel: string;
  runtimeTrustScore: number;
  runtimeHealthCheckRan: boolean;
  runtimeHealthCheckPassed: boolean;
  runtimeHHat: number;
  runtimeRhoHat: number;
  runtimeLHat: number;
  runtimeMatchScore: number;
  runtimeW1Distance: number;
  runtimeW1Threshold: number;
  runtimeAnchorPrefix: Uint8Array;
  runtimeError: string;
  /** Effective entropy rate: hHat * (1 - |rhoHat|) per C-DBRW Prop 4.23. */
  runtimeH0Eff: number;
  /** Recommended orbit length for current entropy rate. */
  runtimeRecommendedN: number;
  /** Resonant health tier: PASS | RESONANT | ADAPTED | FAIL per C-DBRW §7. */
  runtimeResonantStatus: string;
};

// ---- enum → human-readable string helpers ----

function accessLevelToString(level: CdbrwAccessLevel): string {
  switch (level) {
    case CdbrwAccessLevel.CDBRW_ACCESS_BLOCKED: return 'BLOCKED';
    case CdbrwAccessLevel.CDBRW_ACCESS_READ_ONLY: return 'READ_ONLY';
    case CdbrwAccessLevel.CDBRW_ACCESS_PIN_REQUIRED: return 'PIN_REQUIRED';
    case CdbrwAccessLevel.CDBRW_ACCESS_FULL_ACCESS: return 'FULL_ACCESS';
    default: return 'UNSPECIFIED';
  }
}

function resonantStatusToString(status: CdbrwResonantStatus): string {
  switch (status) {
    case CdbrwResonantStatus.CDBRW_RESONANT_PASS: return 'PASS';
    case CdbrwResonantStatus.CDBRW_RESONANT_RESONANT: return 'RESONANT';
    case CdbrwResonantStatus.CDBRW_RESONANT_ADAPTED: return 'ADAPTED';
    case CdbrwResonantStatus.CDBRW_RESONANT_FAIL: return 'FAIL';
    default: return 'UNSPECIFIED';
  }
}

function isHealthPassed(status: CdbrwResonantStatus): boolean {
  return (
    status === CdbrwResonantStatus.CDBRW_RESONANT_PASS ||
    status === CdbrwResonantStatus.CDBRW_RESONANT_RESONANT
  );
}

// ---- Extract trust snapshot into runtime fields ----

function trustToRuntime(
  trust: CdbrwTrustSnapshot | undefined,
  anchorPrefix: Uint8Array,
): Pick<
  DbrwStatus,
  | 'runtimeMetricsPresent'
  | 'runtimeAccessLevel'
  | 'runtimeTrustScore'
  | 'runtimeHealthCheckRan'
  | 'runtimeHealthCheckPassed'
  | 'runtimeHHat'
  | 'runtimeRhoHat'
  | 'runtimeLHat'
  | 'runtimeMatchScore'
  | 'runtimeW1Distance'
  | 'runtimeW1Threshold'
  | 'runtimeAnchorPrefix'
  | 'runtimeError'
  | 'runtimeH0Eff'
  | 'runtimeRecommendedN'
  | 'runtimeResonantStatus'
> {
  if (!trust) {
    return {
      runtimeMetricsPresent: false,
      runtimeAccessLevel: 'UNSPECIFIED',
      runtimeTrustScore: 0,
      runtimeHealthCheckRan: false,
      runtimeHealthCheckPassed: false,
      runtimeHHat: 0,
      runtimeRhoHat: 0,
      runtimeLHat: 0,
      runtimeMatchScore: 0,
      runtimeW1Distance: 0,
      runtimeW1Threshold: 0,
      runtimeAnchorPrefix: new Uint8Array(0),
      runtimeError: '',
      runtimeH0Eff: 0,
      runtimeRecommendedN: 0,
      runtimeResonantStatus: 'UNSPECIFIED',
    };
  }
  return {
    runtimeMetricsPresent: true,
    runtimeAccessLevel: accessLevelToString(trust.accessLevel),
    runtimeTrustScore: trust.trustScore,
    runtimeHealthCheckRan: true,
    runtimeHealthCheckPassed: isHealthPassed(trust.resonantStatus),
    runtimeHHat: trust.hHat,
    runtimeRhoHat: trust.rhoHat,
    runtimeLHat: trust.lHat,
    runtimeMatchScore: trust.trustScore,
    runtimeW1Distance: trust.w1Distance,
    runtimeW1Threshold: trust.w1Threshold,
    runtimeAnchorPrefix: anchorPrefix,
    runtimeError: trust.note,
    runtimeH0Eff: trust.h0Eff,
    runtimeRecommendedN: trust.recommendedN,
    runtimeResonantStatus: resonantStatusToString(trust.resonantStatus),
  };
}

/**
 * Capture C-DBRW orbit timings for live health check.
 */
async function captureOrbitTimings(): Promise<Uint8Array> {
  return captureCdbrwOrbitTimings();
}

/**
 * Measure trust with captured orbit timings.
 */
async function measureTrustWithOrbit(
  orbitBytes: Uint8Array,
  histogramBins: number,
): Promise<CdbrwTrustSnapshot> {
  // Convert byte array to bigint[] (little-endian i64). Proto field is int64.
  const timings: bigint[] = [];
  for (let i = 0; i + 7 < orbitBytes.length; i += 8) {
    let value = 0n;
    for (let j = 0; j < 8; j++) {
      value |= BigInt(orbitBytes[i + j] & 0xff) << BigInt(j * 8);
    }
    timings.push(value);
  }

  const orbit = new CdbrwOrbitTrial({ timings });
  const reqProto = new CdbrwMeasureTrustRequest({
    orbit,
    histogramBins,
  });

  const resBytes = await routerQueryBin('cdbrw.measure_trust', reqProto.toBinary());

  if (!resBytes || resBytes.length === 0) {
    throw new Error('measureTrustWithOrbit: empty response from bridge');
  }

  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    throw new Error(`measureTrustWithOrbit: ${env.payload.value.message || 'unknown error'}`);
  }
  if (env.payload.case !== 'cdbrwTrustSnapshot') {
    throw new Error(`measureTrustWithOrbit: unexpected payload ${env.payload.case}`);
  }

  return env.payload.value;
}

/**
 * Fetch C-DBRW status.
 * @param live  When `true`, Android runs the heavy runtime snapshot
 *              (9 derive trials + health capture). When `false` (default),
 *              only stored enrollment data is returned — instant.
 */
export async function getDbrwStatus(live = false): Promise<DbrwStatus> {
  // Always fetch stored enrollment status.
  const params = new Uint8Array(0);
  const resBytes = await routerQueryBin('dbrw.status', params);

  if (!resBytes || resBytes.length === 0) {
    throw new Error('getDbrwStatus: empty response from bridge');
  }

  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    throw new Error(`getDbrwStatus: ${env.payload.value.message || 'unknown error'}`);
  }
  if (env.payload.case !== 'dbrwStatusResponse') {
    throw new Error(`getDbrwStatus: unexpected payload ${env.payload.case}`);
  }

  const resp = env.payload.value;
  if (!resp) {
    throw new Error('getDbrwStatus: dbrwStatusResponse payload is null');
  }

  // For live checks, capture orbit timings and measure trust on-device.
  const trust: CdbrwTrustSnapshot | undefined = live
    ? await measureTrustWithOrbit(await captureOrbitTimings(), resp.histogramBins)
    : resp.trust;

  return {
    enrolled: resp.enrolled,
    bindingKeyPresent: resp.bindingKeyPresent,
    verifierKeypairPresent: resp.verifierKeypairPresent,
    storageBaseDirSet: resp.storageBaseDirSet,
    enrollmentRevision: resp.enrollmentRevision,
    arenaBytes: resp.arenaBytes,
    probes: resp.probes,
    stepsPerProbe: resp.stepsPerProbe,
    histogramBins: resp.histogramBins,
    rotationBits: resp.rotationBits,
    epsilonIntra: resp.epsilonIntra,
    meanHistogramLen: resp.meanHistogramLen,
    referenceAnchorPrefix: resp.referenceAnchorPrefix,
    bindingKeyPrefix: resp.bindingKeyPrefix,
    verifierPublicKeyPrefix: resp.verifierPublicKeyPrefix,
    verifierPublicKeyLen: resp.verifierPublicKeyLen,
    storageBaseDir: resp.storageBaseDir,
    statusNote: resp.statusNote,
    ...trustToRuntime(trust, resp.referenceAnchorPrefix),
  };
}
