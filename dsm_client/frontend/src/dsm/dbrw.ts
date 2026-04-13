import { routerQueryBin, captureCdbrwOrbitTimings } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
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

/**
 * Capture C-DBRW orbit timings for live health check.
 */
async function captureOrbitTimings(): Promise<Uint8Array> {
  const bytes = await captureCdbrwOrbitTimings();
  // Convert ByteArray (little-endian i64) back to Uint8Array
  return bytes;
}

/**
 * Measure trust with captured orbit timings.
 */
async function measureTrustWithOrbit(orbitBytes: Uint8Array): Promise<CdbrwTrustSnapshot> {
  // Convert byte array back to i64 array (little-endian)
  const timings: number[] = [];
  for (let i = 0; i < orbitBytes.length; i += 8) {
    let value = 0;
    for (let j = 0; j < 8; j++) {
      value |= (orbitBytes[i + j] & 0xff) << (j * 8);
    }
    timings.push(value);
  }
  
  // Create CdbrwMeasureTrustRequest
  const req = {
    orbit: {
      timings,
    },
    histogramBins: 256, // Default bins
  };
  
  // Encode the request
  const { CdbrwMeasureTrustRequest } = await import('../proto/dsm_app_pb');
  const reqProto = new CdbrwMeasureTrustRequest();
  reqProto.orbit = req.orbit;
  reqProto.histogramBins = req.histogramBins;
  
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
  if (live) {
    // For live checks, capture orbit timings and measure trust
    const orbitTimings = await captureOrbitTimings();
    const trustSnapshot = await measureTrustWithOrbit(orbitTimings);
    
    // Also get the stored status
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
    
    // Combine stored status with live trust data
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
      runtimeMetricsPresent: true,
      runtimeAccessLevel: trustSnapshot.accessLevel,
      runtimeTrustScore: trustSnapshot.trustScore,
      runtimeHealthCheckRan: true,
      runtimeHealthCheckPassed: trustSnapshot.healthPassed,
      runtimeHHat: trustSnapshot.hHat,
      runtimeRhoHat: trustSnapshot.rhoHat,
      runtimeLHat: trustSnapshot.lHat,
      runtimeMatchScore: trustSnapshot.matchScore,
      runtimeW1Distance: trustSnapshot.w1Distance,
      runtimeW1Threshold: trustSnapshot.w1Threshold,
      runtimeAnchorPrefix: trustSnapshot.anchorPrefix,
      runtimeError: trustSnapshot.error,
      runtimeH0Eff: trustSnapshot.h0Eff,
      runtimeRecommendedN: trustSnapshot.recommendedN,
      runtimeResonantStatus: trustSnapshot.resonantStatus,
    };
  } else {
    // Original implementation for stored status only
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
      runtimeMetricsPresent: resp.runtimeMetricsPresent,
      runtimeAccessLevel: resp.runtimeAccessLevel,
      runtimeTrustScore: resp.runtimeTrustScore,
      runtimeHealthCheckRan: resp.runtimeHealthCheckRan,
      runtimeHealthCheckPassed: resp.runtimeHealthCheckPassed,
      runtimeHHat: resp.runtimeHHat,
      runtimeRhoHat: resp.runtimeRhoHat,
      runtimeLHat: resp.runtimeLHat,
      runtimeMatchScore: resp.runtimeMatchScore,
      runtimeW1Distance: resp.runtimeW1Distance,
      runtimeW1Threshold: resp.runtimeW1Threshold,
      runtimeAnchorPrefix: resp.runtimeAnchorPrefix,
      runtimeError: resp.runtimeError,
      runtimeH0Eff: resp.runtimeH0Eff,
      runtimeRecommendedN: resp.runtimeRecommendedN,
      runtimeResonantStatus: resp.runtimeResonantStatus,
    };
  }
}
