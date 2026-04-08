import { appRouterQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';

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
 * Fetch C-DBRW status.
 * @param live  When `true`, Android runs the heavy runtime snapshot
 *              (9 derive trials + health capture). When `false` (default),
 *              only stored enrollment data is returned — instant.
 */
export async function getDbrwStatus(live = false): Promise<DbrwStatus> {
  // Pass raw bytes directly (not ArgPack-wrapped) so that the Rust handler
  // can check q.params == b"live" to decide whether to run the heavy
  // runtime snapshot.  Empty params = stored enrollment only (instant).
  const params = live ? new TextEncoder().encode('live') : new Uint8Array(0);
  const resBytes = await appRouterQueryBin('dbrw.status', params);

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
