import { RejectCode } from "./rejectCodes";
import type { VectorAdapter } from "./runner";
import { processEnvelopeV3Bin } from "../dsm/WebViewBridge";
import { decodeFramedEnvelopeV3 } from "../dsm/decoding";
import * as pb from "../proto/dsm_app_pb";

// Error codes from dsm_core. 
// These must match the constants in dsm::core::bridge / tools/vector_runner
const VECTOR_REJECT_PROOF_TOO_LARGE = 470;
const VECTOR_REJECT_INVALID_PROOF = 471;
const VECTOR_REJECT_MISSING_WITNESS = 472;
const VECTOR_REJECT_MODAL_CONFLICT_PENDING_ONLINE = 473;
const VECTOR_REJECT_STORAGE_ERROR = 474;

function mapRejectCode(code: number): RejectCode {
  switch (code) {
    case 400: return RejectCode.DECODE_ERROR;
    case VECTOR_REJECT_PROOF_TOO_LARGE: return RejectCode.PROOF_TOO_LARGE;
    case VECTOR_REJECT_INVALID_PROOF: return RejectCode.INVALID_PROOF;
    case VECTOR_REJECT_MISSING_WITNESS: return RejectCode.MISSING_WITNESS;
    case VECTOR_REJECT_MODAL_CONFLICT_PENDING_ONLINE: return RejectCode.MODAL_CONFLICT_PENDING_ONLINE;
    case VECTOR_REJECT_STORAGE_ERROR: return RejectCode.STORAGE_ERROR;
    default: return RejectCode.UNKNOWN_REJECT;
  }
}

/**
 * Real WebView inbound adapter.
 * Calls processEnvelopeV3Bin (the same path used by receiving logic to inject bytes into core)
 * to inject bytes into the native core and map the result.
 */
export const realWebviewInboundAdapter: VectorAdapter = async (wire, _caseId) => {
  let respBytes: Uint8Array;
  console.log('[Adapter] Calling processEnvelopeV3Bin...');
  try {
    respBytes = await processEnvelopeV3Bin(wire);
  } catch (e) {
    console.log('[Adapter] Bridge threw error:', e);
    console.error('Vector adapter: bridge call failed', e);
    return RejectCode.UNKNOWN_REJECT;
  }

  // Decode response envelope (canonical framed path)
  let env: pb.Envelope;
  try {
    env = decodeFramedEnvelopeV3(respBytes);
  } catch {
    return RejectCode.DECODE_ERROR;
  }

  // Check payload for Error
  if (env.payload.case === 'error') {
     const err = env.payload.value;
     console.log(`[Adapter] Got top-level error: code=${err.code} msg=${err.message}`);
     return mapRejectCode(err.code);
  }

  // Check payload for UniversalRx
  if (env.payload.case === 'universalRx') {
     const rx = env.payload.value;
     if (rx.results.length > 0) {
        const result = rx.results[0];
        if (result.accepted) {
           return RejectCode.ACCEPT;
        }
        if (result.error) {
           console.log(`[Adapter] Got OpResult error: code=${result.error.code} msg=${result.error.message}`);
           return mapRejectCode(result.error.code);
        }
        console.log(`[Adapter] OpResult rejected but no error? id=${result.opId}`);
     } else {
        console.log(`[Adapter] UniversalRx with empty results`);
     }
  } else {
      console.log(`[Adapter] Unexpected payload case: ${env.payload.case}`);
  }

  return RejectCode.UNKNOWN_REJECT;
};
