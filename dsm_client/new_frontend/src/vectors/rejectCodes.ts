export enum RejectCode {
  ACCEPT = "ACCEPT",
  DECODE_ERROR = "DECODE_ERROR",
  PROOF_TOO_LARGE = "PROOF_TOO_LARGE",
  INVALID_PROOF = "INVALID_PROOF",
  MISSING_WITNESS = "MISSING_WITNESS",
  MODAL_CONFLICT_PENDING_ONLINE = "MODAL_CONFLICT_PENDING_ONLINE",
  STORAGE_ERROR = "STORAGE_ERROR",
  UNKNOWN_REJECT = "UNKNOWN_REJECT",
}

export function parseRejectCode(s: string): RejectCode {
  const t = s.trim();
  switch (t) {
    case RejectCode.ACCEPT:
    case RejectCode.DECODE_ERROR:
    case RejectCode.PROOF_TOO_LARGE:
    case RejectCode.INVALID_PROOF:
    case RejectCode.MISSING_WITNESS:
    case RejectCode.MODAL_CONFLICT_PENDING_ONLINE:
    case RejectCode.STORAGE_ERROR:
    case RejectCode.UNKNOWN_REJECT:
      return t as RejectCode;
    default:
      throw new Error(`unknown RejectCode: ${t}`);
  }
}
