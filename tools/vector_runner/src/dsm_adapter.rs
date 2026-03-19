use crate::vectors::{Reject, RejectCode, VectorApi};
use dsm::types::proto as gp;
use prost::Message;

const VECTOR_REJECT_PROOF_TOO_LARGE: u32 = 470;
const VECTOR_REJECT_INVALID_PROOF: u32 = 471;
const VECTOR_REJECT_MISSING_WITNESS: u32 = 472;
const VECTOR_REJECT_MODAL_CONFLICT_PENDING_ONLINE: u32 = 473;
const VECTOR_REJECT_STORAGE_ERROR: u32 = 474;

pub struct DsmCoreAdapter;

impl DsmCoreAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl VectorApi for DsmCoreAdapter {
    fn process_wire(&mut self, wire: &[u8], _case_id: &str) -> Reject {
        let resp = dsm::core::bridge::handle_envelope_universal(wire);
        let env = match gp::Envelope::decode(resp.as_slice()) {
            Ok(e) => e,
            Err(_) => {
                return Reject {
                    code: RejectCode::DecodeError,
                    debug: None,
                }
            }
        };

        if let Some(gp::envelope::Payload::Error(err)) = env.payload {
            return Reject {
                code: map_reject_code(err.code),
                debug: None,
            };
        }

        if let Some(gp::envelope::Payload::UniversalRx(rx)) = env.payload {
            if let Some(result) = rx.results.first() {
                if result.accepted {
                    return Reject {
                        code: RejectCode::Accept,
                        debug: None,
                    };
                }
                if let Some(err) = result.error.as_ref() {
                    return Reject {
                        code: map_reject_code(err.code),
                        debug: None,
                    };
                }
            }
        }

        Reject {
            code: RejectCode::UnknownReject,
            debug: None,
        }
    }
}

fn map_reject_code(code: u32) -> RejectCode {
    match code {
        400 => RejectCode::DecodeError,
        VECTOR_REJECT_PROOF_TOO_LARGE => RejectCode::ProofTooLarge,
        VECTOR_REJECT_INVALID_PROOF => RejectCode::InvalidProof,
        VECTOR_REJECT_MISSING_WITNESS => RejectCode::MissingWitness,
        VECTOR_REJECT_MODAL_CONFLICT_PENDING_ONLINE => RejectCode::ModalConflictPendingOnline,
        VECTOR_REJECT_STORAGE_ERROR => RejectCode::StorageError,
        _ => RejectCode::UnknownReject,
    }
}
