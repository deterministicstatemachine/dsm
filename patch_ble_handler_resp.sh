sed -i '' -e 's/session.phase = BilateralPhase::Accepted;/if session.phase == BilateralPhase::Accepted || session.phase == BilateralPhase::Committed || session.phase == BilateralPhase::ConfirmPending {\
                    log::warn!("[BLE_HANDLER] ⚠️ Duplicate prepare response for {}. Dropping silently.", bytes_to_base32(\&commitment_hash));\
                    return Err(DsmError::invalid_operation("silent_drop_duplicate_packet"));\
                }\
                session.phase = BilateralPhase::Accepted;/' dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/bilateral_ble_handler.rs
