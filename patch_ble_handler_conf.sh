sed -i '' -e 's/session.phase = BilateralPhase::Committed;/if session.phase == BilateralPhase::Committed {\
                    log::warn!("[BLE_HANDLER] ⚠️ Duplicate confirm request for {}. Dropping silently.", bytes_to_base32(\&commitment_hash));\
                    return Err(DsmError::invalid_operation("silent_drop_duplicate_packet"));\
                }\
                session.phase = BilateralPhase::Committed;/' dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/bilateral_ble_handler.rs
