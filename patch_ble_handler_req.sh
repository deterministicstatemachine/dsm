sed -i '' -e 's/let session = BilateralBleSession {/let mut sessions = self.sessions.sessions.lock().await;\
        if sessions.contains_key(\&origin_commitment_hash) {\
            log::warn!("[BLE_HANDLER] ⚠️ Duplicate prepare request for {}. Dropping silently.", bytes_to_base32(\&origin_commitment_hash));\
            return Err(DsmError::invalid_operation("silent_drop_duplicate_packet"));\
        }\
        drop(sessions);\
\
        let session = BilateralBleSession {/' dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/bilateral_ble_handler.rs
