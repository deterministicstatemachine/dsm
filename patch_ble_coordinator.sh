sed -i '' -e 's/match self.bilateral_handler.handle_prepare_request(payload).await {/match self.bilateral_handler.handle_prepare_request(payload).await {\
                    Err(e) if e.to_string().contains("silent_drop_duplicate_packet") => {\
                        log::warn!("Silently dropping duplicate Prepare request.");\
                        return Ok(None);\
                    }/' dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/ble_frame_coordinator.rs
