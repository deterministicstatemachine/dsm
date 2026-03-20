sed -i '' -e 's/let (commit_envelope, _meta) = self/match self.bilateral_handler.handle_prepare_response(payload).await {\
                    Ok((commit_envelope, _meta)) => {\
                        info!("Bilateral prepare response processed; emitting commit request envelope ({} bytes)", commit_envelope.len());\
                        Ok(Some(commit_envelope))\
                    },\
                    Err(e) if e.to_string().contains("silent_drop_duplicate_packet") => {\
                        log::warn!("Silently dropping duplicate Prepare Response.");\
                        Ok(None)\
                    },\
                    Err(e) => Err(e)\
                }\
                \/\/let TEMP_REMOVED = self/' dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/ble_frame_coordinator.rs
