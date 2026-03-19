// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message route handlers for AppRouterImpl.
//!
//! Handles: `message.send`

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::err;

impl AppRouterImpl {
    pub(crate) async fn handle_message_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "message.send" => {
                let arg_pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if arg_pack.codec != generated::Codec::Proto as i32 {
                    return err("message.send: ArgPack.codec must be PROTO".into());
                }

                let msg_req = match generated::OnlineMessageRequest::decode(&*arg_pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode OnlineMessageRequest failed: {e}")),
                };

                self.process_online_message_logic(msg_req).await
            }

            other => err(format!("unknown message invoke method: {other}")),
        }
    }
}
