// SPDX-License-Identifier: MIT OR Apache-2.0
//! `receipts.email` (DSM Amendment A17): the page asks for a receipt to be
//! emailed for a send it just made. The SDK names the recipient's email and
//! the sender, signs the request and posts it to the network's receipt
//! service; the answer is where the receipt went, or why it did not.

use prost::Message;

use dsm::types::proto as generated;

use crate::bridge::{AppInvoke, AppResult};
use crate::sdk::email_receipts;

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};

impl AppRouterImpl {
    pub(crate) async fn handle_receipts_invoke(&self, i: AppInvoke) -> AppResult {
        if i.method != "receipts.email" {
            return err(format!("receipts: unknown invoke '{}'", i.method));
        }
        let pack = match generated::ArgPack::decode(&*i.args) {
            Ok(p) => p,
            Err(e) => return err(format!("receipts.email: decode ArgPack failed: {e}")),
        };
        if pack.codec != generated::Codec::Proto as i32 {
            return err("receipts.email: ArgPack.codec must be PROTO".into());
        }
        let intent = match generated::ReceiptEmailIntentV1::decode(&*pack.body) {
            Ok(intent) => intent,
            Err(e) => return err(format!("receipts.email: the intent does not decode: {e}")),
        };
        let url = match email_receipts::service_url() {
            Ok(url) => url,
            Err(e) => return err(format!("receipts.email: {e}")),
        };
        let request = match email_receipts::build_request(&intent) {
            Ok(request) => request,
            Err(e) => return err(format!("receipts.email: {e}")),
        };
        match email_receipts::post(&url, &request).await {
            Ok(result) => {
                pack_envelope_ok(generated::envelope::Payload::ReceiptEmailResult(result))
            }
            Err(e) => err(format!("receipts.email: {e}")),
        }
    }
}
