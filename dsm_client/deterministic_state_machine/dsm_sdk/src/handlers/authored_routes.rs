// SPDX-License-Identifier: MIT OR Apache-2.0

//! `authored.publish` and `authored.read`: objects an account publishes under
//! a topic of its own, each signed by its AK (`sdk::authored_objects`).
//!
//! Publishing writes to the pinned storage set of this device's committed
//! network, as every other publication does. Reading returns only objects
//! recognized from their own bytes as the named author's; whether that is
//! every one published is said, never assumed.

use dsm::sofi::storage::Discovered;
use dsm::types::proto as generated;
use prost::Message;

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};
use crate::bridge::{AppInvoke, AppQuery, AppResult};
use crate::sdk::authored_objects;

fn request<M: Message + Default>(params: &[u8], route: &str) -> Result<M, String> {
    let pack = generated::ArgPack::decode(params)
        .map_err(|e| format!("{route}: decode ArgPack failed: {e}"))?;
    if pack.codec != generated::Codec::Proto as i32 {
        return Err(format!("{route}: ArgPack.codec must be PROTO"));
    }
    M::decode(&*pack.body).map_err(|e| format!("{route}: decode request failed: {e}"))
}

fn d32(bytes: &[u8], what: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|e| format!("{what} is {} bytes, not 32: {e}", bytes.len()))
}

fn own_set() -> Result<crate::sdk::storage_set::StorageSet, String> {
    let network = crate::sdk::economic_admission_flow::committed_network_id()
        .map_err(|e| format!("no committed network: {e}"))?;
    crate::sdk::storage_set::canonical_set(&network)
        .map_err(|e| format!("no pinned storage set: {e}"))
}

async fn publish(params: &[u8]) -> Result<generated::AuthoredPublishedResponse, String> {
    let req: generated::AuthoredPublishRequestV1 = request(params, "authored.publish")?;
    let topic = d32(&req.topic, "the topic")?;
    let set = own_set()?;
    let published = authored_objects::publish(&set, &topic, &req.payload)
        .await
        .map_err(|e| format!("authored.publish: {e}"))?;
    Ok(generated::AuthoredPublishedResponse {
        address: published.address.to_vec(),
        locator: published.locator.to_vec(),
        stored: published.stored,
    })
}

async fn read(params: &[u8]) -> Result<generated::AuthoredObjectsResponse, String> {
    let req: generated::AuthoredReadRequestV1 = request(params, "authored.read")?;
    let author = d32(&req.author_device_id, "the author's device id")?;
    let topic = d32(&req.topic, "the topic")?;
    let set = own_set()?;
    let discovered = authored_objects::read(&set, &author, &topic)
        .await
        .map_err(|e| format!("authored.read: {e}"))?;
    let complete = matches!(discovered, Discovered::Complete(..));
    let objects = match discovered {
        Discovered::Complete(objects) | Discovered::Partial(objects) => objects,
    };
    Ok(generated::AuthoredObjectsResponse {
        objects: objects
            .into_iter()
            .map(|o| generated::AuthoredObjectReadV1 {
                address: o.address.to_vec(),
                author_genesis: o.author_genesis.to_vec(),
                payload: o.payload,
            })
            .collect(),
        complete,
    })
}

impl AppRouterImpl {
    pub(crate) async fn handle_authored_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "authored.publish" => match publish(&i.args).await {
                Ok(r) => {
                    pack_envelope_ok(generated::envelope::Payload::AuthoredPublishedResponse(r))
                }
                Err(e) => err(e),
            },
            other => err(format!("unknown authored invoke: {other}")),
        }
    }

    pub(crate) async fn handle_authored_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "authored.read" => match read(&q.params).await {
                Ok(r) => pack_envelope_ok(generated::envelope::Payload::AuthoredObjectsResponse(r)),
                Err(e) => err(e),
            },
            other => err(format!("unknown authored query: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::AppRouter;
    use crate::economic_fixtures::NETWORK;
    use crate::sdk::storage_io::{append_to_index, put_immutable};
    use crate::sdk::storage_set::canonical_set;
    use crate::test_support::one_device::Device;
    use dsm::crypto::sphincs::{generate_keypair, sphincs_sign, SphincsVariant};
    use serial_test::serial;

    fn args(body: Vec<u8>) -> Vec<u8> {
        generated::ArgPack {
            schema_hash: None,
            codec: generated::Codec::Proto as i32,
            body,
        }
        .encode_to_vec()
    }

    fn answer(result: &AppResult) -> generated::envelope::Payload {
        assert!(result.success, "{:?}", result.error_message);
        crate::handlers::response_helpers::decode_local_envelope(&result.data)
            .expect("a local answer")
            .payload
            .expect("a payload")
    }

    async fn publish(
        d: &Device,
        topic: [u8; 32],
        payload: &[u8],
    ) -> generated::AuthoredPublishedResponse {
        let result = d
            .router
            .invoke(AppInvoke {
                method: "authored.publish".into(),
                args: args(
                    generated::AuthoredPublishRequestV1 {
                        topic: topic.to_vec(),
                        payload: payload.to_vec(),
                    }
                    .encode_to_vec(),
                ),
            })
            .await;
        match answer(&result) {
            generated::envelope::Payload::AuthoredPublishedResponse(r) => r,
            other => panic!("authored.publish answered {other:?}"),
        }
    }

    async fn read(
        d: &Device,
        author: &[u8],
        topic: [u8; 32],
    ) -> generated::AuthoredObjectsResponse {
        let result = d
            .router
            .query(AppQuery {
                path: "authored.read".into(),
                params: args(
                    generated::AuthoredReadRequestV1 {
                        author_device_id: author.to_vec(),
                        topic: topic.to_vec(),
                    }
                    .encode_to_vec(),
                ),
            })
            .await;
        match answer(&result) {
            generated::envelope::Payload::AuthoredObjectsResponse(r) => r,
            other => panic!("authored.read answered {other:?}"),
        }
    }

    /// An object whose body names `claimed` as its author but is signed by
    /// another key, whose AK and AttA do not derive `claimed`.
    fn impostor(claimed: &[u8; 32], topic: [u8; 32], payload: &[u8]) -> Vec<u8> {
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("a key");
        let body = generated::AuthoredObjectBodyV1 {
            author_genesis: vec![2; 32],
            author_device_id: claimed.to_vec(),
            author_ak: kp.public_key.clone(),
            author_att_a: vec![3; 32],
            topic: topic.to_vec(),
            payload: payload.to_vec(),
        }
        .encode_to_vec();
        let digest =
            dsm::crypto::blake3::domain_hash(authored_objects::TAG_AUTHORED_STATEMENT, &body);
        let signature = sphincs_sign(&kp.secret_key, digest.as_bytes()).expect("a signature");
        generated::AuthoredObjectV1 { body, signature }.encode_to_vec()
    }

    /// An account publishes under its topic and any reader reads exactly its
    /// objects back: an object another key appended under the locator,
    /// naming this account as its author, is not among them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn an_accounts_objects_are_read_back_and_an_impostors_are_not() {
        let d = Device::start(0xA7).await;
        let topic = [0x42; 32];
        let first = publish(&d, topic, b"issued").await;
        let second = publish(&d, topic, b"successor").await;
        assert!(first.stored && second.stored, "both are Stored");
        assert_eq!(
            first.locator, second.locator,
            "one locator per author and topic"
        );
        assert_ne!(first.address, second.address);

        let me = d.identity.device_id;
        let forged = impostor(&me, topic, b"a modded state");
        let set = canonical_set(NETWORK).expect("the pinned set");
        let (addr, _) = put_immutable(&set, authored_objects::TAG_AUTHORED_OBJECT, &forged)
            .await
            .expect("the put");
        append_to_index(
            &set,
            authored_objects::TAG_AUTHORED_LOCATOR.source_bytes(),
            &authored_objects::locator(&me, &topic),
            &addr,
        )
        .await
        .expect("the append");

        let read_back = read(&d, &me, topic).await;
        assert!(read_back.complete, "every candidate was read");
        let payloads: Vec<Vec<u8>> = read_back
            .objects
            .iter()
            .map(|o| o.payload.clone())
            .collect();
        assert_eq!(payloads, vec![b"issued".to_vec(), b"successor".to_vec()]);
        assert_eq!(read_back.objects[0].address, first.address);
        assert!(
            read(&d, &me, [0x43; 32]).await.objects.is_empty(),
            "another topic"
        );
        assert!(
            read(&d, &[9; 32], topic).await.objects.is_empty(),
            "another author"
        );
    }
}
