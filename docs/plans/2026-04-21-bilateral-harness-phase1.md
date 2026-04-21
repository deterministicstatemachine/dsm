# Bilateral Test Harness — Phase 1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship a deterministic two-peer BLE test harness that drives the real 3-phase bilateral commit (Prepare → Accept → Commit) end-to-end without Android, with fault injection (drops, reorders, delays, partitions, corruption) and deterministic RNG. Smoke tests prove it works; subsequent phases (audit, proptest, concurrency) ride on top.

**Architecture:** The existing `BleTransportDelegate` trait + `BilateralTransportAdapter` + `BleFrameCoordinator` already provide a clean seam. We build a `bilateral_test_harness` module under `dsm_sdk/tests/common/` that wraps those primitives in a `TestPeer` + `FakeNetwork` + `PeerPair` abstraction. We use `BilateralBleHandler::new_with_smt` so each peer gets an isolated SMT (critical — without it, both "peers" in one process corrupt each other's root). We use `#[serial_test::serial]` + `configure_local_identity_for_receipts` to manage the shared `AppState` (known limitation, called out explicitly and revisited in Phase 2/3 if it blocks).

**Tech Stack:**
- Rust async (`tokio`)
- `prost` (protobuf)
- Existing: `BilateralBleHandler`, `BilateralTransportAdapter`, `BleFrameCoordinator`, `BilateralTransactionManager`
- New: `bilateral_test_harness` module in `dsm_sdk/tests/common/mod.rs` (accessible from `tests/` files)
- `serial_test` (already a dep) for AppState serialization
- `blake3` for deterministic IDs

**Out of scope for Phase 1 (enforced):**
- The audit itself (Phase 2)
- Property tests (Phase 4)
- Deep concurrency tests (Phase 3)
- Changing production APIs
- Touching `bilateral_ble_handler.rs` internals

---

## Task 0: Baseline check

**Files:** none

**Step 1: Confirm existing bilateral tests pass before we touch anything**

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm --test bilateral_transaction_integration_tests`
Expected: all tests PASS

**Step 2: Confirm SDK tests compile**

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk --no-run`
Expected: compiles clean (warnings OK, errors NOT OK)

**Step 3: No commit**

Baseline only — nothing to commit.

---

## Task 1: Scaffold the harness module

**Files:**
- Create: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/mod.rs`
- Create: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/harness.rs`
- Create: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Write the failing test**

```rust
// tests/bilateral_harness_smoke.rs

mod common;

use common::harness::PeerPair;

#[tokio::test]
#[serial_test::serial]
async fn peer_pair_can_be_constructed() {
    let pair = PeerPair::spawn("alice", "bob").await;
    assert_ne!(pair.alice.device_id(), pair.bob.device_id());
    assert_ne!(pair.alice.genesis_hash(), pair.bob.genesis_hash());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke peer_pair_can_be_constructed`
Expected: FAIL with `cannot find module common` or similar.

**Step 3: Write minimal scaffolding**

```rust
// tests/common/mod.rs
pub mod harness;
```

```rust
// tests/common/harness.rs
#![allow(dead_code)] // harness API grows over subsequent tasks

use std::sync::Arc;
use tokio::sync::RwLock;

use dsm_sdk::bluetooth::bilateral_ble_handler::BilateralBleHandler;
use dsm_sdk::bluetooth::bilateral_transport_adapter::BilateralTransportAdapter;
use dsm_sdk::bluetooth::ble_frame_coordinator::BleFrameCoordinator;

use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::identifiers::NodeId;

/// One side of a two-peer test. Owns its handler, adapter, coordinator,
/// manager, keypair, genesis hash, and device id. Deterministic —
/// constructed from a seed label.
pub struct TestPeer {
    pub label: &'static str,
    pub device_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub keypair: SignatureKeyPair,
    pub manager: Arc<RwLock<BilateralTransactionManager>>,
    pub handler: Arc<BilateralBleHandler>,
    pub adapter: Arc<BilateralTransportAdapter>,
    pub coordinator: Arc<BleFrameCoordinator>,
    pub smt: Arc<RwLock<dsm::merkle::sparse_merkle_tree::SparseMerkleTree>>,
}

impl TestPeer {
    pub fn device_id(&self) -> [u8; 32] { self.device_id }
    pub fn genesis_hash(&self) -> [u8; 32] { self.genesis_hash }

    pub fn spawn(label: &'static str) -> Self {
        let keypair = SignatureKeyPair::generate_from_entropy(label.as_bytes())
            .expect("deterministic keygen");
        let device_id = blake3_32(&[b"dsm/test/device:", label.as_bytes()]);
        let genesis_hash = blake3_32(&[b"dsm/test/genesis:", label.as_bytes()]);
        let nodes = vec![NodeId::new("harness_node")];
        let contacts = DsmContactManager::new(device_id, nodes);
        let manager = BilateralTransactionManager::new(
            contacts, keypair.clone(), device_id, genesis_hash,
        );
        let manager = Arc::new(RwLock::new(manager));
        let smt = Arc::new(RwLock::new(
            dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256),
        ));
        let handler = Arc::new(
            BilateralBleHandler::new_with_smt(manager.clone(), device_id, smt.clone()),
        );
        let adapter = Arc::new(BilateralTransportAdapter::new(handler.clone()));
        let coordinator = Arc::new(BleFrameCoordinator::new(device_id));
        Self {
            label, device_id, genesis_hash, keypair, manager,
            handler, adapter, coordinator, smt,
        }
    }
}

/// A pair of peers. Does not yet establish relationships or network — just builds both sides.
pub struct PeerPair {
    pub alice: TestPeer,
    pub bob: TestPeer,
}

impl PeerPair {
    pub async fn spawn(a_label: &'static str, b_label: &'static str) -> Self {
        Self {
            alice: TestPeer::spawn(a_label),
            bob: TestPeer::spawn(b_label),
        }
    }
}

fn blake3_32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for p in parts { h.update(p); }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke peer_pair_can_be_constructed`
Expected: PASS.

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs
git commit -m "test(bilateral): scaffold PeerPair harness for device-free bilateral tests

Lays down TestPeer and PeerPair in tests/common/harness.rs. Deterministic
genesis/device ids via blake3. Isolated SMT per peer (required so two
simulated devices in one process don't corrupt each other's root)."
```

---

## Task 2: Establish relationships + verified contacts

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/harness.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
#[serial_test::serial]
async fn peer_pair_establishes_bidirectional_relationship() {
    let mut pair = PeerPair::spawn("alice", "bob").await;
    pair.establish_relationship().await;

    let alice_mgr = pair.alice.manager.read().await;
    assert!(alice_mgr.has_verified_contact(&pair.bob.device_id));
    drop(alice_mgr);

    let bob_mgr = pair.bob.manager.read().await;
    assert!(bob_mgr.has_verified_contact(&pair.alice.device_id));
}
```

**Step 2: Run to verify it fails**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke peer_pair_establishes_bidirectional_relationship`
Expected: FAIL (`no method named establish_relationship`).

**Step 3: Implement**

Add to `PeerPair`:

```rust
impl PeerPair {
    /// Add both peers as verified contacts of each other and establish the
    /// bilateral relationship on both sides. Idempotent-safe but intended to
    /// be called once per PeerPair.
    pub async fn establish_relationship(&mut self) {
        let contact_b = dsm::types::contact_types::DsmVerifiedContact {
            alias: self.bob.label.to_string(),
            device_id: self.bob.device_id,
            genesis_hash: self.bob.genesis_hash,
            public_key: self.bob.keypair.public_key().to_vec(),
            genesis_material: vec![0u8; 32],
            chain_tip: None,
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: None,
        };
        let contact_a = dsm::types::contact_types::DsmVerifiedContact {
            alias: self.alice.label.to_string(),
            device_id: self.alice.device_id,
            genesis_hash: self.alice.genesis_hash,
            public_key: self.alice.keypair.public_key().to_vec(),
            genesis_material: vec![0u8; 32],
            chain_tip: None,
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: None,
        };
        {
            let mut m = self.alice.manager.write().await;
            m.add_verified_contact(contact_b).expect("alice add bob");
        }
        {
            let mut m = self.bob.manager.write().await;
            m.add_verified_contact(contact_a).expect("bob add alice");
        }
        // Relationships established on their own SMTs.
        {
            let mut m = self.alice.manager.write().await;
            let mut smt = self.alice.smt.write().await;
            m.establish_relationship(&self.bob.device_id, &mut *smt)
                .await
                .expect("alice establish rel");
        }
        {
            let mut m = self.bob.manager.write().await;
            let mut smt = self.bob.smt.write().await;
            m.establish_relationship(&self.alice.device_id, &mut *smt)
                .await
                .expect("bob establish rel");
        }
    }
}
```

**Step 4: Run to verify it passes**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke peer_pair_establishes_bidirectional_relationship`
Expected: PASS.

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common/harness.rs \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs
git commit -m "test(bilateral): PeerPair::establish_relationship crosslinks contacts + SMT

Both peers add each other as verified contacts and establish the bilateral
relationship on their own isolated SMT. Mirrors the real contact flow
without needing storage nodes or MPC genesis."
```

---

## Task 3: FakeNetwork — minimal happy-path frame relay

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/harness.rs`
- Create: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/mod.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
#[serial_test::serial]
async fn network_relays_prepare_frame_from_alice_to_bob() {
    let mut pair = PeerPair::spawn("alice", "bob").await;
    pair.establish_relationship().await;
    let mut net = pair.wire_network();
    // Alice seeds ERA projection so a transfer is possible.
    pair.alice.seed_era_balance(10_000);

    let op = common::ops::transfer(&pair.alice, &pair.bob, 10, "ERA");
    let prepare_bytes = pair.alice.adapter
        .create_prepare_message(pair.bob.device_id, op, 300)
        .await
        .expect("prepare bytes");

    net.send_from_alice(common::BleFrameType::BilateralPrepare, prepare_bytes).await;
    net.deliver_all().await.expect("deliver prepare");

    let pending = {
        let m = pair.alice.manager.read().await;
        m.list_pending_commitments()
    };
    assert_eq!(pending.len(), 1, "one pending commitment on Alice after prepare");
}
```

**Step 2: Run to verify it fails**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke network_relays_prepare_frame_from_alice_to_bob`
Expected: FAIL.

**Step 3: Implement FakeNetwork**

```rust
// tests/common/mod.rs
pub mod harness;
pub mod fake_network;
pub mod ops;

pub use dsm_sdk::bluetooth::ble_frame_coordinator::BleFrameType;
```

```rust
// tests/common/ops.rs
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;
use super::harness::TestPeer;

pub fn transfer(sender: &TestPeer, receiver: &TestPeer, amount: u64, token: &str) -> Operation {
    Operation::Transfer {
        to_device_id: receiver.device_id.to_vec(),
        amount: Balance::from_state(amount, [1u8; 32]),
        token_id: token.as_bytes().to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 8],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: receiver.device_id.to_vec(),
        to: receiver.label.as_bytes().to_vec(),
        message: format!("harness transfer {amount} {token}"),
        signature: Vec::new(),
    }
}
```

```rust
// tests/common/fake_network.rs
use std::collections::VecDeque;
use std::sync::Arc;

use dsm_sdk::bluetooth::bilateral_transport_adapter::{
    BilateralTransportAdapter, BleTransportDelegate, TransportInboundMessage,
};
use dsm_sdk::bluetooth::ble_frame_coordinator::{
    BleFrameCoordinator, BleFrameType, FrameIngressResult,
};
use dsm::types::error::DsmError;

use super::harness::{PeerPair, TestPeer};

/// Direction is written from the perspective of the side that authored the
/// frame: `AliceToBob` means alice.coordinator chunked the payload and the
/// chunks are delivered into bob.coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction { AliceToBob, BobToAlice }

#[derive(Debug, Clone)]
struct ChunkInFlight {
    dir: Direction,
    bytes: Vec<u8>,
}

pub struct FakeNetwork {
    /// Pending in-flight chunks awaiting delivery.
    queue: VecDeque<ChunkInFlight>,
    /// Alice-side peer address used in TransportInboundMessage.
    pub alice_addr: String,
    pub bob_addr: String,
    alice_coord: Arc<BleFrameCoordinator>,
    bob_coord: Arc<BleFrameCoordinator>,
    alice_adapter: Arc<BilateralTransportAdapter>,
    bob_adapter: Arc<BilateralTransportAdapter>,
}

impl FakeNetwork {
    pub fn new(pair: &PeerPair) -> Self {
        Self {
            queue: VecDeque::new(),
            alice_addr: "harness/alice".to_string(),
            bob_addr: "harness/bob".to_string(),
            alice_coord: pair.alice.coordinator.clone(),
            bob_coord: pair.bob.coordinator.clone(),
            alice_adapter: pair.alice.adapter.clone(),
            bob_adapter: pair.bob.adapter.clone(),
        }
    }

    pub async fn send_from_alice(&mut self, ft: BleFrameType, bytes: Vec<u8>) {
        let chunks = self.alice_coord.encode_message(ft, &bytes).expect("encode");
        for c in chunks {
            self.queue.push_back(ChunkInFlight { dir: Direction::AliceToBob, bytes: c });
        }
    }

    pub async fn send_from_bob(&mut self, ft: BleFrameType, bytes: Vec<u8>) {
        let chunks = self.bob_coord.encode_message(ft, &bytes).expect("encode");
        for c in chunks {
            self.queue.push_back(ChunkInFlight { dir: Direction::BobToAlice, bytes: c });
        }
    }

    /// Drain every queued chunk, deliver to the opposite coordinator. Any
    /// resulting outbound frame (from the delegate) is re-enqueued. Loops
    /// until the queue is empty. Returns the count of messages delivered.
    pub async fn deliver_all(&mut self) -> Result<usize, DsmError> {
        let mut delivered = 0;
        while let Some(chunk) = self.queue.pop_front() {
            let (coord, adapter, addr, reverse_dir) = match chunk.dir {
                Direction::AliceToBob => (
                    &self.bob_coord, &self.bob_adapter,
                    self.bob_addr.clone(), Direction::BobToAlice,
                ),
                Direction::BobToAlice => (
                    &self.alice_coord, &self.alice_adapter,
                    self.alice_addr.clone(), Direction::AliceToBob,
                ),
            };
            match coord.ingest_chunk(&chunk.bytes).await? {
                FrameIngressResult::MessageComplete { message } => {
                    let outbound = adapter
                        .on_transport_message(TransportInboundMessage {
                            peer_address: addr,
                            frame_type: message.frame_type,
                            payload: message.payload,
                        })
                        .await?;
                    delivered += 1;
                    // Re-enqueue any produced chunks back through the other coord.
                    let sender_coord = match reverse_dir {
                        Direction::AliceToBob => &self.alice_coord,
                        Direction::BobToAlice => &self.bob_coord,
                    };
                    for out in outbound {
                        let chs = sender_coord.encode_message(out.frame_type, &out.payload)?;
                        for c in chs {
                            self.queue.push_back(ChunkInFlight { dir: reverse_dir, bytes: c });
                        }
                    }
                }
                FrameIngressResult::NeedMoreChunks
                | FrameIngressResult::ProtocolControl(_) => {}
            }
        }
        Ok(delivered)
    }

    pub fn pending_chunks(&self) -> usize { self.queue.len() }
}
```

Also add on `TestPeer`:

```rust
impl TestPeer {
    pub fn seed_era_balance(&self, available: u64) {
        use dsm_sdk::storage::client_db::{self, BalanceProjectionRecord};
        use dsm_sdk::util::text_id;

        let device_txt = text_id::encode_base32_crockford(&self.device_id);
        let record = BalanceProjectionRecord {
            balance_key: format!("test:{device_txt}:ERA"),
            device_id: device_txt,
            token_id: "ERA".to_string(),
            policy_commit: text_id::encode_base32_crockford(
                dsm_sdk::policy::builtins::NATIVE_POLICY_COMMIT,
            ),
            available,
            locked: 0,
            source_state_hash: text_id::encode_base32_crockford(&[0u8; 32]),
            source_state_number: 0,
            updated_at: 0,
        };
        client_db::upsert_balance_projection(&record).expect("seed projection");
    }
}
```

Add on `PeerPair`:

```rust
impl PeerPair {
    pub fn wire_network(&self) -> FakeNetwork { FakeNetwork::new(self) }
}
```

Also: at top of the smoke test file, add a helper that initializes the shared client_db for the test process once. Use the existing `client_db::reset_database_for_tests` + `init_database` pattern:

```rust
// tests/bilateral_harness_smoke.rs
use serial_test::serial;

mod common;
use common::{harness::PeerPair, BleFrameType};

fn ensure_db() {
    use dsm_sdk::storage::client_db;
    let _ = client_db::reset_database_for_tests();
    let _ = client_db::init_database();
    // Configure a temp storage dir the first time.
    let tmp = std::env::temp_dir().join("dsm_bilateral_harness");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("tmp");
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(tmp);
}
```

Call `ensure_db()` at the top of every harness test.

**Step 4: Run to verify it passes**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke network_relays_prepare_frame_from_alice_to_bob`
Expected: PASS.

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs
git commit -m "test(bilateral): FakeNetwork delivers bilateral chunks between peers

FakeNetwork queues chunks, delivers them into the opposite peer's
coordinator, and re-enqueues any outbound response. Closes the loop for
fully in-process 3-phase commit drives — no Android, no BLE radio."
```

---

## Task 4: Full happy-path 3-phase transfer test

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/harness.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
#[serial]
async fn full_3phase_commit_happy_path() {
    ensure_db();
    let mut pair = PeerPair::spawn("alice", "bob").await;
    pair.establish_relationship().await;
    pair.alice.seed_era_balance(10_000);
    let mut net = pair.wire_network();

    let op = common::ops::transfer(&pair.alice, &pair.bob, 10, "ERA");

    // Prepare: alice -> bob (bob auto-accepts because manual_accept is off in tests)
    pair.alice.configure_identity_as_local();
    let prepare = pair.alice.adapter
        .create_prepare_message(pair.bob.device_id, op.clone(), 300)
        .await
        .expect("prepare");
    net.send_from_alice(BleFrameType::BilateralPrepare, prepare).await;
    net.deliver_all().await.expect("prepare delivered");

    // Accept: fetch pending commitment on Alice; Bob creates accept; push back.
    let commitment = {
        let m = pair.alice.manager.read().await;
        *m.list_pending_commitments().first().expect("pending")
    };
    let accept = pair.bob.handler
        .create_prepare_accept_envelope(commitment).await
        .expect("accept");
    pair.bob.configure_identity_as_local();
    net.send_from_bob(BleFrameType::BilateralPrepareResponse, accept).await;
    net.deliver_all().await.expect("accept delivered");

    // Confirm + Ack round-trips are driven by the adapter via deliver_all()
    // (handle_prepare_response → BilateralConfirm → handle_confirm_request
    // → BilateralCommitResponse → completes both sides).

    // Both sides finalized
    {
        let m = pair.alice.manager.read().await;
        assert!(!m.has_pending_commitment(&commitment));
        let tip = m.get_chain_tip_for(&pair.bob.device_id).expect("alice tip");
        assert!(tip != [0u8; 32], "alice tip advances");
    }
    {
        let m = pair.bob.manager.read().await;
        let tip = m.get_chain_tip_for(&pair.alice.device_id).expect("bob tip");
        assert!(tip != [0u8; 32], "bob tip advances");
    }
}
```

**Step 2: Run to verify it fails**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke full_3phase_commit_happy_path`
Expected: FAIL — most likely `configure_identity_as_local` is not defined, or the confirm envelope path fails because AppState isn't set before alice processes the prepare response.

**Step 3: Implement `configure_identity_as_local` on `TestPeer`**

```rust
impl TestPeer {
    /// Make this peer's identity the *current* AppState identity. Because
    /// AppState is process-global, only one peer can "be local" at a time
    /// — this is why harness tests are `#[serial]`. Callers must call this
    /// immediately before each step that signs or verifies as this peer.
    pub fn configure_identity_as_local(&self) {
        dsm_sdk::sdk::app_state::AppState::set_identity_info(
            self.device_id.to_vec(),
            self.keypair.public_key().to_vec(),
            self.genesis_hash.to_vec(),
            vec![0u8; 32],
        );
        dsm_sdk::sdk::app_state::AppState::set_has_identity(true);
    }
}
```

Document the AppState serialization constraint inline near the `TestPeer` definition.

**Step 4: Run to verify it passes**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke full_3phase_commit_happy_path -- --nocapture`
Expected: PASS.

If it fails because `deliver_all()` doesn't know to swap identity between steps: add an `on_before_deliver` callback to `FakeNetwork` OR have the test drive the phases step-wise and call `configure_identity_as_local` between them. Prefer the step-wise variant (matches the existing mock pattern and keeps `FakeNetwork` dumb).

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common/harness.rs \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs
git commit -m "test(bilateral): harness drives full 3-phase commit without devices

Happy-path transfer (prepare → accept → confirm → commit response) runs
entirely in process via FakeNetwork. Both peer chain tips advance. This
is the baseline all Phase 2+ tests will build on."
```

---

## Task 5: Fault injection — chunk drop

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
#[serial]
async fn drop_nth_chunk_leaves_message_incomplete() {
    ensure_db();
    let mut pair = PeerPair::spawn("alice", "bob").await;
    pair.establish_relationship().await;
    pair.alice.seed_era_balance(10_000);
    let mut net = pair.wire_network();
    net.faults_mut().drop_every_nth(2); // drop every 2nd chunk

    let op = common::ops::transfer(&pair.alice, &pair.bob, 10, "ERA");
    pair.alice.configure_identity_as_local();
    let prepare = pair.alice.adapter
        .create_prepare_message(pair.bob.device_id, op, 300)
        .await.unwrap();
    net.send_from_alice(BleFrameType::BilateralPrepare, prepare).await;
    net.deliver_all().await.unwrap();

    // With chunks dropped, bob should NOT have produced a pending commitment on alice.
    let pending = {
        let m = pair.alice.manager.read().await;
        m.list_pending_commitments()
    };
    // Alice still has her own pending — but bob never saw the complete prepare,
    // so no accept was produced and the deliver_all() loop did not close.
    // We assert on bob-side: no commit chunks should have been queued.
    assert!(net.pending_chunks() == 0, "no accept chunks from bob");
    assert_eq!(pending.len(), 1, "alice still has her own pending prepare");
}
```

**Step 2: Run to verify it fails**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke drop_nth_chunk_leaves_message_incomplete`
Expected: FAIL — no `faults_mut()` API.

**Step 3: Implement fault injection**

Add to `FakeNetwork`:

```rust
#[derive(Debug, Default, Clone)]
pub struct Faults {
    drop_every_nth: Option<u64>,
    chunk_counter: u64,
    // More fields added in subsequent tasks (reorder, delay, corrupt, partition).
}

impl Faults {
    pub fn drop_every_nth(&mut self, n: u64) -> &mut Self {
        self.drop_every_nth = Some(n);
        self
    }

    fn should_drop(&mut self) -> bool {
        self.chunk_counter = self.chunk_counter.wrapping_add(1);
        matches!(self.drop_every_nth, Some(n) if n > 0 && self.chunk_counter % n == 0)
    }
}
```

Add `faults: Faults` field to `FakeNetwork`, `faults_mut(&mut self) -> &mut Faults`, and consult `self.faults.should_drop()` at the top of the `deliver_all` loop — if true, discard the chunk and continue.

**Step 4: Run to verify it passes**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke drop_nth_chunk_leaves_message_incomplete`
Expected: PASS.

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs
git commit -m "test(bilateral): FakeNetwork fault injection — drop every Nth chunk

First fault primitive. More to follow: reorder, delay, corrupt, partition."
```

---

## Task 6: Fault injection — reorder within window

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
#[serial]
async fn reorder_chunks_still_completes_prepare() {
    ensure_db();
    let mut pair = PeerPair::spawn("alice", "bob").await;
    pair.establish_relationship().await;
    pair.alice.seed_era_balance(10_000);
    let mut net = pair.wire_network();
    net.faults_mut().reorder_window(4);

    let op = common::ops::transfer(&pair.alice, &pair.bob, 10, "ERA");
    pair.alice.configure_identity_as_local();
    let prepare = pair.alice.adapter
        .create_prepare_message(pair.bob.device_id, op, 300)
        .await.unwrap();
    net.send_from_alice(BleFrameType::BilateralPrepare, prepare).await;
    net.deliver_all().await.expect("deliver despite reorder");

    let pending = { pair.alice.manager.read().await.list_pending_commitments() };
    assert_eq!(pending.len(), 1, "prepare completed after reorder");
}
```

**Step 2: Run to verify it fails**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke reorder_chunks_still_completes_prepare`
Expected: FAIL (`no method reorder_window`).

**Step 3: Implement**

Add `reorder_window: Option<usize>` to `Faults`. When set, `deliver_all` pops up to `window` chunks from the queue, reverses the slice, and re-enqueues at the front (or uses a seeded Vec shuffle). Keep deterministic (seed or fixed transform). Document that the reorder is applied *before* drop.

**Step 4: Run to verify it passes**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke reorder_chunks_still_completes_prepare`
Expected: PASS.

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs
git commit -m "test(bilateral): FakeNetwork fault — deterministic reorder within window

Out-of-order chunk arrival. Reassembly must still complete because the
coordinator indexes chunks by sequence number."
```

---

## Task 7: Fault injection — partition + heal

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
#[serial]
async fn partition_blocks_delivery_heal_resumes_it() {
    ensure_db();
    let mut pair = PeerPair::spawn("alice", "bob").await;
    pair.establish_relationship().await;
    pair.alice.seed_era_balance(10_000);
    let mut net = pair.wire_network();

    pair.alice.configure_identity_as_local();
    let op = common::ops::transfer(&pair.alice, &pair.bob, 10, "ERA");
    let prepare = pair.alice.adapter
        .create_prepare_message(pair.bob.device_id, op, 300)
        .await.unwrap();
    net.faults_mut().partition();
    net.send_from_alice(BleFrameType::BilateralPrepare, prepare).await;
    let delivered = net.deliver_all().await.unwrap();
    assert_eq!(delivered, 0, "partition blocks all delivery");
    assert!(net.pending_chunks() > 0, "chunks are held, not dropped");

    net.faults_mut().heal();
    let delivered = net.deliver_all().await.unwrap();
    assert!(delivered >= 1, "heal resumes delivery");
}
```

**Step 2: Run to verify it fails**

Expected: FAIL (`no method partition`).

**Step 3: Implement**

Add `partitioned: bool` to `Faults`. When `partition()` is called, set it true; when `heal()` is called, set it false. In `deliver_all`, if partitioned, return early — leave the queue untouched. Held chunks stay in the queue.

**Step 4: Run to verify it passes**

Run: `cargo test -p dsm_sdk --test bilateral_harness_smoke partition_blocks_delivery_heal_resumes_it`
Expected: PASS.

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs
git commit -m "test(bilateral): FakeNetwork fault — partition + heal

Complete BLE outage simulation. Chunks stay queued; delivery resumes on
heal. Lets Phase 2 audit test 'what happens if BLE drops mid-commit'."
```

---

## Task 8: Fault injection — corrupt Nth chunk

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
#[serial]
async fn corrupt_chunk_fails_reassembly_checksum() {
    ensure_db();
    let mut pair = PeerPair::spawn("alice", "bob").await;
    pair.establish_relationship().await;
    pair.alice.seed_era_balance(10_000);
    let mut net = pair.wire_network();

    pair.alice.configure_identity_as_local();
    let op = common::ops::transfer(&pair.alice, &pair.bob, 10, "ERA");
    let prepare = pair.alice.adapter
        .create_prepare_message(pair.bob.device_id, op, 300)
        .await.unwrap();
    net.faults_mut().corrupt_nth(1); // flip a byte in the first chunk
    net.send_from_alice(BleFrameType::BilateralPrepare, prepare).await;
    // Reassembly should return an error (checksum or decode failure).
    let result = net.deliver_all().await;
    assert!(result.is_err() || net.pending_chunks() == 0,
        "corrupted chunk yields error or silent drop; crucially, no commitment is registered");
    let pending = { pair.bob.manager.read().await.list_pending_commitments() };
    assert!(pending.is_empty(), "bob does not register a commitment for corrupted prepare");
}
```

**Step 2: Run to verify it fails**

Expected: FAIL.

**Step 3: Implement**

Add `corrupt_nth: Option<u64>` to `Faults`. When the Nth chunk comes up in `deliver_all`, flip byte 5 of the chunk payload before calling `ingest_chunk`. Document that this is a synthetic byte-flip, not a cryptographic attack.

**Step 4: Run to verify it passes**

Expected: PASS.

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs
git commit -m "test(bilateral): FakeNetwork fault — corrupt Nth chunk flips a byte

Byte-flip before reassembly. Proves the coordinator rejects tampered
chunks (checksum enforcement)."
```

---

## Task 9: NetworkTap — observe every frame on the wire

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
#[serial]
async fn tap_records_all_frame_types_during_happy_path() {
    ensure_db();
    let mut pair = PeerPair::spawn("alice", "bob").await;
    pair.establish_relationship().await;
    pair.alice.seed_era_balance(10_000);
    let mut net = pair.wire_network();

    // ...run the full 3-phase flow like Task 4...

    let tapped = net.tap().frame_types();
    assert!(tapped.contains(&BleFrameType::BilateralPrepare));
    assert!(tapped.contains(&BleFrameType::BilateralPrepareResponse));
    assert!(tapped.contains(&BleFrameType::BilateralConfirm));
    assert!(tapped.contains(&BleFrameType::BilateralCommitResponse));
}
```

**Step 2: Run to verify it fails**

Expected: FAIL.

**Step 3: Implement NetworkTap**

Add a `tap: NetworkTap` field to `FakeNetwork`. In `deliver_all`, on `MessageComplete`, push `(direction, frame_type)` into the tap. Expose `tap()` returning `&NetworkTap` and `NetworkTap::frame_types() -> Vec<BleFrameType>`.

**Step 4: Run to verify it passes**

Expected: PASS.

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs
git commit -m "test(bilateral): FakeNetwork NetworkTap observes every completed frame

Tap exposes frame-level ground truth for Phase 2 audit assertions —
e.g. 'BilateralConfirm is always preceded by BilateralPrepareResponse'."
```

---

## Task 10: MTU clamp to force chunking

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/harness.rs` (or add a small wrapper)
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Investigate**

`MAX_BLE_CHUNK_SIZE` in `ble_frame_coordinator.rs` is a `const`. Clamping it at runtime for tests requires either:
  - (a) a `TransportConfig`-like knob exposed by `BleFrameCoordinator`, or
  - (b) building a custom coordinator that wraps and post-processes the chunk list.

Check if `BleFrameCoordinator::new` accepts MTU config. If not, go route (b): in `FakeNetwork::send_from_*`, after `encode_message`, split any chunk > `test_mtu` into smaller sub-chunks **only if** the protocol supports arbitrary chunk sizes — otherwise skip this task and document that MTU variation is covered by proptest over realistic chunk counts later.

(If route (b) is not safe, mark Task 10 as DEFERRED in the commit message and move on.)

**Step 2: Implement if safe**

```rust
impl FakeNetwork {
    pub fn clamp_mtu(&mut self, _max_chunk_bytes: usize) {
        // If BleFrameCoordinator accepts runtime MTU: apply it. Otherwise
        // document as deferred.
    }
}
```

**Step 3: Test**

If implemented: a test sends a large prepare payload and asserts `>=` N chunks were emitted. If deferred: skip.

**Step 4: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs
git commit -m "test(bilateral): FakeNetwork MTU clamp — [implemented|deferred with rationale]"
```

---

## Task 11: Delay injection (deterministic tick-based)

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
#[serial]
async fn delay_holds_chunks_until_tick_advances() {
    ensure_db();
    let mut pair = PeerPair::spawn("alice", "bob").await;
    pair.establish_relationship().await;
    pair.alice.seed_era_balance(10_000);
    let mut net = pair.wire_network();
    net.faults_mut().delay_ticks(2);

    pair.alice.configure_identity_as_local();
    let op = common::ops::transfer(&pair.alice, &pair.bob, 10, "ERA");
    let prepare = pair.alice.adapter
        .create_prepare_message(pair.bob.device_id, op, 300)
        .await.unwrap();
    net.send_from_alice(BleFrameType::BilateralPrepare, prepare).await;

    let d0 = net.deliver_all().await.unwrap();
    assert_eq!(d0, 0, "tick 0: everything delayed");
    net.advance_tick();
    let d1 = net.deliver_all().await.unwrap();
    assert_eq!(d1, 0, "tick 1: still delayed");
    net.advance_tick();
    let d2 = net.deliver_all().await.unwrap();
    assert!(d2 >= 1, "tick 2: chunks delivered");
}
```

**Step 2: Run to verify it fails**

Expected: FAIL.

**Step 3: Implement logical ticks**

Add `tick: u64` and `delay_ticks: u64` to `Faults`. Each queued chunk carries `due_tick`. `advance_tick()` increments `tick`. `deliver_all` only delivers chunks whose `due_tick <= tick`.

Critical: this is the SDK *transport* tick, not the DSM protocol clock. Protocol still has no wall-clock dependency.

**Step 4: Run to verify it passes**

Expected: PASS.

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common/fake_network.rs \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/bilateral_harness_smoke.rs
git commit -m "test(bilateral): FakeNetwork deterministic delay via logical ticks

Transport-only delay model. No wall-clock; protocol invariant preserved."
```

---

## Task 12: Document the harness API + AppState constraint

**Files:**
- Create: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/README.md`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/tests/common/harness.rs` (module doc at top)

**Step 1: Write the README**

Short (80–120 lines) covering:
- Purpose: device-free bilateral tests
- Components: `TestPeer`, `PeerPair`, `FakeNetwork`, `Faults`, `NetworkTap`
- AppState is process-global → harness tests must be `#[serial_test::serial]`
- Per-peer `configure_identity_as_local()` swaps AppState; call before any step that signs or verifies as that peer
- Per-peer isolated SMT via `new_with_smt` (critical invariant — document why)
- Fault API cheat sheet
- Example: minimal happy-path test (~25 lines)

**Step 2: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/tests/common/README.md \
        dsm_client/deterministic_state_machine/dsm_sdk/tests/common/harness.rs
git commit -m "docs(bilateral): harness README + module-level rustdoc

Documents TestPeer/PeerPair/FakeNetwork, the AppState serialization rule,
and why each peer needs its own SMT."
```

---

## Task 13: Phase 1 exit — run the full suite + announce gate

**Files:** none

**Step 1: Run everything**

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk --test bilateral_harness_smoke -- --nocapture`
Expected: all new tests PASS.

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk`
Expected: full SDK suite still PASS (no regressions).

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm`
Expected: full core suite still PASS.

**Step 2: Summarize**

Write a one-line status for Brandon:
- Harness module lines-of-code
- Fault primitives delivered
- Tests passing
- Any deferred items (e.g. MTU clamp if Task 10 was punted)

**Step 3: Await Phase 2 gate approval**

Do not proceed to Phase 2 (audit) without Brandon's review. Phase 1 exit is:
> "Harness ready. 10+ tests green. Ready to start the race/hazard audit. Proceed?"

---

## Risks and open questions (acknowledge up front)

1. **AppState is process-global.** Every harness test must be `#[serial]`. If Phase 3 wants true concurrency tests across two peers, we'll need to either (a) refactor `AppState` to accept an explicit identity context, or (b) test concurrency within one peer only. Decision deferred to Phase 3.
2. **MTU clamp (Task 10) may need a prod-code touch** to expose `TransportConfig` at coordinator construction. If yes, that's a Phase 1 scope-creep — prefer to defer and cover MTU variation in Phase 4 proptest.
3. **The `deliver_all` loop is deterministic but not adversarial.** Phase 4 proptest will explore interleavings the harness doesn't generate on its own.
4. **`configure_local_identity_for_receipts` exists in the old mock** and does additional assertions beyond AppState setting. Use that file as reference but keep the harness's `configure_identity_as_local` minimal — the assertions belong in tests, not the helper.

## Done means

- 10–12 commits, one per task.
- `tests/bilateral_harness_smoke.rs` exists with at least: happy-path, drop, reorder, partition+heal, corrupt, tap, delay.
- `tests/common/` contains `mod.rs`, `harness.rs`, `fake_network.rs`, `ops.rs`, `README.md`.
- Full SDK + core suites still pass.
- Phase 1 summary posted. Brandon reviews. Phase 2 gate opens or Phase 1 revises.
