// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the anchor allocates, operation by operation, against the heap the monitor gives it. An
//! allocation the Secure heap cannot meet halts the board, so the budget is held here, on the model,
//! rather than found on a chip. This binary holds one test so that nothing else allocates beside it.

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use anchor_chip::{MAX_REQUEST_BYTES, SECURE_HEAP_BYTES};
use anchor_core::proto::{encode_request, pb};
use anchor_core::root_advance::{anchor_root_advance, transition_digest, OwnedTransition};
use support::{provision_request, try_run_request, ModelServer, Served};

struct Counted;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards each call to the system allocator unchanged and only counts around it.
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
        PEAK.fetch_max(live, Ordering::SeqCst);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static HEAP: Counted = Counted;

/// Run `op` and report how far above what is live now it took the heap.
fn peak_of<T>(name: &str, ceiling: usize, op: impl FnOnce() -> T) -> T {
    let before = LIVE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let out = op();
    let peak = PEAK.load(Ordering::SeqCst);
    eprintln!("{name}: {peak} bytes at its peak ({before} live before it)");
    assert!(
        peak <= ceiling,
        "{name} reached {peak} bytes of a {ceiling}-byte budget"
    );
    out
}

/// A transition carrying `proof_bytes` of proofs. The wallet's own carry none: it attaches them to the
/// release after the emit.
fn transition(prev_root: [u8; 32], counter: u64, proof_bytes: usize) -> OwnedTransition {
    let challenge = [0x55; 32];
    let mut t = OwnedTransition {
        relationship_id: [1; 32],
        object_id: [2; 32],
        sender_device_id: [0x77; 32],
        recipient_device_id: [0x44; 32],
        prev_root,
        next_root: prev_root,
        anchor_counter: counter,
        next_anchor_counter: counter + 1,
        action_type: 0,
        action_fields: Vec::new(),
        payload_hash: [6; 32],
        old_leaf_proof: vec![0xAB; proof_bytes],
        new_leaf_proof: Vec::new(),
        authority_policy_hash: [0x33; 32],
    };
    let digest = transition_digest(&t.as_transition(), &challenge);
    t.next_root = anchor_root_advance(&prev_root, &digest);
    t
}

#[test]
fn every_operation_fits_the_secure_heap() {
    // The heap also holds what fragmentation strands, so an operation may reach three quarters of it.
    let ceiling = SECURE_HEAP_BYTES / 4 * 3;
    let model = ModelServer::start();
    let booted = peak_of("boot, unprovisioned", ceiling, || model.boot());
    let mut anchor = match booted {
        Ok(anchor) => Served::new(anchor),
        Err(e) => panic!("the anchor did not come up: {e:?}"),
    };
    let run = peak_of("try-run", ceiling, || anchor.request(&try_run_request()));
    assert!(run.ok, "the try-run: {:?}", run.try_run);
    drop(run);
    let answer = peak_of("provision, its own try-run first", ceiling, || {
        anchor.request(&provision_request())
    });
    assert!(answer.ok, "provision: error {}", answer.error);
    drop(answer);
    let status = peak_of("status", ceiling, || anchor.bare(pb::Op::Status));
    assert!(status.ok, "status: error {}", status.error);
    let root: [u8; 32] = match status.active_root.as_slice().try_into() {
        Ok(root) => root,
        Err(e) => panic!("a 32-byte frontier: {e}"),
    };

    let prepare = |proof_bytes| pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(transition(root, 0, proof_bytes).to_pb()),
        receiver_challenge: vec![0x55; 32],
        sender_device_root_before: vec![0x51; 32],
        sender_device_root_after: vec![0x52; 32],
        ..Default::default()
    };

    // The largest request the monitor takes, then cancelled so the spend below is the wallet's.
    let framing = encode_request(&prepare(0)).len();
    let largest = prepare(MAX_REQUEST_BYTES - framing - 8);
    assert!(encode_request(&largest).len() <= MAX_REQUEST_BYTES);
    let answer = peak_of("prepare, the largest request", ceiling, || {
        anchor.request(&largest)
    });
    assert!(answer.ok, "prepare: error {}", answer.error);
    let answer = anchor.bare(pb::Op::Cancel);
    assert!(answer.ok, "cancel: error {}", answer.error);

    let answer = peak_of("prepare, as the wallet sends it", ceiling, || {
        anchor.request(&prepare(0))
    });
    assert!(answer.ok, "prepare: error {}", answer.error);
    let answer = peak_of("commit", ceiling, || anchor.bare(pb::Op::Commit));
    assert!(answer.ok, "commit: error {}", answer.error);
    let answer = peak_of("emit", ceiling, || anchor.bare(pb::Op::Emit));
    assert!(answer.ok, "emit: error {}", answer.error);
    drop(answer);
    drop(anchor);

    // A boot that restores a committed record and recovers it holds the record twice over.
    let rebooted = peak_of("boot, committed record", ceiling, || model.boot());
    let mut anchor = match rebooted {
        Ok(anchor) => Served::new(anchor),
        Err(e) => panic!("the anchor did not come back: {e:?}"),
    };
    let answer = peak_of("finalize", ceiling, || anchor.bare(pb::Op::Finalize));
    assert!(answer.ok, "finalize: error {}", answer.error);

    // The receiver's side: a challenge, a payment made for it (the anchor's own, standing in for a
    // payer's), its check, the largest request any op takes, and the receive.
    use support::{
        check_of, disclosure_of, prepare_of, receive_of, self_payment, served, thirty_two,
    };
    let status = served(anchor.bare(pb::Op::Status), "status");
    let challenge = thirty_two(
        &peak_of("challenge", ceiling, || {
            served(anchor.bare(pb::Op::Challenge), "challenge")
        })
        .receiver_challenge,
        "the challenge",
    );
    let paid = self_payment(thirty_two(&status.active_root, "h"), 1, &challenge);
    served(
        anchor.request(&prepare_of(&paid, &challenge, [0x51; 32], [0x52; 32])),
        "pay",
    );
    served(anchor.bare(pb::Op::Commit), "commit");
    let release = match served(anchor.bare(pb::Op::Emit), "emit").release {
        Some(release) => match release.to_release() {
            Ok(release) => release,
            Err(e) => panic!("the release decodes: {e:?}"),
        },
        None => panic!("the emit carried no release"),
    };
    let root = thirty_two(
        &served(anchor.bare(pb::Op::Finalize), "finalize").active_root,
        "h",
    );
    let check = check_of(&release, &disclosure_of(&status));
    assert!(
        encode_request(&check).len() <= anchor_core::service::MAX_PAYMENT_CHECK_BYTES,
        "a payment check fits the frame the monitor takes"
    );
    drop(release);
    peak_of("payment check, the largest request", ceiling, || {
        served(anchor.request(&check), "the check")
    });
    let paid = match check.payment.as_ref().map(|p| p.to_release()) {
        Some(Ok(paid)) => paid,
        other => panic!("the checked payment decodes: {:?}", other.map(|r| r.err())),
    };
    let t = receive_of(&paid, root, 2, &challenge);
    drop(paid);
    drop(check);
    peak_of("receive prepare", ceiling, || {
        served(
            anchor.request(&prepare_of(&t, &challenge, [0x71; 32], [0x72; 32])),
            "receive",
        )
    });
    peak_of("receive commit", ceiling, || {
        served(anchor.bare(pb::Op::Commit), "commit")
    });
    drop(peak_of("receive emit", ceiling, || {
        served(anchor.bare(pb::Op::Emit), "emit")
    }));
    peak_of("receive finalize", ceiling, || {
        served(anchor.bare(pb::Op::Finalize), "finalize")
    });
}
