// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the anchor allocates, operation by operation, against the heap the monitor gives it. An
//! allocation the Secure heap cannot meet halts the board, so the budget is held here, on the model,
//! rather than found on a chip. This binary holds one test so that nothing else allocates beside it.

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use anchor_chip::bring_up::Measurement;
use anchor_chip::SECURE_HEAP_BYTES;
use anchor_core::proto::{encode_request, pb};
use anchor_core::root_advance::{anchor_root_advance, transition_digest, OwnedTransition};
use anchor_core::service::REQUEST_HEAD_MAX;
use anchor_core::tropic::PartitionSig;
use support::{authorization_for, provision_request, try_run_request, ModelServer, Served};

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
    // A try-run is two requests; the wallet's signing between them is the host's work, measured
    // nowhere here. The anchor's two halves are: the birth into the trial slots, and the payment
    // with the authorization's frame held and checked.
    let rehearse = |anchor: &mut Served, request: pb::ApplianceRequest, what: &str| {
        let begun = peak_of(&format!("{what}, begun"), ceiling, || {
            anchor.request(&request)
        });
        assert!(
            begun.ok,
            "{what} begun: error {} {}",
            begun.error, begun.detail
        );
        let digest: [u8; 32] = match begun.awaiting_authorization.as_slice().try_into() {
            Ok(digest) => digest,
            Err(e) => panic!("a 32-byte digest: {e}"),
        };
        let signature = match anchor_chip::bring_up::SphincsPart::owner_sign(
            &support::rehearsal_key().0,
            &digest,
        ) {
            Ok(sig) => sig,
            Err(e) => panic!("the rehearsal key signs: {e:?}"),
        };
        drop(begun);
        let frame = support::authorize_frame(&digest, &signature);
        drop(signature);
        peak_of(&format!("{what}, authorized and finished"), ceiling, || {
            anchor.frame(frame, Measurement::Matches)
        })
    };
    let run = rehearse(&mut anchor, try_run_request(), "try-run");
    assert!(run.ok, "the try-run: {:?}", run.try_run);
    drop(run);
    let answer = rehearse(
        &mut anchor,
        provision_request(),
        "provision, its own try-run first",
    );
    assert!(answer.ok, "provision: error {}", answer.error);
    drop(answer);
    let status = peak_of("status", ceiling, || anchor.bare(pb::Op::Status));
    assert!(status.ok, "status: error {}", status.error);
    let root: [u8; 32] = match status.active_root.as_slice().try_into() {
        Ok(root) => root,
        Err(e) => panic!("a 32-byte frontier: {e}"),
    };

    let bundle = status.anchor_bundle.clone();
    let prepare = |proof_bytes| pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(transition(root, 0, proof_bytes).to_pb()),
        receiver_challenge: vec![0x55; 32],
        sender_device_root_before: vec![0x51; 32],
        sender_device_root_after: vec![0x52; 32],
        ..Default::default()
    };
    // The owner's authorization: signed by the host outside what is measured; the frame, the one
    // copy the monitor holds, and its check are the anchor's.
    let authorize = |anchor: &mut Served, request: &pb::ApplianceRequest, name: &str| {
        let nonce = anchor.authorization_nonce();
        let (digest, signature) = authorization_for(request, &bundle, &nonce);
        let frame = support::authorize_frame(&digest, &signature);
        drop(signature);
        let answer = peak_of(name, ceiling, || anchor.frame(frame, Measurement::Matches));
        assert!(answer.ok, "authorize: error {}", answer.error);
    };

    // The largest request message the monitor takes, then cancelled so the spend below is the
    // wallet's. Its authorization first: the frame the monitor holds, one signature long, and its
    // check.
    let framing = encode_request(&prepare(0)).len();
    let largest = prepare(REQUEST_HEAD_MAX - framing - 8);
    assert!(encode_request(&largest).len() <= REQUEST_HEAD_MAX);
    authorize(&mut anchor, &largest, "authorize, the largest request's");
    let answer = peak_of("prepare, the largest request", ceiling, || {
        anchor.request(&largest)
    });
    assert!(answer.ok, "prepare: error {}", answer.error);
    let answer = anchor.bare(pb::Op::Cancel);
    assert!(answer.ok, "cancel: error {}", answer.error);

    let wallets = prepare(0);
    authorize(&mut anchor, &wallets, "authorize, as the wallet sends it");
    let answer = peak_of("prepare, as the wallet sends it", ceiling, || {
        anchor.request(&wallets)
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
    let pay = prepare_of(&paid, &challenge, [0x51; 32], [0x52; 32]);
    authorize(&mut anchor, &pay, "authorize, the payment's");
    served(anchor.request(&pay), "pay");
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
    let receive = prepare_of(&t, &challenge, [0x71; 32], [0x72; 32]);
    authorize(&mut anchor, &receive, "authorize, the receive's");
    peak_of("receive prepare", ceiling, || {
        served(anchor.request(&receive), "receive")
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
