// SPDX-License-Identifier: MIT OR Apache-2.0
//! Each device's one backup slot (DSM Amendment A40; owner, 2026-11-23: "There
//! only should be one backup per phone, per device", "incomplete backups
//! should still be written over", and "it needs the key to do such a thing"),
//! executed against the served assembly on a Postgres database of its own.
//!
//! A slot holds one whole backup and at most one being written. Only the
//! device's cell lock starts a write; a part is taken only as the digest its
//! start names; a write cut short is written over by the next start; and the
//! moment every part of the one being written is held, it replaces the whole
//! one, whose parts are gone from the store.

mod common;

use axum::{http::StatusCode, Router};
use common::call;
use dsm::crypto::sphincs::{generate_keypair_from_seed, SphincsKeyPair};
use dsm::owned_cell::CELL_LOCK_VARIANT;
use dsm::utils::text_id;
use dsm::wallet_backup::{part_digest, BackupKeys};
use prost::Message;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    common::ok_or_panic(result, context)
}

fn lock(seed: u8) -> SphincsKeyPair {
    ok(
        generate_keypair_from_seed(CELL_LOCK_VARIANT, &[seed; 32]),
        "a lock",
    )
}

/// A backup of `parts`, sealed for `generation` at the slot.
fn parts_of(keys: &BackupKeys, slot: &[u8; 32], generation: u64, parts: &[&[u8]]) -> Vec<Vec<u8>> {
    let count = ok(u32::try_from(parts.len()), "the count");
    parts
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let i = ok(u32::try_from(i), "the index");
            ok(keys.seal(slot, generation, i, count, chunk), "sealed")
        })
        .collect()
}

fn digests(parts: &[Vec<u8>]) -> Vec<[u8; 32]> {
    parts.iter().map(|p| part_digest(p)).collect()
}

fn path(slot: &[u8; 32]) -> String {
    format!("/api/v2/backup/{}", text_id::encode_base32_crockford(slot))
}

fn state(body: &[u8]) -> dsm::types::proto::BackupSlotV1 {
    ok(
        dsm::types::proto::BackupSlotV1::decode(body),
        "BackupSlotV1",
    )
}

async fn start(app: &Router, slot: &[u8; 32], bytes: Vec<u8>) -> (StatusCode, Vec<u8>) {
    call(app, "POST", &path(slot), &[], bytes).await
}

async fn put_part(
    app: &Router,
    slot: &[u8; 32],
    generation: u64,
    part: usize,
    bytes: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    call(
        app,
        "POST",
        &format!("{}/{generation}/{part}", path(slot)),
        &[],
        bytes,
    )
    .await
}

async fn read_part(app: &Router, slot: &[u8; 32], generation: u64, part: usize) -> Vec<u8> {
    let (status, body) = call(
        app,
        "GET",
        &format!("{}/{generation}/{part}", path(slot)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body
}

async fn read_slot(app: &Router, slot: &[u8; 32]) -> dsm::types::proto::BackupSlotV1 {
    let (status, body) = call(app, "GET", &path(slot), &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    state(&body)
}

/// How many parts of any generation the store holds at `slot`.
async fn stored_parts(pool: &dsm_storage_node::db::DBPool, slot: &[u8; 32]) -> i64 {
    let client = ok(pool.get().await, "connection");
    ok(
        client
            .query_one(
                "SELECT COUNT(*) FROM backup_parts WHERE slot_key = $1",
                &[&slot.as_slice()],
            )
            .await,
        "count",
    )
    .get(0)
}

/// Write `parts` as `generation`, start then every part: the slot's state
/// after the last part.
async fn write_whole(
    app: &Router,
    keys: &BackupKeys,
    owner: &SphincsKeyPair,
    generation: u64,
    parts: &[Vec<u8>],
) -> dsm::types::proto::BackupSlotV1 {
    let (slot, bytes) = ok(keys.start(owner, generation, &digests(parts)), "a start");
    let (status, _) = start(app, &slot, bytes).await;
    assert_eq!(status, StatusCode::OK, "the owner's start is taken");
    let mut last = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let (status, body) = put_part(app, &slot, generation, i, part.clone()).await;
        assert_eq!(status, StatusCode::OK, "part {i} is taken");
        last = body;
    }
    state(&last)
}

/// A slot holds one backup: the next whole one replaces it and its parts
/// leave the store; one cut short holds nothing a reader takes and is written
/// over by the next start; an older start, replayed, is refused; and only the
/// device's lock starts a write.
/// MUTATION CONTROL: keeping the earlier whole backup's parts in
/// `db::backup_part` (dropping its DELETE) turns the store count red; taking
/// a start of a lower generation in `db::backup_start` turns the replay red;
/// taking a part whatever its digest turns the forged part red; taking a start
/// unsigned in `dsm::wallet_backup::admit_start` turns the forged start red
/// (run 2026-11-23, with the old backup cells' check dropped: that test red).
#[test]
fn a_device_holds_one_backup_and_it_is_written_over() {
    common::runtime().block_on(async {
        let pool = common::fresh_store("backup_slot_one_per_device").await;
        let app = common::member("member", pool.clone());
        let keys = BackupKeys::of_wallet_seed(&[0x42; 64]);
        let owner = lock(0x11);
        let slot = keys.slot(&owner.public_key);

        assert_eq!(read_slot(&app, &slot).await.generation, 0, "nothing yet");

        // Generation 1, whole.
        let first = parts_of(&keys, &slot, 1, &[b"contacts, part one", b"part two"]);
        let held = write_whole(&app, &keys, &owner, 1, &first).await;
        assert_eq!((held.generation, held.highest_generation), (1, 1));
        assert_eq!(read_part(&app, &slot, 1, 1).await, first[1]);
        assert_eq!(stored_parts(&pool, &slot).await, 2);

        // Generation 2 is cut short after one part: the whole backup is still
        // generation 1, and a reader asking for 2 gets nothing.
        let cut = parts_of(&keys, &slot, 2, &[b"cut", b"short", b"here"]);
        let (slot2, bytes) = ok(keys.start(&owner, 2, &digests(&cut)), "a start");
        assert_eq!(slot2, slot);
        assert_eq!(start(&app, &slot, bytes).await.0, StatusCode::OK);
        let (status, body) = put_part(&app, &slot, 2, 0, cut[0].clone()).await;
        assert_eq!(status, StatusCode::OK);
        let writing = state(&body);
        assert_eq!((writing.generation, writing.highest_generation), (1, 2));
        assert!(read_part(&app, &slot, 2, 0).await.is_empty(), "not whole");
        assert_eq!(
            read_part(&app, &slot, 1, 0).await,
            first[0],
            "1 still whole"
        );

        // A part whose digest the start does not name is refused.
        let forged = parts_of(&keys, &slot, 2, &[b"cut", b"forged", b"here"]);
        assert_eq!(
            put_part(&app, &slot, 2, 1, forged[1].clone()).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            put_part(&app, &slot, 2, 3, cut[2].clone()).await.0,
            StatusCode::BAD_REQUEST,
            "no such part"
        );

        // Generation 3 writes over the one cut short, then replaces 1.
        let third = parts_of(&keys, &slot, 3, &[b"the latest contacts"]);
        let held = write_whole(&app, &keys, &owner, 3, &third).await;
        assert_eq!((held.generation, held.highest_generation), (3, 3));
        assert_eq!(read_part(&app, &slot, 3, 0).await, third[0]);
        assert!(read_part(&app, &slot, 1, 0).await.is_empty(), "1 is gone");
        assert_eq!(
            stored_parts(&pool, &slot).await,
            1,
            "one backup's parts, nothing of 1 or of the one cut short"
        );
        assert_eq!(
            put_part(&app, &slot, 2, 1, cut[1].clone()).await.0,
            StatusCode::CONFLICT,
            "the one cut short takes no more parts"
        );

        // The same start again is answered as the whole one; an older one,
        // replayed, is refused.
        let (_, again) = ok(keys.start(&owner, 3, &digests(&third)), "a start");
        assert_eq!(start(&app, &slot, again).await.0, StatusCode::OK);
        let (_, older) = ok(keys.start(&owner, 1, &digests(&first)), "a start");
        let (status, body) = start(&app, &slot, older).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(state(&body).highest_generation, 3, "names the highest");

        // Another device's lock does not start a write here: neither its own
        // start, nor its signature carried under the owner's lock.
        let (_, theirs) = ok(keys.start(&lock(0x22), 9, &digests(&third)), "their start");
        assert_eq!(
            start(&app, &slot, theirs.clone()).await.0,
            StatusCode::FORBIDDEN
        );
        let mut forged = ok(
            dsm::types::proto::BackupSlotStartV1::decode(theirs.as_slice()),
            "their start decodes",
        );
        forged.lock_public_key = owner.public_key.clone();
        assert_eq!(
            start(&app, &slot, forged.encode_to_vec()).await.0,
            StatusCode::FORBIDDEN,
            "a stranger's signature under the owner's lock"
        );
        assert_eq!(read_slot(&app, &slot).await.generation, 3);
    });
}

/// The backup cells of before the slot are no longer a place: a write there
/// is refused, whoever carries it.
/// MUTATION CONTROL: dropping the retired namespace from
/// `dsm::owned_cell::ownership` turns this red.
#[test]
fn the_old_backup_cells_take_no_write() {
    common::runtime().block_on(async {
        let pool = common::fresh_store("backup_cells_retired").await;
        let app = common::member("member", pool);
        let key = text_id::encode_base32_crockford(&[0x5C; 32]);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/api/v2/cell/{key}"),
            &[("x-namespace", "DSM/wallet-backup/v1")],
            b"an old part".to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}
