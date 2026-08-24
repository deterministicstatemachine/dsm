// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ONE generic recovery sweep for frozen publication artifacts.
//!
//! Every artifact a canonical advance froze (`frozen_publication_artifact`)
//! is owed to a quorum of the storage set it was frozen FOR. This sweep — run
//! at cold boot and on every `storage.sync` push pass — takes the oldest
//! unpublished rows and replays their EXACT bytes to that set's members until
//! `quorum_for(|S|)` of them have accepted. It resolves the row's frozen
//! `storage_set_id` through the local catalog and, if that fails, leaves the
//! row pending — it never substitutes another set and never falls back to
//! "the configured fleet". It never signs, never rebuilds from a later head,
//! and knows nothing about what an artifact means (`purpose` is opaque).
//!
//! Quorum here is delivery, not authority: the canonical transition already
//! decided what is true; publication only makes it discoverable.

use crate::sdk::storage_set::StorageSetCatalog;
use crate::storage::client_db::frozen_publication_artifact as fpa;

/// Split an `immutable::{namespace}::{addr_b32}` object key into its parts.
/// Returns `None` for ordinary keyed objects. The namespace itself contains
/// `/` but never `::`, so splitting on the LAST `::` is unambiguous.
fn parse_immutable_object_key(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix("immutable::")?;
    let idx = rest.rfind("::")?;
    Some((&rest[..idx], &rest[idx + 2..]))
}

/// Bounded work per pass so a large backlog cannot starve the rest of a sync.
pub(crate) const ARTIFACT_REPUBLISH_ROWS_PER_POLL: u32 = 8;

/// Replay up to [`ARTIFACT_REPUBLISH_ROWS_PER_POLL`] unpublished artifacts.
/// Returns how many reached quorum in this pass. Per-row failures are recorded
/// on the row (`last_error`) and never abort the pass.
pub(crate) async fn republish_unpublished_artifacts() -> Result<u32, String> {
    let rows = fpa::list_unpublished_artifacts(ARTIFACT_REPUBLISH_ROWS_PER_POLL)
        .map_err(|e| format!("list unpublished artifacts: {e}"))?;
    republish_rows(rows).await
}

/// The pass proper, over an already-selected batch.
///
/// Split out so a test can hand it a DELIBERATELY STALE batch — the selection
/// happens once, before any network I/O, and everything below is what has to
/// stay correct when the world moves underneath that snapshot.
async fn republish_rows(rows: Vec<fpa::FrozenArtifact>) -> Result<u32, String> {
    if rows.is_empty() {
        return Ok(0);
    }
    let catalog = StorageSetCatalog::from_env_config()
        .map_err(|e| format!("storage-set catalog unavailable: {e}"))?;

    let mut published = 0u32;
    for row in rows {
        // THE ROW MAY HAVE DIED WHILE AN EARLIER ROW WAS IN FLIGHT.
        //
        // `rows` was selected before this pass made a single network call, and
        // every iteration below awaits. A `dlv.close` (or any later generation)
        // committing in that window supersedes this row and publishes its own
        // bytes under the same `.../latest` mirror key. Replaying the stale row
        // afterwards would put an OLDER generation's bytes back on every member
        // — a closed vault would serve its birth anchor again — and the damage
        // would be permanent and invisible: `upsert_artifact_publication_state`
        // declines to write to a superseded row, so nothing records that the
        // fleet now disagrees with us, and `list_unpublished_artifacts` skips
        // published rows, so the newer bytes are never re-sent.
        //
        // The module's own contract is that a superseded row is never replayed.
        // Honour it against the CURRENT state, not the state at selection time.
        match fpa::get_artifact(&row.object_key, &row.content_digest) {
            Ok(Some(current)) => {
                if !matches!(
                    current.state,
                    fpa::ArtifactState::Frozen | fpa::ArtifactState::PublicationPending
                ) {
                    log::info!(
                        "[artifact republish] {} ({}): {} since selection — not replayed",
                        row.object_key,
                        row.purpose,
                        current.state.as_str()
                    );
                    continue;
                }
            }
            Ok(None) => continue,
            Err(e) => {
                log::warn!(
                    "[artifact republish] {}: state re-read failed ({e}) — holding",
                    row.object_key
                );
                continue;
            }
        }
        // THE SET IS THE ROW'S, NOT OURS. An id the catalog cannot re-derive
        // means this device does not know how to reach that set; the bytes stay
        // owed, and are sent nowhere else.
        let Some(set) = catalog.resolve(&row.storage_set_id) else {
            let msg = "frozen storage set is not resolvable through the local catalog; \
                       holding — will not publish to any other set";
            log::warn!(
                "[artifact republish] {} ({}): {msg}",
                row.object_key,
                row.purpose
            );
            fpa::upsert_artifact_publication_state(
                &row.object_key,
                &row.content_digest,
                fpa::ArtifactState::PublicationPending,
                msg,
            )
            .map_err(|e| e.to_string())?;
            continue;
        };

        // The exact frozen bytes, to the exact set. Nothing is regenerated.
        // Keys of the shape `immutable::{namespace}::{addr_b32}` are Area-4
        // immutable tuples and travel through the write-once immutable
        // endpoint; everything else is an ordinary keyed object.
        let fanout_result =
            if let Some((namespace, addr_b32)) = parse_immutable_object_key(&row.object_key) {
                crate::sdk::storage_io::put_immutable_to_all_members(
                    set,
                    namespace,
                    &row.payload,
                    addr_b32,
                )
                .await
            } else {
                crate::sdk::storage_io::put_bytes_to_all_members(set, &row.object_key, &row.payload)
                    .await
            };
        let fanout = match fanout_result {
            Ok(f) => f,
            Err(e) => {
                fpa::upsert_artifact_publication_state(
                    &row.object_key,
                    &row.content_digest,
                    fpa::ArtifactState::PublicationPending,
                    &format!("fan-out failed: {e}"),
                )
                .map_err(|e| e.to_string())?;
                continue;
            }
        };
        for o in &fanout.outcomes {
            if o.accepted {
                fpa::record_accepting_member(&row.object_key, &o.member_id, &row.content_digest)
                    .map_err(|e| e.to_string())?;
            }
        }
        let accepted = fpa::count_accepting_members(&row.object_key, &row.content_digest)
            .map_err(|e| e.to_string())?;
        if accepted >= set.quorum() {
            fpa::upsert_artifact_publication_state(
                &row.object_key,
                &row.content_digest,
                fpa::ArtifactState::Published,
                "",
            )
            .map_err(|e| e.to_string())?;
            published += 1;
            log::info!(
                "[artifact republish] {} ({}) published: {accepted}/{} members",
                row.object_key,
                row.purpose,
                set.len()
            );
        } else {
            let errs: Vec<String> = fanout
                .outcomes
                .iter()
                .filter_map(|o| o.error.as_ref().map(|e| format!("{}: {e}", o.member_id)))
                .collect();
            fpa::upsert_artifact_publication_state(
                &row.object_key,
                &row.content_digest,
                fpa::ArtifactState::PublicationPending,
                &format!(
                    "{accepted}/{} accepted (quorum {}); {}",
                    set.len(),
                    set.quorum(),
                    errs.join("; ")
                ),
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(published)
}

/// Cold-boot / warm-swap entry: run one pass in the background. NOT gated on
/// the wallet seed — frozen payloads are plain bytes and the fan-out needs only
/// storage auth. Errors are logged; the `storage.sync` pass retries.
pub(crate) fn spawn_frozen_artifact_republish(origin: &'static str) {
    crate::runtime::get_runtime().spawn(async move {
        match republish_unpublished_artifacts().await {
            Ok(0) => {}
            Ok(n) => log::info!("[SDK] frozen artifact republish ({origin}): {n} reached quorum"),
            Err(e) => {
                log::warn!("[SDK] frozen artifact republish ({origin}) errored (non-fatal): {e}")
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::storage_io::fake_fleet;
    use crate::storage::client_db::{get_connection, reset_database_for_tests};
    use serial_test::serial;

    fn init() -> StorageSetCatalog {
        // The sweep resolves a row's FROZEN set through the catalog, so these
        // tests must use the catalog's own set — and therefore must pin which
        // catalog that is. Clearing the path any earlier test pointed the
        // loader at is what makes the hermetic three-node default reachable;
        // without it this module inherits whichever fleet ran first and the
        // partition assertions below stop meaning anything.
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
            std::env::remove_var("DSM_ENV_CONFIG_PATH");
        };
        reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        fake_fleet::reset();
        StorageSetCatalog::from_env_config().expect("test catalog")
    }

    fn freeze(set: &[u8; 32], key: &str, payload: &[u8]) -> [u8; 32] {
        let binding = get_connection().expect("db");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        fpa::freeze_artifact_with_conn(&conn, set, key, payload, &[0x11; 32], "test")
            .expect("freeze")
    }

    fn state_of(key: &str, digest: &[u8; 32]) -> fpa::ArtifactState {
        fpa::get_artifact(key, digest).unwrap().expect("row").state
    }

    #[tokio::test]
    #[serial]
    async fn sweep_replays_exact_frozen_bytes_to_the_frozen_set_and_publishes_at_quorum() {
        let cat = init();
        let set = cat.sole_set().expect("one set");
        let sid = set.id();
        let d1 = freeze(&sid, "sofi/x/latest", b"payload-one");
        let d2 = freeze(&sid, "sofi/y/seq-0", b"payload-two");
        // One member down: 2 of 3 still reach quorum.
        fake_fleet::fail_member("test-3");

        let n = republish_unpublished_artifacts().await.expect("sweep");
        assert_eq!(n, 2, "both artifacts reached quorum");
        assert_eq!(
            state_of("sofi/x/latest", &d1),
            fpa::ArtifactState::Published
        );
        assert_eq!(state_of("sofi/y/seq-0", &d2), fpa::ArtifactState::Published);
        // The bytes that landed are the frozen bytes, byte for byte.
        assert_eq!(
            fake_fleet::stored("test-1", "sofi/x/latest").as_deref(),
            Some(&b"payload-one"[..])
        );
        assert_eq!(
            fake_fleet::stored("test-2", "sofi/y/seq-0").as_deref(),
            Some(&b"payload-two"[..])
        );
        assert!(
            fake_fleet::stored("test-3", "sofi/x/latest").is_none(),
            "the failed member holds nothing"
        );
        // Every PUT that was attempted carried the frozen payload's digest —
        // nothing was rebuilt.
        for (_, key, digest) in fake_fleet::put_log() {
            let expected = if key == "sofi/x/latest" {
                b"payload-one".as_slice()
            } else {
                b"payload-two"
            };
            assert_eq!(
                digest,
                *blake3::hash(expected).as_bytes(),
                "PUT bytes == frozen bytes"
            );
        }
        assert_eq!(
            fpa::count_accepting_members("sofi/x/latest", &d1).unwrap(),
            2
        );
        // Nothing left to sweep.
        assert_eq!(republish_unpublished_artifacts().await.unwrap(), 0);
    }

    #[tokio::test]
    #[serial]
    async fn a_row_stays_pending_below_quorum_and_the_retry_replays_the_same_bytes() {
        let cat = init();
        let sid = cat.sole_set().unwrap().id();
        let d = freeze(&sid, "sofi/z/latest", b"gen0");
        fake_fleet::fail_member("test-2");
        fake_fleet::fail_member("test-3");
        assert_eq!(republish_unpublished_artifacts().await.unwrap(), 0);
        let row = fpa::get_artifact("sofi/z/latest", &d).unwrap().unwrap();
        assert_eq!(row.state, fpa::ArtifactState::PublicationPending);
        assert!(
            row.last_error.contains("1/3 accepted"),
            "last_error: {}",
            row.last_error
        );

        // A member comes back: the retry replays the SAME frozen bytes and now
        // reaches quorum. The member that already held them keeps counting.
        fake_fleet::heal_member("test-2");
        assert_eq!(republish_unpublished_artifacts().await.unwrap(), 1);
        assert_eq!(state_of("sofi/z/latest", &d), fpa::ArtifactState::Published);
        let digests: std::collections::BTreeSet<[u8; 32]> = fake_fleet::put_log()
            .into_iter()
            .filter(|(_, k, _)| k == "sofi/z/latest")
            .map(|(_, _, dg)| dg)
            .collect();
        assert_eq!(digests.len(), 1, "every attempt PUT identical bytes");
        assert_eq!(
            digests.into_iter().next().unwrap(),
            *blake3::hash(b"gen0").as_bytes()
        );
    }

    #[tokio::test]
    #[serial]
    async fn an_unresolvable_frozen_set_is_held_and_sent_nowhere() {
        let _cat = init();
        let foreign = crate::sdk::storage_set::compute_storage_set_id(&["c", "d", "e"]).unwrap();
        let d = freeze(&foreign, "sofi/foreign/latest", b"bytes");
        assert_eq!(republish_unpublished_artifacts().await.unwrap(), 0);
        let row = fpa::get_artifact("sofi/foreign/latest", &d)
            .unwrap()
            .unwrap();
        assert_eq!(row.state, fpa::ArtifactState::PublicationPending);
        assert!(
            row.last_error.contains("not resolvable"),
            "{}",
            row.last_error
        );
        assert!(
            fake_fleet::put_log().is_empty(),
            "an unresolvable set is never substituted with the configured fleet"
        );
    }

    #[tokio::test]
    #[serial]
    async fn a_node_echoing_another_members_id_does_not_count() {
        let cat = init();
        let sid = cat.sole_set().unwrap().id();
        let d = freeze(&sid, "sofi/echo/latest", b"bytes");
        // test-1 answers as if it were test-2 (two catalog entries on one box);
        // test-3 is down. Only test-2's own acceptance may count.
        fake_fleet::set_echo("test-1", Some("test-2"));
        fake_fleet::fail_member("test-3");
        assert_eq!(republish_unpublished_artifacts().await.unwrap(), 0);
        assert_eq!(
            fpa::count_accepting_members("sofi/echo/latest", &d).unwrap(),
            1
        );
        assert_eq!(
            state_of("sofi/echo/latest", &d),
            fpa::ArtifactState::PublicationPending
        );
        // Identity restored: quorum.
        fake_fleet::set_echo("test-1", Some("test-1"));
        assert_eq!(republish_unpublished_artifacts().await.unwrap(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn a_superseded_generation_is_never_swept() {
        let cat = init();
        let sid = cat.sole_set().unwrap().id();
        let d0 = freeze(&sid, "sofi/latest", b"gen0");
        let d1 = freeze(&sid, "sofi/latest", b"gen1");
        assert_eq!(republish_unpublished_artifacts().await.unwrap(), 1);
        assert_eq!(state_of("sofi/latest", &d0), fpa::ArtifactState::Superseded);
        assert_eq!(state_of("sofi/latest", &d1), fpa::ArtifactState::Published);
        let put_digests: Vec<[u8; 32]> = fake_fleet::put_log()
            .into_iter()
            .map(|(_, _, dg)| dg)
            .collect();
        assert!(put_digests
            .iter()
            .all(|dg| *dg == *blake3::hash(b"gen1").as_bytes()));
        assert_eq!(
            fake_fleet::stored("test-1", "sofi/latest").as_deref(),
            Some(&b"gen1"[..]),
            "members hold the current generation"
        );
    }
    /// A ROW SUPERSEDED *AFTER* SELECTION IS NOT REPLAYED.
    ///
    /// `a_superseded_generation_is_never_swept` above cannot catch this: the
    /// SELECT already filters superseded rows, so it passes whether or not the
    /// pass re-checks anything. The dangerous case is the row that was
    /// legitimately selected and then died while an EARLIER row of the same
    /// batch was in flight — every iteration awaits, and a `dlv.close`
    /// committing in that window supersedes this row and publishes its own
    /// bytes under the same `.../latest` mirror.
    ///
    /// Replaying it then puts an older generation back on every member. That
    /// damage is permanent AND silent: `upsert_artifact_publication_state`
    /// declines to write to a superseded row, so nothing records the
    /// divergence, and `list_unpublished_artifacts` skips published rows, so
    /// the newer bytes are never re-sent. A closed vault would serve its birth
    /// anchor to every trader, forever.
    ///
    /// The stale batch is handed to `republish_rows` directly, which is exactly
    /// what the real pass holds after its own SELECT.
    #[tokio::test]
    #[serial]
    async fn a_row_superseded_after_selection_is_not_replayed_over_the_newer_one() {
        let cat = init();
        let sid = cat.sole_set().unwrap().id();

        // gen0 is frozen and legitimately selected while it is still current.
        let d0 = freeze(&sid, "sofi/latest", b"gen0");
        let selected = fpa::list_unpublished_artifacts(8).expect("select");
        assert_eq!(selected.len(), 1, "gen0 was selected while current");
        assert_eq!(selected[0].content_digest, d0);

        // The world moves: a close freezes gen1 under the same mirror key and
        // publishes it to quorum. gen0 is now superseded.
        let d1 = freeze(&sid, "sofi/latest", b"gen1");
        assert_eq!(republish_unpublished_artifacts().await.unwrap(), 1);
        assert_eq!(state_of("sofi/latest", &d1), fpa::ArtifactState::Published);
        assert_eq!(state_of("sofi/latest", &d0), fpa::ArtifactState::Superseded);
        assert_eq!(
            fake_fleet::stored("test-1", "sofi/latest").as_deref(),
            Some(&b"gen1"[..])
        );

        // Now the in-flight pass reaches its stale row.
        let published = republish_rows(selected).await.expect("stale pass");
        assert_eq!(published, 0, "a dead row publishes nothing");

        // THE FLEET STILL HOLDS THE NEWER GENERATION, on every member.
        for m in ["test-1", "test-2", "test-3"] {
            assert_eq!(
                fake_fleet::stored(m, "sofi/latest").as_deref(),
                Some(&b"gen1"[..]),
                "{m} must not have been rolled back to gen0"
            );
        }
        // And gen0's bytes were never sent at all after it died — asserted on
        // the wire, not only on the resulting state, because a PUT that landed
        // and was then overwritten would leave the same final state.
        let gen0 = *blake3::hash(b"gen0").as_bytes();
        assert_eq!(
            fake_fleet::put_log()
                .into_iter()
                .filter(|(_, k, dg)| k == "sofi/latest" && *dg == gen0)
                .count(),
            0,
            "the superseded bytes were never put on the wire"
        );
        // The newer row is untouched — still published, still the latest.
        assert_eq!(state_of("sofi/latest", &d1), fpa::ArtifactState::Published);
        assert!(fpa::is_artifact_published("sofi/latest").unwrap());
    }
}
