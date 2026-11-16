// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one in-place upgrade a beta wallet makes: from the database
//! 0.1.0-beta.4 shipped (version 47), or a build between it and this one (48),
//! to [`super::CLIENT_DB_SCHEMA_VERSION`].
//!
//! Owner, 2026-11-15, asked twice whether the 0.1.1-beta.4 wallet may upgrade
//! a beta.4 database in place against the beta rule that nothing migrates:
//! "Yeah, I make that upgrade. I can't afford to waste those." and "yes,
//! second yes". The wallets in question own hardware boards installed to them
//! for good, and a board refuses a second install, so the wallet must keep
//! what binds it: its sealed seed, its genesis and device id, and its public
//! key. The beta storage fleet was reprovisioned the same night, so everything
//! the wallet knew of the network (positions, balances, contacts,
//! relationships, inboxes, publications) describes nodes that no longer hold
//! it; that is emptied, and the wallet starts its network life again from its
//! genesis head through its ordinary start (directory entry, activation,
//! faucet).
//!
//! The whole upgrade is one transaction: on any failure the file stays exactly
//! as it was, at its old version, and the open refuses it as before.

use anyhow::{anyhow, Result};
use dsm::types::device_state::{DeviceState, RealizedHead};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

/// The versions this build upgrades in place.
const UPGRADED_FROM: [i64; 2] = [47, 48];

/// The tables whose rows the upgrade keeps exactly: the device's identity and
/// secrets, and other devices' boards this device pinned (dropping those would
/// reopen the first-transfer trust window, `anchor_enrollments` in
/// `create_schema`). Every other table of the old file describes the network
/// that was reprovisioned and is emptied. `bcr_device_heads`,
/// `identity_publication` and `recovery_prefs` are rewritten, not kept.
const KEPT: [&str; 6] = [
    "genesis_records",
    "settings",
    "bitcoin_accounts",
    "anchor_enrollments",
    "anchor_accepted_roots",
    "manifold_seeds",
];

/// Rewritten by the upgrade, below.
const REWRITTEN: [&str; 3] = ["bcr_device_heads", "identity_publication", "recovery_prefs"];

/// The one `recovery_prefs` key the wallet keeps: its hardware-sealed seed.
const SEALED_SEED_KEY: &str = "encrypted_wallet_seed";

/// The phases of an offline step its board may hold a record of: a sender's
/// release being driven, a receiver's board committing the receive, and a
/// confirmed step whose board frontier may not have advanced. A restart
/// settles each from its `bilateral_sessions` row, and nothing else can.
const BOARD_STEP_PHASES: [&str; 3] = ["releasing", "receiving", "confirm_pending"];

/// Upgrade the database on `conn` in place when it is at a version this build
/// upgrades from; leave any other file untouched for `create_schema` to judge.
pub(crate) fn upgrade_in_place(conn: &mut Connection) -> Result<()> {
    let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if !UPGRADED_FROM.contains(&found) {
        return Ok(());
    }
    log::info!(
        "[client_db] upgrading the wallet database in place from version {found} to {}",
        super::CLIENT_DB_SCHEMA_VERSION
    );
    // Foreign keys are switched off for the rewrite, outside the transaction
    // as SQLite requires, and back on whatever the outcome.
    conn.execute_batch("PRAGMA foreign_keys = OFF;")?;
    let upgraded = rewrite(conn);
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    upgraded
}

fn rewrite(conn: &mut Connection) -> Result<()> {
    // Two opens at once both see the old version; the write lock taken here
    // lets one upgrade, and the other reads the version again under it and
    // finds nothing left to do.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if !UPGRADED_FROM.contains(&found) {
        return Ok(());
    }
    refuse_a_board_step_in_flight(&tx)?;
    let head = genesis_head_of(&tx)?;
    let tables: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )?;
        let names = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        names
    };
    for table in &tables {
        if KEPT.contains(&table.as_str()) || REWRITTEN.contains(&table.as_str()) {
            continue;
        }
        if table == "inbox_route" {
            // Its lock column becomes required: `create_schema` makes it anew.
            tx.execute_batch("DROP TABLE inbox_route;")?;
            continue;
        }
        tx.execute(
            &format!("DELETE FROM \"{}\"", table.replace('"', "\"\"")),
            [],
        )?;
    }
    tx.execute("DELETE FROM bcr_device_heads", [])?;
    super::bcr::update_bcr_device_head_with_conn(&tx, &head)?;
    tx.execute(
        "UPDATE identity_publication SET state = 'publication_pending', last_error = ''",
        [],
    )?;
    tx.execute(
        "DELETE FROM recovery_prefs WHERE key <> ?1",
        params![SEALED_SEED_KEY],
    )?;
    tx.execute_batch(&format!(
        "PRAGMA user_version = {};",
        super::CLIENT_DB_SCHEMA_VERSION
    ))?;
    tx.commit()?;
    log::info!("[client_db] wallet database upgraded in place; its network state starts again");
    Ok(())
}

/// Refuse the upgrade while an offline step is unfinished on a board. Its
/// session row is the only thing that can settle the board's record of it, and
/// the upgrade empties that table, so upgrading now would leave the board
/// unable to stage or receive again. Left at its old version, the file opens on
/// the build that started the step, which finishes it at its next start.
fn refuse_a_board_step_in_flight(conn: &Connection) -> Result<()> {
    let has_sessions: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'bilateral_sessions'",
        [],
        |r| r.get(0),
    )?;
    if has_sessions == 0 {
        return Ok(());
    }
    let in_flight: i64 = conn.query_row(
        "SELECT count(*) FROM bilateral_sessions WHERE phase IN (?1, ?2, ?3)",
        params![
            BOARD_STEP_PHASES[0],
            BOARD_STEP_PHASES[1],
            BOARD_STEP_PHASES[2]
        ],
        |r| r.get(0),
    )?;
    if in_flight > 0 {
        return Err(anyhow!(
            "upgrade: {in_flight} offline step(s) are unfinished on a board; open this wallet on \
             the build that started them and let them finish before upgrading"
        ));
    }
    Ok(())
}

/// The device's head, started again from its genesis: the same genesis, device
/// id and public key, and nothing the old network held. Its own boards'
/// offline accounts are carried as [`carried_offline_account`] says.
fn genesis_head_of(conn: &Connection) -> Result<RealizedHead> {
    // The genesis record names the device in Base32 text. Several records can
    // stand side by side; the device is the newest, as the runtime reads it
    // (`genesis::get_verified_genesis_record`).
    let named: String = conn
        .query_row(
            "SELECT device_id FROM genesis_records ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("upgrade: the database holds no genesis record"))?;
    let decoded = crate::util::text_id::decode_base32_crockford(&named)
        .ok_or_else(|| anyhow!("upgrade: the genesis record's device id is not Base32"))?;
    let devid = <[u8; 32]>::try_from(decoded.as_slice())
        .map_err(|e| anyhow!("upgrade: the genesis record's device id: {e}"))?;
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT head_bytes FROM bcr_device_heads WHERE device_id = ?1",
            params![devid.as_slice()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("upgrade: the database holds no head for its own device"))?;
    let pending = super::economic_admission::load_pending_admission_with_conn(conn, &devid)?;
    let (old, _) = super::bcr::decode_device_state(&bytes, pending)?;
    if old.devid() != devid {
        return Err(anyhow!(
            "upgrade: the stored head is not the genesis record's device"
        ));
    }
    let mut head =
        DeviceState::genesis_head(old.genesis_digest(), old.devid(), old.public_key().to_vec());
    for (bundle, account) in old.offline_accounts() {
        if let Some((frontier, counter)) = carried_offline_account(account)? {
            head = head
                .open_offline_account(bundle, frontier, counter)
                .map_err(|e| anyhow!("upgrade: reopening the offline account: {e}"))?;
        }
    }
    Ok(head)
}

/// What becomes of one of this device's own boards' offline accounts: it is
/// opened again, empty, where its board stands, at the account's frontier and
/// counter, so the board's next attach finds the account standing exactly
/// where the chip does. What it held is dropped: the loads and receipts behind
/// it were admitted on the fleet that was reprovisioned, so no receiver can
/// check them any more. Owner, 2026-11-15, asked whether the upgraded wallet
/// may reopen each board's account empty at the board's counter so the
/// installed boards keep working: "The answer is fucking yes, man." This is
/// the one place an account opens at a counter above the chip's origin;
/// `CoreSDK::require_offline_account_at` still refuses that at any attach.
fn carried_offline_account(
    account: &dsm::types::offline_account::OfflineAccount,
) -> Result<Option<([u8; 32], u64)>> {
    let held: u64 = account.allocations().values().sum();
    if held > 0 {
        log::warn!(
            "[client_db] upgrade: a board's offline account at counter {} held {held}; it is \
             reopened empty there",
            account.counter()
        );
    }
    Ok(Some((account.frontier(), account.counter())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::device_state::DeviceState;

    const DEVICE: [u8; 32] = [0xD7; 32];
    const BUNDLE: [u8; 32] = [0xB1; 32];
    const FRONTIER: [u8; 32] = [0xF4; 32];

    /// A wallet database as 0.1.0-beta.4 leaves it, in the parts the upgrade
    /// reads: a genesis record, the device's head with its board's offline
    /// account at counter 4, a contact, a stale publication, the sealed seed
    /// beside another recovery setting, another device's board pin, and an
    /// inbox route of the old shape.
    fn beta4_database() -> Connection {
        let conn = Connection::open_in_memory().expect("an in-memory database");
        super::super::create_schema(&conn).expect("the current schema");
        let named = crate::util::text_id::encode_base32_crockford(&DEVICE);
        conn.execute(
            "INSERT INTO genesis_records(genesis_id, device_id, device_birth_binding, \
             merkle_root, chain_tip, publication_hash, entropy_hash, protocol_version) \
             VALUES ('G', ?1, 'b', 'm', 'c', 'p', 'e', 'v')",
            params![named],
        )
        .expect("the genesis record");
        let head = DeviceState::genesis_head([0x6E; 32], DEVICE, vec![0xAB; 64])
            .open_offline_account(&BUNDLE, FRONTIER, 4)
            .expect("the board's account");
        super::super::bcr::update_bcr_device_head_with_conn(&conn, &head).expect("the head");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS recovery_prefs(key TEXT PRIMARY KEY, value BLOB NOT NULL);
             INSERT INTO recovery_prefs(key, value) VALUES ('encrypted_wallet_seed', x'5EED');
             INSERT INTO recovery_prefs(key, value) VALUES ('recovery_phase', 'idle');
             INSERT INTO identity_publication(device_id, genesis_hash, state, quorum_required, last_error)
                 VALUES ('D', 'G', 'published', 3, 'old');
             INSERT INTO contacts(contact_id, device_id, alias, genesis_hash, verified, status, needs_online_reconcile)
                 VALUES ('c1', x'01', 'peer', x'02', 1, 'Created', 0);
             DROP TABLE inbox_route;
             CREATE TABLE inbox_route(address TEXT PRIMARY KEY, route_digest BLOB NOT NULL, lock_public_key BLOB);
             INSERT INTO inbox_route(address, route_digest) VALUES ('open', x'00');
             PRAGMA user_version = 47;",
        )
        .expect("beta.4's rows");
        conn
    }

    /// The upgrade keeps the device's identity, its sealed seed and its
    /// board, and starts its network state again: the head is the device's
    /// genesis head with the board's account reopened empty at counter 4, the
    /// contact and the stale publication are gone, the inbox routes take the
    /// current shape, and the database is at the current version.
    #[test]
    fn a_beta4_database_is_upgraded_keeping_identity_and_board() {
        let mut conn = beta4_database();
        upgrade_in_place(&mut conn).expect("the upgrade");
        super::super::create_schema(&conn).expect("the current schema accepts it");

        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("the version");
        assert_eq!(version, super::super::CLIENT_DB_SCHEMA_VERSION);
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT head_bytes FROM bcr_device_heads WHERE device_id = ?1",
                params![DEVICE.as_slice()],
                |r| r.get(0),
            )
            .expect("the head");
        let (head, _) = super::super::bcr::decode_device_state(&bytes, None).expect("decoded");
        assert_eq!(head.devid(), DEVICE);
        let account = head.offline_account(&BUNDLE).expect("the board's account");
        assert_eq!((account.counter(), account.frontier()), (4, FRONTIER));
        assert!(account.allocations().is_empty());

        let kept: Vec<String> = conn
            .prepare("SELECT key FROM recovery_prefs")
            .expect("prefs")
            .query_map([], |r| r.get(0))
            .expect("rows")
            .collect::<std::result::Result<_, _>>()
            .expect("keys");
        assert_eq!(kept, vec![SEALED_SEED_KEY.to_string()]);
        let contacts: i64 = conn
            .query_row("SELECT count(*) FROM contacts", [], |r| r.get(0))
            .expect("contacts");
        assert_eq!(contacts, 0);
        let state: String = conn
            .query_row("SELECT state FROM identity_publication", [], |r| r.get(0))
            .expect("publication");
        assert_eq!(state, "publication_pending");
        let routes: i64 = conn
            .query_row("SELECT count(*) FROM inbox_route", [], |r| r.get(0))
            .expect("routes");
        assert_eq!(routes, 0);
    }

    /// A database at any other version is left exactly as it is, for the
    /// schema check to judge.
    #[test]
    fn another_version_is_left_untouched() {
        let mut conn = beta4_database();
        conn.execute_batch("PRAGMA user_version = 46;")
            .expect("stamp");
        upgrade_in_place(&mut conn).expect("nothing to do");
        let contacts: i64 = conn
            .query_row("SELECT count(*) FROM contacts", [], |r| r.get(0))
            .expect("contacts");
        assert_eq!(contacts, 1);
    }

    /// A board step left unfinished by beta.4 refuses the upgrade, and the file
    /// is left exactly as it was, so the build that started the step can
    /// settle it. A step that ended does not hold the upgrade back.
    /// MUTATION CONTROL: dropping the check upgrades the first database and
    /// empties its session row.
    #[test]
    fn a_board_step_in_flight_holds_the_upgrade_back() {
        for phase in BOARD_STEP_PHASES {
            let mut conn = beta4_database();
            conn.execute(
                "INSERT INTO bilateral_sessions(commitment_hash, counterparty_device_id, \
                 operation_bytes, phase) VALUES (x'01', x'02', x'03', ?1)",
                params![phase],
            )
            .expect("the session");
            let refused = upgrade_in_place(&mut conn).expect_err("a board step in flight");
            assert!(
                refused.to_string().contains("unfinished on a board"),
                "{phase}: {refused}"
            );
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .expect("the version");
            assert_eq!(version, 47, "{phase}");
            let sessions: i64 = conn
                .query_row("SELECT count(*) FROM bilateral_sessions", [], |r| r.get(0))
                .expect("sessions");
            assert_eq!(sessions, 1, "{phase}");
        }
        let mut conn = beta4_database();
        conn.execute(
            "INSERT INTO bilateral_sessions(commitment_hash, counterparty_device_id, \
             operation_bytes, phase) VALUES (x'01', x'02', x'03', 'committed')",
            [],
        )
        .expect("the session");
        upgrade_in_place(&mut conn).expect("an ended step does not hold it back");
    }

    /// With two genesis records, the upgrade rebuilds the newest one's device,
    /// the one the runtime reads, and keeps its board.
    /// MUTATION CONTROL: reading the oldest record finds no head for its
    /// device and refuses.
    #[test]
    fn the_newest_genesis_record_names_the_device() {
        let mut conn = beta4_database();
        conn.execute_batch("DELETE FROM genesis_records;")
            .expect("clear");
        for (id, device) in [("OLD", [0x01; 32]), ("NEW", DEVICE)] {
            conn.execute(
                "INSERT INTO genesis_records(genesis_id, device_id, device_birth_binding, \
                 merkle_root, chain_tip, publication_hash, entropy_hash, protocol_version) \
                 VALUES (?1, ?2, 'b', 'm', 'c', 'p', 'e', 'v')",
                params![id, crate::util::text_id::encode_base32_crockford(&device)],
            )
            .expect("a genesis record");
        }
        upgrade_in_place(&mut conn).expect("the newest record's device upgrades");
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT head_bytes FROM bcr_device_heads WHERE device_id = ?1",
                params![DEVICE.as_slice()],
                |r| r.get(0),
            )
            .expect("the head");
        let (head, _) = super::super::bcr::decode_device_state(&bytes, None).expect("decoded");
        let account = head.offline_account(&BUNDLE).expect("the board's account");
        assert_eq!((account.counter(), account.frontier()), (4, FRONTIER));
    }

    /// A database with no head for its genesis record's device is refused
    /// and left at its version: the transaction rolls back.
    #[test]
    fn a_head_of_another_device_leaves_the_database_as_it_was() {
        let mut conn = beta4_database();
        conn.execute(
            "UPDATE genesis_records SET device_id = ?1",
            params![crate::util::text_id::encode_base32_crockford(&[0x01; 32])],
        )
        .expect("another device");
        let refused = upgrade_in_place(&mut conn).expect_err("another device's head is refused");
        assert!(
            refused.to_string().contains("no head for its own device"),
            "{refused}"
        );
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("the version");
        assert_eq!(version, 47);
    }
}
