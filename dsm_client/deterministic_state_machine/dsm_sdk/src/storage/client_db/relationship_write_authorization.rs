// SPDX-License-Identifier: MIT OR Apache-2.0
//! A relationship's write authorizations as this device holds them (DSM
//! Amendment A34): one row per counterparty and direction.
//!
//! - `outbound`: this device writes to the counterparty. `write_public_key` is
//!   its own write key, which comes back from the master seed and the
//!   instance, so no secret is stored; `message` is its offer, frozen with the
//!   establishment that made the instance; `grant_wire` is the counterparty's
//!   grant once it verified here.
//! - `inbound`: the counterparty writes to this device. `write_public_key` is
//!   the counterparty's key; `message` is the grant this device issued for it.
//!
//! `delivered` says whether `message` reached the storage set. A row is only
//! ever written by an establishment (the offer) or by a verified offer or
//! grant: none exists for a relationship this device has not established.
//! Termination is final (DSM Amendment A33), so one instance per counterparty
//! and direction is all a row holds; an offer or a grant for any other
//! instance, or a second grant for the same one, is refused, never stored
//! beside it.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use super::{column_32, get_connection};

/// Which way a row's authorization runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteDirection {
    /// This device writes to the counterparty.
    Outbound,
    /// The counterparty writes to this device.
    Inbound,
}

impl WriteDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            WriteDirection::Outbound => "outbound",
            WriteDirection::Inbound => "inbound",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "outbound" => Ok(WriteDirection::Outbound),
            "inbound" => Ok(WriteDirection::Inbound),
            other => Err(anyhow!(
                "relationship_write_authorization holds an unknown direction {other:?}"
            )),
        }
    }
}

/// This device's own write authorization toward a counterparty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnWriteAuthorization {
    pub relationship_instance_id: [u8; 32],
    pub write_public_key: Vec<u8>,
    /// The frozen offer, `RelationshipWriteKeyOfferV1` wire bytes.
    pub offer_wire: Vec<u8>,
    pub offer_delivered: bool,
    /// The counterparty's grant for this key, once verified here.
    pub grant: Option<HeldGrant>,
}

/// A grant as a row holds it: its identifier and its wire bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldGrant {
    pub grant_id: [u8; 32],
    pub grant_wire: Vec<u8>,
}

/// A grant this device issued to a counterparty's write key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedWriteGrant {
    pub relationship_instance_id: [u8; 32],
    pub write_public_key: Vec<u8>,
    pub grant: HeldGrant,
    pub delivered: bool,
}

/// What recording an offer or a grant came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteAuthorizationRecorded {
    /// Written now.
    Recorded,
    /// The same thing was already held: nothing changed.
    AlreadyHeld,
}

/// A frozen message this device still owes a counterparty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwedWriteAuthorization {
    pub counterparty_device_id: [u8; 32],
    pub direction: WriteDirection,
    pub message: Vec<u8>,
}

fn lock_conn<T>(f: impl FnOnce(&rusqlite::Connection) -> Result<T>) -> Result<T> {
    let binding = get_connection()?;
    let conn = match binding.lock() {
        Ok(conn) => conn,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&conn)
}

fn short(device: &[u8]) -> String {
    crate::util::text_id::encode_base32_crockford(&device[..4.min(device.len())])
}

/// Freeze this device's offer for the instance its establishment with
/// `counterparty` opened, inside the establishment's own transaction. The
/// same offer again changes nothing; an offer for another instance or
/// another key is refused.
pub fn freeze_own_offer_with_conn(
    conn: &rusqlite::Connection,
    counterparty: &[u8; 32],
    relationship_instance_id: &[u8; 32],
    write_public_key: &[u8],
    offer_wire: &[u8],
) -> Result<WriteAuthorizationRecorded> {
    let held: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT relationship_instance_id, write_public_key, message \
             FROM relationship_write_authorization \
             WHERE counterparty_device_id = ?1 AND direction = 'outbound'",
            params![counterparty.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    match held {
        Some((instance, key, message))
            if instance == relationship_instance_id.as_slice()
                && key == write_public_key
                && message == offer_wire =>
        {
            Ok(WriteAuthorizationRecorded::AlreadyHeld)
        }
        Some(_) => Err(anyhow!(
            "this device already offered {} another write key or instance",
            short(counterparty)
        )),
        None => {
            conn.execute(
                "INSERT INTO relationship_write_authorization(counterparty_device_id, \
                 relationship_instance_id, direction, write_public_key, message, delivered) \
                 VALUES (?1, ?2, 'outbound', ?3, ?4, 0)",
                params![
                    counterparty.as_slice(),
                    relationship_instance_id.as_slice(),
                    write_public_key,
                    offer_wire
                ],
            )?;
            Ok(WriteAuthorizationRecorded::Recorded)
        }
    }
}

/// This device's write authorization toward `counterparty`, if its
/// establishment made one.
pub fn own_write_authorization(counterparty: &[u8; 32]) -> Result<Option<OwnWriteAuthorization>> {
    lock_conn(|conn| {
        conn.query_row(
            "SELECT relationship_instance_id, write_public_key, message, delivered, grant_id, \
             grant_wire FROM relationship_write_authorization \
             WHERE counterparty_device_id = ?1 AND direction = 'outbound'",
            params![counterparty.as_slice()],
            |r| {
                let grant_id: Option<Vec<u8>> = r.get(4)?;
                let grant_wire: Option<Vec<u8>> = r.get(5)?;
                let grant = match (grant_id, grant_wire) {
                    (Some(id), Some(wire)) => Some(HeldGrant {
                        grant_id: <[u8; 32]>::try_from(id.as_slice()).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                4,
                                rusqlite::types::Type::Blob,
                                Box::new(e),
                            )
                        })?,
                        grant_wire: wire,
                    }),
                    _ => None,
                };
                let delivered: i64 = r.get(3)?;
                Ok(OwnWriteAuthorization {
                    relationship_instance_id: column_32(r, 0)?,
                    write_public_key: r.get(1)?,
                    offer_wire: r.get(2)?,
                    offer_delivered: delivered == 1,
                    grant,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    })
}

/// Record the counterparty's grant for this device's key, verified by the
/// caller against the instance and key of this device's row. The same grant
/// again changes nothing; a different grant for the same key is refused, so
/// the first verified grant is the one held.
pub fn record_grant_received(
    counterparty: &[u8; 32],
    relationship_instance_id: &[u8; 32],
    grant: &HeldGrant,
) -> Result<WriteAuthorizationRecorded> {
    lock_conn(|conn| {
        let held: Option<(Vec<u8>, Option<Vec<u8>>)> = conn
            .query_row(
                "SELECT relationship_instance_id, grant_id FROM relationship_write_authorization \
                 WHERE counterparty_device_id = ?1 AND direction = 'outbound'",
                params![counterparty.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match held {
            None => Err(anyhow!(
                "no write key of this device toward {} for a grant to authorize",
                short(counterparty)
            )),
            Some((instance, _)) if instance != relationship_instance_id.as_slice() => Err(anyhow!(
                "the grant from {} names another relationship instance than this device's key",
                short(counterparty)
            )),
            Some((_, Some(id))) if id == grant.grant_id.as_slice() => {
                Ok(WriteAuthorizationRecorded::AlreadyHeld)
            }
            Some((_, Some(_))) => Err(anyhow!(
                "{} already granted this device's key; a different grant is refused",
                short(counterparty)
            )),
            Some((_, None)) => {
                conn.execute(
                    "UPDATE relationship_write_authorization SET grant_id = ?2, grant_wire = ?3 \
                     WHERE counterparty_device_id = ?1 AND direction = 'outbound' \
                     AND grant_id IS NULL",
                    params![
                        counterparty.as_slice(),
                        grant.grant_id.as_slice(),
                        grant.grant_wire
                    ],
                )?;
                Ok(WriteAuthorizationRecorded::Recorded)
            }
        }
    })
}

/// Record the grant this device issued to `counterparty`'s write key, signed
/// over a verified offer. The same grant again changes nothing; a grant for
/// another instance or another key is refused, so a counterparty holds one
/// grant from this device.
pub fn record_grant_issued(
    counterparty: &[u8; 32],
    relationship_instance_id: &[u8; 32],
    write_public_key: &[u8],
    grant: &HeldGrant,
) -> Result<WriteAuthorizationRecorded> {
    lock_conn(|conn| {
        let held: Option<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> = conn
            .query_row(
                "SELECT relationship_instance_id, write_public_key, grant_id \
                 FROM relationship_write_authorization \
                 WHERE counterparty_device_id = ?1 AND direction = 'inbound'",
                params![counterparty.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match held {
            Some((instance, key, Some(id)))
                if instance == relationship_instance_id.as_slice()
                    && key == write_public_key
                    && id == grant.grant_id.as_slice() =>
            {
                Ok(WriteAuthorizationRecorded::AlreadyHeld)
            }
            Some(_) => Err(anyhow!(
                "this device already granted {} a write key; another is refused",
                short(counterparty)
            )),
            None => {
                conn.execute(
                    "INSERT INTO relationship_write_authorization(counterparty_device_id, \
                     relationship_instance_id, direction, write_public_key, message, delivered, \
                     grant_id) VALUES (?1, ?2, 'inbound', ?3, ?4, 0, ?5)",
                    params![
                        counterparty.as_slice(),
                        relationship_instance_id.as_slice(),
                        write_public_key,
                        grant.grant_wire,
                        grant.grant_id.as_slice()
                    ],
                )?;
                Ok(WriteAuthorizationRecorded::Recorded)
            }
        }
    })
}

/// The grant this device issued to `counterparty`, if any.
pub fn issued_write_grant(counterparty: &[u8; 32]) -> Result<Option<IssuedWriteGrant>> {
    lock_conn(|conn| {
        conn.query_row(
            "SELECT relationship_instance_id, write_public_key, grant_id, message, delivered \
             FROM relationship_write_authorization \
             WHERE counterparty_device_id = ?1 AND direction = 'inbound'",
            params![counterparty.as_slice()],
            |r| {
                let delivered: i64 = r.get(4)?;
                Ok(IssuedWriteGrant {
                    relationship_instance_id: column_32(r, 0)?,
                    write_public_key: r.get(1)?,
                    grant: HeldGrant {
                        grant_id: column_32(r, 2)?,
                        grant_wire: r.get(3)?,
                    },
                    delivered: delivered == 1,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    })
}

/// Every frozen offer and issued grant not yet delivered, oldest
/// counterparty first.
pub fn owed_write_authorizations() -> Result<Vec<OwedWriteAuthorization>> {
    lock_conn(|conn| {
        let mut stmt = conn.prepare(
            "SELECT counterparty_device_id, direction, message \
             FROM relationship_write_authorization WHERE delivered = 0 \
             ORDER BY counterparty_device_id, direction",
        )?;
        let rows = stmt.query_map([], |r| {
            let direction: String = r.get(1)?;
            Ok((column_32(r, 0)?, direction, r.get::<_, Vec<u8>>(2)?))
        })?;
        let mut owed = Vec::new();
        for row in rows {
            let (counterparty_device_id, direction, message) = row?;
            owed.push(OwedWriteAuthorization {
                counterparty_device_id,
                direction: WriteDirection::parse(&direction)?,
                message,
            });
        }
        Ok(owed)
    })
}

/// The frozen message toward `counterparty` in `direction` reached the
/// storage set.
pub fn mark_write_authorization_delivered(
    counterparty: &[u8; 32],
    direction: WriteDirection,
) -> Result<()> {
    lock_conn(|conn| {
        let changed = conn.execute(
            "UPDATE relationship_write_authorization SET delivered = 1 \
             WHERE counterparty_device_id = ?1 AND direction = ?2",
            params![counterparty.as_slice(), direction.as_str()],
        )?;
        if changed != 1 {
            return Err(anyhow!(
                "no {} write authorization toward {} to mark delivered",
                direction.as_str(),
                short(counterparty)
            ));
        }
        Ok(())
    })
}

/// An inbox address's route digest and, for a locked inbox, the recipient's
/// lock it is bound to (DSM Amendment A34).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxRoute {
    pub route_digest: [u8; 32],
    pub lock_public_key: Option<Vec<u8>>,
}

/// Remember how `address` was derived. The same address is always the same
/// derivation, so recording it again changes nothing.
pub fn record_inbox_route(address: &str, route: &InboxRoute) -> Result<()> {
    lock_conn(|conn| {
        conn.execute(
            "INSERT OR IGNORE INTO inbox_route(address, route_digest, lock_public_key) \
             VALUES (?1, ?2, ?3)",
            params![
                address,
                route.route_digest.as_slice(),
                route.lock_public_key
            ],
        )?;
        Ok(())
    })
}

/// How `address` was derived, if this device derived it.
pub fn inbox_route(address: &str) -> Result<Option<InboxRoute>> {
    lock_conn(|conn| {
        conn.query_row(
            "SELECT route_digest, lock_public_key FROM inbox_route WHERE address = ?1",
            params![address],
            |r| {
                Ok(InboxRoute {
                    route_digest: column_32(r, 0)?,
                    lock_public_key: r.get(1)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    })
}
