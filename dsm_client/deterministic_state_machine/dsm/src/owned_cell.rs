// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cells a person pays for are theirs (owner ruling, 2026-11-19: "Everything
//! that they pay for should be that way. It's theirs. It's not someone
//! else's.").
//!
//! A cell one party owns lives at its route bound to the owner's cell lock,
//! the key the owner's directory entry publishes: `address = H(DSM/owned-cell/v1
//! ‖ route ‖ lock)`. A write carries the route, the lock and the lock's
//! signature over the namespace, the address and the value's digest. Every
//! member runs the one check here before it keeps the value: the address is
//! the route bound to the lock the write carries, and the lock signed this
//! write. Nobody else holds the lock, so nobody else can put anything at the
//! address, and nothing anyone else writes is kept there to be read.
//!
//! A device's own directory cell is where readers learn its lock, so it is
//! bound to the device itself: its address is the directory key of the genesis
//! and the device id, and the write carries the AK and AttA whose hash is that
//! device id, signed by the AK.
//!
//! Three cells are their authorizer's, and anyone delivers to them, so their
//! address holds no lock (DSM Amendment A41): a register cell keeps a route
//! entry whose claim the trader's AK signed for that key; an application cell
//! keeps one carrying a write that a writer of its committed set signed; and a
//! fulfillment cell keeps one carrying an `F` that, with the 32-byte genesis
//! the write carries, derives the cell and verifies under its own key.
//!
//! The check is the protocol running, the same code on every member, with no
//! setting, no list of owners and no state (as DSM Amendment A34's inbox check
//! is). A cell several parties write by protocol is open, and its readers keep
//! the first value their rule recognizes (storage spec §9).

use crate::common::domain_tags::{
    TAG_DSM_CELL_LOCK, TAG_DSM_DIRECTORY_CELL_WRITE, TAG_DSM_OWNED_CELL, TAG_DSM_OWNED_CELL_WRITE,
};
use crate::core::identity::directory::{directory_cell_key, AK_PUBLIC_KEY_LEN, DIRECTORY_NAMESPACE};
use crate::crypto::blake3::{dsm_domain_hasher, dsm_domain_hasher_keyed};
use crate::crypto::domain::TaggedHashDomain;
use crate::crypto::sphincs::{
    generate_keypair_from_seed, sphincs_sign, sphincs_verify, SphincsKeyPair, SphincsVariant,
};
use crate::types::error::DsmError;
use crate::types::proto::{DirectoryCellWriteV1, OwnedCellWriteV1};
use crate::types::receipt_types::{validate_length_delimited_wire, FieldLimit};

/// A cell lock is a SPHINCS+ SPX256f key, as every DSM device key is.
pub const CELL_LOCK_VARIANT: SphincsVariant = SphincsVariant::SPX256f;
/// A lock's public key length, `PK.seed ‖ PK.root`.
pub const CELL_LOCK_LEN: usize = 64;
/// The longest signature a proof carries (SPX256f is 49,856 bytes).
pub(crate) const SIGNATURE_MAX_LEN: usize = 65_535;

/// Who may write a cell of a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellOwnership {
    /// Several parties write it by protocol; a write carries no proof.
    Open,
    /// One party owns it: its address is a route bound to the owner's cell
    /// lock, and the lock signs every write.
    Owned,
    /// A device's own directory cell, bound to the device id.
    Directory,
    /// A trader's economic register cell `K_root(q)` (owner, 2026-11-19:
    /// "only the owner authorizes the economic transition, but anyone may
    /// deliver its authenticated proof"). Its address stays `K_root(G, DevID,
    /// q)`; a write is kept only when its value is a route entry for this
    /// cell whose claim proves its own authority for exactly this key (DSM
    /// Amendment A10: the claim's key and AttA derive the trader's device and
    /// the key signed it), whoever delivers it.
    Register,
    /// An application cell `K_app` (DSM Amendment A35): its writer set is
    /// committed in its address, and any one writer of the set writes it.
    /// A write is kept only when its value is a route entry for this cell
    /// carrying a write that proves its own authority (its application,
    /// writer set and name derive the cell, and a writer of that set signed
    /// it), whoever delivers it. Owner, 2026-11-20: "the fulfillment cell and
    /// application cells still need the same kind of write protection. Add
    /// that without breaking any legitimate multi-party protocol steps."
    Application,
    /// A trader's fulfillment cell `K_ful(q)` (SoFi §17.4): the trader's,
    /// and anyone delivers to it (SoFi Amendment S20: "Any caller MAY relay
    /// F"). Owner, 2026-11-20: "the storage node should recompute the cell
    /// address from the provided genesis, device ID, and position, then
    /// verify the trader's signature and its binding. The genesis is a
    /// public hint, not a secret." A write carries the trader's 32-byte
    /// genesis as its proof, since `F` carries none; it is kept only when its
    /// value is a route entry for this cell carrying an `F` whose key and
    /// AttA derive a device that, with that genesis and `F`'s position,
    /// derives this cell, and which verifies under its own key.
    Fulfillment,
    /// A namespace no member keeps a write in any more: the wallet backup
    /// cells of before 2026-11-23, replaced by each device's one backup slot
    /// (owner, 2026-11-23: "adjust the code after that so that there's no
    /// longer that spot").
    Retired,
    /// An offline account's origin cell `K_off = H(DSM/offline-origin/v1 ‖ B
    /// ‖ R)` (DSM Amendment A39): the account's, its authority the board's
    /// signatures under `B`, and anyone holding a step delivers it (its
    /// payer, its receiver, a later payee). Owner, 2026-11-21, asked whether
    /// to protect origin cells as the other cells are: "sure protect them". A
    /// write carries no proof; it is kept only when its value is a route
    /// entry for this cell carrying a write that proves its own authority
    /// there — a step the board signed starting from the cell's root, or the
    /// departure of a boundary leaving it — the check every reader makes.
    /// Nothing of an offline step between boards changes: members take part
    /// only when a step is published for settling.
    OfflineOrigin,
}

/// The namespaces of owned cells.
fn owned_namespaces() -> [&'static [u8]; 1] {
    [crate::recovery::RecoveryCell::namespace()]
}

/// Who may write a cell of `namespace`.
pub fn ownership(namespace: &[u8]) -> CellOwnership {
    if namespace == crate::common::domain_tags::RETIRED_WALLET_BACKUP_CELLS {
        CellOwnership::Retired
    } else if namespace == DIRECTORY_NAMESPACE {
        CellOwnership::Directory
    } else if namespace == crate::economic::register::economic_root_namespace() {
        CellOwnership::Register
    } else if namespace == crate::sofi::registration::fulfillment_namespace() {
        CellOwnership::Fulfillment
    } else if namespace == crate::offline_origin::namespace() {
        CellOwnership::OfflineOrigin
    } else if namespace == crate::app_cell::namespace() {
        CellOwnership::Application
    } else if owned_namespaces().contains(&namespace) {
        CellOwnership::Owned
    } else {
        CellOwnership::Open
    }
}

/// The cell lock of `device_id`: SPHINCS+ key generation from
/// `keyed-BLAKE3(Smaster, "DSM/cell-lock/v1" ‖ device id)`. One per device,
/// never the AK, nothing secret stored, and it comes back from the phrase.
pub fn derive_cell_lock_keypair(
    s_master: &[u8; 32],
    device_id: &[u8; 32],
) -> Result<SphincsKeyPair, DsmError> {
    let mut h = dsm_domain_hasher_keyed(TAG_DSM_CELL_LOCK, s_master);
    h.update(device_id);
    let seed = zeroize::Zeroizing::new(*h.finalize().as_bytes());
    generate_keypair_from_seed(CELL_LOCK_VARIANT, &seed)
}

/// An owned cell's address: `route` bound to the owner's cell lock.
pub fn owned_cell_address(route: &[u8; 32], lock_public_key: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_OWNED_CELL);
    h.update(route);
    h.update(lock_public_key);
    *h.finalize().as_bytes()
}

/// What a write's key signs: `H(tag ‖ u16be(|namespace|) ‖ namespace ‖
/// address ‖ entry digest of the value)`. The namespace is length-prefixed and
/// every other field has a fixed length, so the signed bytes have one reading.
fn write_target(
    tag: TaggedHashDomain<'static>,
    namespace: &[u8],
    address: &[u8; 32],
    value: &[u8],
) -> Result<[u8; 32], CellWriteRefusal> {
    let len =
        u16::try_from(namespace.len()).map_err(|e| CellWriteRefusal::Namespace(e.to_string()))?;
    let mut h = dsm_domain_hasher(tag);
    h.update(&len.to_be_bytes());
    h.update(namespace);
    h.update(address);
    h.update(&crate::storage_cell::entry_digest(value));
    Ok(*h.finalize().as_bytes())
}

/// What a lock signs for a write of `value` at `address` in `namespace`.
pub fn owned_cell_write_target(
    namespace: &[u8],
    address: &[u8; 32],
    value: &[u8],
) -> Result<[u8; 32], CellWriteRefusal> {
    write_target(TAG_DSM_OWNED_CELL_WRITE, namespace, address, value)
}

/// The owner's write of `value` to its cell at `route` in `namespace`: the
/// cell's address and the proof a member checks.
pub fn sign_owned_cell_write(
    namespace: &[u8],
    route: &[u8; 32],
    lock: &SphincsKeyPair,
    value: &[u8],
) -> Result<([u8; 32], Vec<u8>), DsmError> {
    use prost::Message;
    let address = owned_cell_address(route, &lock.public_key);
    let target = write_target(TAG_DSM_OWNED_CELL_WRITE, namespace, &address, value)
        .map_err(|why| DsmError::invalid_parameter(why.to_string()))?;
    let proof = OwnedCellWriteV1 {
        route: route.to_vec(),
        lock_public_key: lock.public_key.clone(),
        write_signature: sphincs_sign(&lock.secret_key, &target)?,
    };
    Ok((address, proof.encode_to_vec()))
}

/// A device's write of `value` to its own directory cell: the cell's address
/// and the proof a member checks. `ak_secret` signs; the device id is the hash
/// of `ak_public_key` and `att_a`.
pub fn sign_directory_cell_write(
    genesis: &[u8; 32],
    ak_public_key: &[u8],
    att_a: &[u8; 32],
    ak_secret: &[u8],
    value: &[u8],
) -> Result<([u8; 32], Vec<u8>), DsmError> {
    use prost::Message;
    let device_id = crate::core::identity::genesis_v2::derive_devid(ak_public_key, att_a);
    let address = directory_cell_key(genesis, &device_id);
    let target = write_target(
        TAG_DSM_DIRECTORY_CELL_WRITE,
        DIRECTORY_NAMESPACE,
        &address,
        value,
    )
    .map_err(|why| DsmError::invalid_parameter(why.to_string()))?;
    let proof = DirectoryCellWriteV1 {
        genesis: genesis.to_vec(),
        ak_public_key: ak_public_key.to_vec(),
        att_a: att_a.to_vec(),
        write_signature: sphincs_sign(ak_secret, &target)?,
    };
    Ok((address, proof.encode_to_vec()))
}

/// Why a member does not keep a write. Each refusal names one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellWriteRefusal {
    /// The namespace is longer than its length prefix frames: why.
    Namespace(String),
    /// An open cell's write carried a proof: it has one encoding, without one.
    ProofOnOpenCell,
    /// An owned cell's write carried no proof.
    NoProof,
    /// The proof is not its strict wire form.
    Wire(String),
    /// The cell's key is not the address the proof binds.
    WrongAddress,
    /// A register write's value is not a route entry for this cell carrying
    /// a claim its trader's key authorized for this cell (also: a delivery
    /// to a self-authorizing cell that is no route entry).
    ClaimNotAuthorized,
    /// An application cell's write is a route entry for this cell carrying
    /// no write a writer of its committed set signed for it: why.
    WriteNotAuthorized(String),
    /// An origin cell's write is a route entry for this cell carrying no step
    /// its board signed from the cell's root, nor a departure leaving it: why.
    StepNotAuthorized(String),
    /// A fulfillment cell's write carries no 32-byte genesis hint: why.
    GenesisHint(String),
    /// A fulfillment cell's write is a route entry for this cell carrying no
    /// `F` that, with the genesis it carries, names this cell and verifies
    /// under its own key: why.
    FulfillmentNotAuthorized(String),
    /// The proof's key did not sign this write.
    Signature,
    /// The signature could not be checked.
    Crypto(String),
    /// No member keeps a write in this namespace any more.
    Retired,
}

impl core::fmt::Display for CellWriteRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Namespace(why) => {
                write!(f, "the namespace is longer than its length prefix: {why}")
            }
            Self::ProofOnOpenCell => write!(f, "an open cell's write carries no proof"),
            Self::NoProof => write!(
                f,
                "the cell is owned and the write carries no owner's proof"
            ),
            Self::Wire(why) => write!(f, "the owner's proof is not its wire form: {why}"),
            Self::WrongAddress => write!(f, "the cell is not the address the proof binds"),
            Self::ClaimNotAuthorized => write!(
                f,
                "the register write carries no claim its trader authorized for this cell"
            ),
            Self::WriteNotAuthorized(why) => write!(
                f,
                "the application cell write carries no write a writer of its set signed: {why}"
            ),
            Self::StepNotAuthorized(why) => write!(
                f,
                "the origin cell write carries no step its board signed for this cell: {why}"
            ),
            Self::GenesisHint(why) => write!(
                f,
                "a fulfillment cell write carries the trader's 32-byte genesis: {why}"
            ),
            Self::FulfillmentNotAuthorized(why) => write!(
                f,
                "the fulfillment cell write carries no F its trader signed for this cell: {why}"
            ),
            Self::Signature => write!(f, "the proof's key did not sign this write"),
            Self::Crypto(why) => write!(f, "the signature could not be checked: {why}"),
            Self::Retired => write!(f, "no member keeps a write in this namespace any more"),
        }
    }
}

impl std::error::Error for CellWriteRefusal {}

pub(crate) fn strict<M: prost::Message + Default>(
    bytes: &[u8],
    wire: &str,
    max_tag: u32,
    limit: fn(u32) -> Option<FieldLimit>,
) -> Result<M, CellWriteRefusal> {
    validate_length_delimited_wire(bytes, wire, max_tag, limit, |tag| {
        (1..=max_tag).contains(&tag)
    })
    .map_err(|e| CellWriteRefusal::Wire(e.to_string()))?;
    let message = M::decode(bytes).map_err(|e| CellWriteRefusal::Wire(e.to_string()))?;
    if message.encode_to_vec() != bytes {
        return Err(CellWriteRefusal::Wire(format!(
            "{wire}: non-canonical field ordering or encoding"
        )));
    }
    Ok(message)
}

fn owned_write_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1 => Some(FieldLimit::Fixed(32)),
        2 => Some(FieldLimit::Fixed(CELL_LOCK_LEN)),
        3 => Some(FieldLimit::Max(SIGNATURE_MAX_LEN)),
        _ => None,
    }
}

fn directory_write_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1 | 3 => Some(FieldLimit::Fixed(32)),
        2 => Some(FieldLimit::Fixed(AK_PUBLIC_KEY_LEN)),
        4 => Some(FieldLimit::Max(SIGNATURE_MAX_LEN)),
        _ => None,
    }
}

pub(crate) fn fixed32(bytes: &[u8]) -> Result<[u8; 32], CellWriteRefusal> {
    bytes
        .try_into()
        .map_err(|e: core::array::TryFromSliceError| CellWriteRefusal::Wire(e.to_string()))
}

pub(crate) fn signed_by(
    public_key: &[u8],
    target: &[u8; 32],
    signature: &[u8],
) -> Result<(), CellWriteRefusal> {
    if sphincs_verify(public_key, target, signature)
        .map_err(|e| CellWriteRefusal::Crypto(e.to_string()))?
    {
        Ok(())
    } else {
        Err(CellWriteRefusal::Signature)
    }
}

/// The route entry a delivery to a self-authorizing cell carries: the value
/// is its own authorization, so a delivery carries nothing else and has one
/// encoding without a proof; the entry must be canonical and name this cell.
fn delivered_entry(
    namespace: &[u8],
    key: &[u8; 32],
    value: &[u8],
    proof: &[u8],
) -> Result<crate::route_chain::RouteEntry, CellWriteRefusal> {
    if !proof.is_empty() {
        return Err(CellWriteRefusal::ProofOnOpenCell);
    }
    entry_naming(namespace, key, value)
}

/// The route entry `value` is, when it is canonical and names this cell.
fn entry_naming(
    namespace: &[u8],
    key: &[u8; 32],
    value: &[u8],
) -> Result<crate::route_chain::RouteEntry, CellWriteRefusal> {
    let entry = crate::route_chain::RouteEntry::decode(value)
        .ok_or(CellWriteRefusal::ClaimNotAuthorized)?;
    if entry.namespace != namespace || entry.key != *key {
        return Err(CellWriteRefusal::WrongAddress);
    }
    Ok(entry)
}

/// The check every member runs before it keeps `value` at `key` in
/// `namespace`, with `proof` as the write carried it (empty for none).
pub fn admit_cell_write(
    namespace: &[u8],
    key: &[u8; 32],
    value: &[u8],
    proof: &[u8],
) -> Result<(), CellWriteRefusal> {
    match ownership(namespace) {
        CellOwnership::Retired => Err(CellWriteRefusal::Retired),
        CellOwnership::Open => {
            if proof.is_empty() {
                Ok(())
            } else {
                Err(CellWriteRefusal::ProofOnOpenCell)
            }
        }
        CellOwnership::Owned => {
            if proof.is_empty() {
                return Err(CellWriteRefusal::NoProof);
            }
            let write: OwnedCellWriteV1 =
                strict(proof, "owned cell write", 3, owned_write_field_limit)?;
            let route = fixed32(&write.route)?;
            if owned_cell_address(&route, &write.lock_public_key) != *key {
                return Err(CellWriteRefusal::WrongAddress);
            }
            let target = write_target(TAG_DSM_OWNED_CELL_WRITE, namespace, key, value)?;
            signed_by(&write.lock_public_key, &target, &write.write_signature)
        }
        CellOwnership::Register => {
            let entry = delivered_entry(namespace, key, value, proof)?;
            if crate::economic::register::root_claim_naming(&entry.value, key).is_none() {
                return Err(CellWriteRefusal::ClaimNotAuthorized);
            }
            Ok(())
        }
        CellOwnership::Fulfillment => {
            let genesis = <[u8; 32]>::try_from(proof)
                .map_err(|e| CellWriteRefusal::GenesisHint(e.to_string()))?;
            let entry = entry_naming(namespace, key, value)?;
            match crate::sofi::registration::fulfillment_naming_cell(&entry.value, &genesis, key) {
                Ok(_fulfillment) => Ok(()),
                Err(why) => Err(CellWriteRefusal::FulfillmentNotAuthorized(why.to_string())),
            }
        }
        CellOwnership::OfflineOrigin => {
            let entry = delivered_entry(namespace, key, value, proof)?;
            match crate::offline_origin::write_occupying(&entry.value, key) {
                Ok(_step) => Ok(()),
                Err(why) => Err(CellWriteRefusal::StepNotAuthorized(format!("{why:?}"))),
            }
        }
        CellOwnership::Application => {
            let entry = delivered_entry(namespace, key, value, proof)?;
            match crate::app_cell::write_occupying(&entry.value, key) {
                Ok(_write) => Ok(()),
                Err(why) => Err(CellWriteRefusal::WriteNotAuthorized(format!("{why:?}"))),
            }
        }
        CellOwnership::Directory => {
            if proof.is_empty() {
                return Err(CellWriteRefusal::NoProof);
            }
            let write: DirectoryCellWriteV1 = strict(
                proof,
                "directory cell write",
                4,
                directory_write_field_limit,
            )?;
            let genesis = fixed32(&write.genesis)?;
            let att_a = fixed32(&write.att_a)?;
            let device_id =
                crate::core::identity::genesis_v2::derive_devid(&write.ak_public_key, &att_a);
            if directory_cell_key(&genesis, &device_id) != *key {
                return Err(CellWriteRefusal::WrongAddress);
            }
            let target = write_target(TAG_DSM_DIRECTORY_CELL_WRITE, namespace, key, value)?;
            signed_by(&write.ak_public_key, &target, &write.write_signature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One field of a signed body changed after signing: its name, and the change.
    type Alteration<T> = (&'static str, fn(&mut T));
    use crate::crypto::sphincs::generate_keypair_from_seed;

    fn lock(seed: u8) -> SphincsKeyPair {
        generate_keypair_from_seed(CELL_LOCK_VARIANT, &[seed; 32]).expect("a lock")
    }

    fn recovery_ns() -> &'static [u8] {
        crate::recovery::RecoveryCell::namespace()
    }

    /// The owner's write is kept; the same bytes under another lock, another
    /// value under the owner's proof, a proof for another namespace, a write
    /// with no proof and a proof bound to another route are each refused with
    /// the check that refuses it.
    /// MUTATION CONTROL (run 2026-11-19): dropping the address comparison
    /// lets the stranger's own signature over the owner's address in and
    /// turns this red; dropping the signature check turns the another-value
    /// and another-namespace assertions red.
    #[test]
    fn only_the_owners_lock_writes_an_owned_cell() {
        let owner = lock(0x11);
        let stranger = lock(0x22);
        let route = [0x7A; 32];
        let (address, proof) =
            sign_owned_cell_write(recovery_ns(), &route, &owner, b"the anchor").expect("signed");
        assert_eq!(address, owned_cell_address(&route, &owner.public_key));
        assert_eq!(
            admit_cell_write(recovery_ns(), &address, b"the anchor", &proof),
            Ok(())
        );

        // A stranger's lock binds another address: it cannot name the owner's cell.
        let (_, foreign) =
            sign_owned_cell_write(recovery_ns(), &route, &stranger, b"a copy").expect("signed");
        assert_eq!(
            admit_cell_write(recovery_ns(), &address, b"a copy", &foreign),
            Err(CellWriteRefusal::WrongAddress)
        );
        // The attack itself: a stranger signs a write naming the OWNER's
        // address with its own lock. The signature verifies under the
        // stranger's lock; only the address check refuses it.
        let aimed = {
            use prost::Message;
            let target = write_target(TAG_DSM_OWNED_CELL_WRITE, recovery_ns(), &address, b"a copy")
                .expect("a target");
            OwnedCellWriteV1 {
                route: route.to_vec(),
                lock_public_key: stranger.public_key.clone(),
                write_signature: sphincs_sign(&stranger.secret_key, &target).expect("signed"),
            }
            .encode_to_vec()
        };
        assert_eq!(
            admit_cell_write(recovery_ns(), &address, b"a copy", &aimed),
            Err(CellWriteRefusal::WrongAddress),
            "a stranger's own signature over the owner's address"
        );
        // The owner's proof does not carry another value.
        assert_eq!(
            admit_cell_write(recovery_ns(), &address, b"a copy", &proof),
            Err(CellWriteRefusal::Signature)
        );
        // Nor another route's address.
        let (other_route_address, _) =
            sign_owned_cell_write(recovery_ns(), &[0x7B; 32], &owner, b"the anchor")
                .expect("signed");
        assert_eq!(
            admit_cell_write(recovery_ns(), &other_route_address, b"the anchor", &proof),
            Err(CellWriteRefusal::WrongAddress)
        );
        // No proof at all.
        assert_eq!(
            admit_cell_write(recovery_ns(), &address, b"the anchor", &[]),
            Err(CellWriteRefusal::NoProof)
        );
        // A proof signed for another namespace.
        let (_, wrong_ns) =
            sign_owned_cell_write(b"DSM/other", &route, &owner, b"the anchor").expect("signed");
        assert_eq!(
            admit_cell_write(recovery_ns(), &address, b"the anchor", &wrong_ns),
            Err(CellWriteRefusal::Signature)
        );
    }

    /// A device writes its own directory cell; another device's AK, or a proof
    /// whose AttA is not this device's, names another cell and is refused.
    /// MUTATION CONTROL: dropping the address comparison turns the
    /// other-device assertion red; dropping the signature check turns the
    /// another-value assertion red.
    #[test]
    fn only_the_device_writes_its_directory_cell() {
        let ak = lock(0x31);
        let other = lock(0x32);
        let genesis = [0x6E; 32];
        let att_a = [0xA7; 32];
        let (address, proof) =
            sign_directory_cell_write(&genesis, &ak.public_key, &att_a, &ak.secret_key, b"entry")
                .expect("signed");
        let device_id = crate::core::identity::genesis_v2::derive_devid(&ak.public_key, &att_a);
        assert_eq!(address, directory_cell_key(&genesis, &device_id));
        assert_eq!(
            admit_cell_write(DIRECTORY_NAMESPACE, &address, b"entry", &proof),
            Ok(())
        );

        let (_, by_other) = sign_directory_cell_write(
            &genesis,
            &other.public_key,
            &att_a,
            &other.secret_key,
            b"entry",
        )
        .expect("signed");
        assert_eq!(
            admit_cell_write(DIRECTORY_NAMESPACE, &address, b"entry", &by_other),
            Err(CellWriteRefusal::WrongAddress)
        );
        assert_eq!(
            admit_cell_write(DIRECTORY_NAMESPACE, &address, b"another entry", &proof),
            Err(CellWriteRefusal::Signature)
        );
        assert_eq!(
            admit_cell_write(DIRECTORY_NAMESPACE, &address, b"entry", &[]),
            Err(CellWriteRefusal::NoProof)
        );
    }

    /// An open cell takes a write with no proof and refuses one that carries
    /// one; a proof that is not its strict wire form is refused as such.
    #[test]
    fn open_cells_carry_no_proof_and_proofs_are_strict() {
        let open = b"DSM/vault-successor/v1";
        assert_eq!(ownership(open), CellOwnership::Open);
        assert_eq!(admit_cell_write(open, &[1; 32], b"v", &[]), Ok(()));
        assert_eq!(
            admit_cell_write(open, &[1; 32], b"v", &[0x0A, 0x00]),
            Err(CellWriteRefusal::ProofOnOpenCell)
        );
        assert!(matches!(
            admit_cell_write(recovery_ns(), &[1; 32], b"v", &[0xFF, 0xFF]),
            Err(CellWriteRefusal::Wire(_))
        ));
    }

    /// A register entry for `claim` at `key`, at `position` on the route.
    fn register_entry(key: [u8; 32], claim: Vec<u8>, position: usize) -> Vec<u8> {
        crate::route_chain::RouteEntry {
            namespace: crate::economic::register::economic_root_namespace().to_vec(),
            key,
            value: claim,
            seat: b"dsm-node-1".to_vec(),
            position,
            // One slot per earlier position, as a relayed copy carries.
            chain: (0..position)
                .map(|_| crate::route_chain::ChainSlot::NoResponse)
                .collect(),
        }
        .encode()
    }

    /// The trader authorizes; anyone delivers (owner, 2026-11-19). A claim the
    /// trader's key signed for its own `K_root(q)` is kept at the leader and
    /// as a relayed copy at a later seat, with no proof and whoever submits
    /// it. Junk, a claim for another position, a claim a stranger signed
    /// naming the trader's device, a claim delivered under another cell's key
    /// and a write carrying a proof are each refused. The address is
    /// `K_root(G, DevID, q)` itself: no lock enters it.
    /// MUTATION CONTROL: dropping the claim check lets the junk, the
    /// other-position claim and the stranger's claim in and turns this red;
    /// dropping the namespace/key comparison lets in the entry that names
    /// another cell around this cell's claim.
    #[test]
    fn a_register_keeps_only_claims_its_trader_authorized_from_anyone() {
        use crate::economic::claim_envelope::device_fixture::{device, signed_by, signed_conditional};
        use crate::economic::register::{economic_root_namespace, economic_root_register_key};
        use crate::sofi::wire::SofiResolutionClaim;
        let ns = economic_root_namespace();
        let trader = device([0xA7; 32]).expect("a trader");
        let stranger = device([0xB7; 32]).expect("a stranger");
        let claim_at = |position: u64| SofiResolutionClaim {
            genesis: [0x11; 32],
            device_id: trader.devid,
            position,
            fulfillment_id: [0xF1; 32],
            realize_root: [0xA1; 32],
            void_root: [0xB1; 32],
        };
        let key = economic_root_register_key(&[0x11; 32], &trader.devid, 7);
        let genuine = signed_conditional(claim_at(7), &trader).expect("C_q");

        assert_eq!(
            admit_cell_write(ns, &key, &register_entry(key, genuine.clone(), 0), &[]),
            Ok(())
        );
        assert_eq!(
            admit_cell_write(ns, &key, &register_entry(key, genuine.clone(), 2), &[]),
            Ok(()),
            "a relayed copy at a later seat"
        );
        assert_eq!(
            admit_cell_write(ns, &key, &register_entry(key, b"junk".to_vec(), 0), &[]),
            Err(CellWriteRefusal::ClaimNotAuthorized)
        );
        assert_eq!(
            admit_cell_write(ns, &key, b"not a route entry", &[]),
            Err(CellWriteRefusal::ClaimNotAuthorized)
        );
        let other_position = signed_conditional(claim_at(8), &trader).expect("C_q at 8");
        assert_eq!(
            admit_cell_write(ns, &key, &register_entry(key, other_position, 0), &[]),
            Err(CellWriteRefusal::ClaimNotAuthorized),
            "the trader's claim for another position"
        );
        let squatted = signed_by(claim_at(7), &stranger, stranger.att_a).expect("a squatter's C_q");
        assert_eq!(
            admit_cell_write(ns, &key, &register_entry(key, squatted, 0), &[]),
            Err(CellWriteRefusal::ClaimNotAuthorized),
            "a stranger's signature naming the trader's device"
        );
        let elsewhere = economic_root_register_key(&[0x11; 32], &trader.devid, 9);
        assert_eq!(
            admit_cell_write(
                ns,
                &key,
                &register_entry(elsewhere, genuine.clone(), 0),
                &[]
            ),
            Err(CellWriteRefusal::WrongAddress),
            "this cell's genuine claim in an entry that names another cell"
        );
        assert_eq!(
            admit_cell_write(
                ns,
                &elsewhere,
                &register_entry(key, genuine.clone(), 0),
                &[]
            ),
            Err(CellWriteRefusal::WrongAddress),
            "a genuine claim delivered under another cell's key"
        );
        assert_eq!(
            admit_cell_write(ns, &key, &register_entry(key, genuine, 0), &[0x0A, 0x00]),
            Err(CellWriteRefusal::ProofOnOpenCell)
        );
    }

    /// What a member keeps at a register is bound to the trader, the
    /// position and the transition the trader signed. Each signed field of a
    /// claim, changed after signing with the trader's signature kept, is
    /// refused at the cell the changed claim names; so is the trader's own
    /// key under another AttA, a claim delivered at another device's or
    /// genesis's register, and the trader's claim in an entry of another
    /// namespace. Both claim kinds: the single-root envelope and the signed
    /// `C_q`.
    /// MUTATION CONTROL: dropping the claim check in `admit_cell_write`
    /// keeps every altered claim and turns this red; dropping only the
    /// namespace half of the delivered entry's comparison keeps the entry of
    /// another namespace.
    #[test]
    fn a_register_keeps_a_claim_only_as_its_trader_signed_it() {
        use crate::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F as ALG;
        use crate::economic::claim::EconomicRootClaimBody;
        use crate::economic::claim_envelope::device_fixture::device;
        use crate::economic::claim_envelope::sign_economic_root_claim;
        use crate::economic::register::{economic_root_namespace, economic_root_register_key};
        use crate::sofi::wire::{SignedSofiResolutionClaim, SofiResolutionClaim};
        use crate::types::proto as generated;
        use prost::Message;
        let ns = economic_root_namespace();
        let trader = device([0xA7; 32]).expect("a trader");
        let other = device([0xC7; 32]).expect("another device");
        let genesis = [0x11; 32];
        // The key the claim names, and the write delivering it there.
        let admit_at = |g: &[u8; 32], devid: &[u8; 32], q: u64, claim: Vec<u8>| {
            let key = economic_root_register_key(g, devid, q);
            admit_cell_write(ns, &key, &register_entry(key, claim, 0), &[])
        };
        let refused =
            |r: Result<(), CellWriteRefusal>| r == Err(CellWriteRefusal::ClaimNotAuthorized);

        // The single-root envelope.
        let body = EconomicRootClaimBody::new(
            genesis,
            trader.devid,
            7,
            [0x0E; 32],
            [0x0F; 32],
            [0x5E; 32],
            ALG,
            &trader.pk,
            trader.att_a,
        )
        .expect("a claim body");
        let signed = sign_economic_root_claim(&body, &trader.sk).expect("signed");
        assert_eq!(admit_at(&genesis, &trader.devid, 7, signed.clone()), Ok(()));
        let signature = generated::EconomicRootClaimV1::decode(signed.as_slice())
            .expect("an envelope")
            .claimant_signature;
        let resealed = |b: &EconomicRootClaimBody| {
            generated::EconomicRootClaimV1 {
                body_ccb: b.encode().expect("a body"),
                claimant_signature: signature.clone(),
            }
            .encode_to_vec()
        };
        let altered: [Alteration<EconomicRootClaimBody>; 7] = [
            ("genesis", |b| b.trader_genesis = [0x12; 32]),
            ("position", |b| b.economic_position = 8),
            ("root", |b| b.post_economic_root = [0x1E; 32]),
            ("manifest", |b| b.admission_manifest_addr = [0x1F; 32]),
            ("set id", |b| b.root_register_storage_set_id = [0x6E; 32]),
            ("devid", |b| b.trader_devid = [0xD1; 32]),
            ("AttA", |b| b.claimant_att_a = [0xA8; 32]),
        ];
        for (field, alter) in altered {
            let mut b = body.clone();
            alter(&mut b);
            assert!(
                refused(admit_at(
                    &b.trader_genesis,
                    &b.trader_devid,
                    b.economic_position,
                    resealed(&b)
                )),
                "a single-root claim with its {field} changed after signing"
            );
        }
        let mut under_other_key = body.clone();
        under_other_key.claimant_public_key = other.pk.clone();
        assert!(
            refused(admit_at(
                &genesis,
                &trader.devid,
                7,
                resealed(&under_other_key)
            )),
            "a single-root claim naming another AK"
        );
        let mut own_key_other_att_a = body.clone();
        own_key_other_att_a.claimant_att_a = other.att_a;
        assert!(
            refused(admit_at(
                &genesis,
                &trader.devid,
                7,
                sign_economic_root_claim(&own_key_other_att_a, &trader.sk).expect("signed")
            )),
            "the trader's own key under another AttA"
        );
        assert!(
            refused(admit_cell_write(
                ns,
                &economic_root_register_key(&genesis, &other.devid, 7),
                &register_entry(
                    economic_root_register_key(&genesis, &other.devid, 7),
                    signed.clone(),
                    0
                ),
                &[]
            )),
            "the trader's claim at another device's register"
        );
        assert!(
            refused(admit_cell_write(
                ns,
                &economic_root_register_key(&[0x12; 32], &trader.devid, 7),
                &register_entry(
                    economic_root_register_key(&[0x12; 32], &trader.devid, 7),
                    signed.clone(),
                    0
                ),
                &[]
            )),
            "the trader's claim at another genesis's register"
        );
        let key = economic_root_register_key(&genesis, &trader.devid, 7);
        let in_other_namespace = crate::route_chain::RouteEntry {
            namespace: b"DSM/sofi/fulfillment/v1".to_vec(),
            key,
            value: signed,
            seat: b"dsm-node-1".to_vec(),
            position: 0,
            chain: Vec::new(),
        }
        .encode();
        assert_eq!(
            admit_cell_write(ns, &key, &in_other_namespace, &[]),
            Err(CellWriteRefusal::WrongAddress),
            "the trader's claim in an entry of another namespace"
        );

        // The signed C_q.
        let c_q = SofiResolutionClaim {
            genesis,
            device_id: trader.devid,
            position: 7,
            fulfillment_id: [0xF1; 32],
            realize_root: [0xA1; 32],
            void_root: [0xB1; 32],
        };
        let digest = crate::sofi::derive::resolution_claim_signing_digest(
            &c_q,
            ALG,
            &trader.pk,
            &trader.att_a,
        );
        let c_q_signature =
            crate::crypto::sphincs::sphincs_sign(&trader.sk, &digest).expect("signs");
        let sealed = |claim: SofiResolutionClaim, pk: &[u8], att_a: [u8; 32]| {
            SignedSofiResolutionClaim::new(claim, ALG, pk, att_a, &c_q_signature)
                .expect("a claim's shape")
                .encode()
        };
        assert_eq!(
            admit_at(
                &genesis,
                &trader.devid,
                7,
                sealed(c_q, &trader.pk, trader.att_a)
            ),
            Ok(())
        );
        let altered: [Alteration<SofiResolutionClaim>; 6] = [
            ("genesis", |c| c.genesis = [0x12; 32]),
            ("device id", |c| c.device_id = [0xD1; 32]),
            ("position", |c| c.position = 8),
            ("fulfillment id", |c| c.fulfillment_id = [0xF2; 32]),
            ("realize root", |c| c.realize_root = [0xA2; 32]),
            ("void root", |c| c.void_root = [0xB2; 32]),
        ];
        for (field, alter) in altered {
            let mut c = c_q;
            alter(&mut c);
            assert!(
                refused(admit_at(
                    &c.genesis,
                    &c.device_id,
                    c.position,
                    sealed(c, &trader.pk, trader.att_a)
                )),
                "a C_q with its {field} changed after signing"
            );
        }
        assert!(
            refused(admit_at(
                &genesis,
                &trader.devid,
                7,
                sealed(c_q, &other.pk, trader.att_a)
            )),
            "a C_q naming another AK"
        );
        assert!(
            refused(admit_at(
                &genesis,
                &trader.devid,
                7,
                sealed(c_q, &trader.pk, other.att_a)
            )),
            "a C_q naming another AttA"
        );
        let mut tampered = sealed(c_q, &trader.pk, trader.att_a);
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            refused(admit_at(&genesis, &trader.devid, 7, tampered)),
            "a C_q with a flipped signature byte"
        );
    }

    /// The cell lock comes back from the master seed alone and is not the
    /// device's other keys.
    #[test]
    fn the_cell_lock_comes_back_from_the_master_seed() {
        let a = derive_cell_lock_keypair(&[0x5A; 32], &[0x01; 32]).expect("a lock");
        let b = derive_cell_lock_keypair(&[0x5A; 32], &[0x01; 32]).expect("a lock");
        let other_device = derive_cell_lock_keypair(&[0x5A; 32], &[0x02; 32]).expect("a lock");
        assert_eq!(a.public_key, b.public_key);
        assert_ne!(a.public_key, other_device.public_key);
        let first_inbox = crate::core::relationship_write_grant::derive_first_inbox_lock_keypair(
            &[0x5A; 32],
            &[0x01; 32],
        )
        .expect("the first-inbox lock");
        assert_ne!(a.public_key, first_inbox.public_key);
    }
}
