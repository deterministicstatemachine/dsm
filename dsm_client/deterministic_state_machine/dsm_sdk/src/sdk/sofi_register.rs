// SPDX-License-Identifier: Apache-2.0

//! Part II §17.4 and stage 7 of §31, rebuild step R9: install a fulfillment at
//! its position — the two position cells, written together.
//!
//! The writer puts the signed envelope of `F` at `K_ful(q)` and
//! `C_q = SofiResolutionClaim(G, DevID, q, FulfillmentId, R_realize, R_void)`
//! at `K_root(q)` in ONE local transaction at the leader of `s(q)`, both or
//! neither, then the same bytes on the other members. `C_q` is computed from
//! the verified `P` and `F` and never caller-supplied, so no claim that
//! disagrees with `F` can be `F`'s claim. The member stores bytes; it
//! establishes nothing. Whether `F` registered is Core's conclusion from raw
//! reads (`FulfillmentRegistered`, rebuild step R10), never a fact this
//! module produces.
//!
//! Before anything is written the producer obtains
//! `FulfillmentConformance(F) = Valid` over evidence it acquired from
//! storage (Section 20.2: "A producer MUST obtain Valid before it publishes
//! F"). Rule T5 holds here as at the draft: on `Unavailable` nothing is
//! written and what is missing is named; on `Invalid` the fulfillment is
//! refused with its reason. A producer that installed a non-conforming `F`
//! would occupy the trader's one position with an exercise nothing realizes.

use std::collections::BTreeMap;

use dsm::common::domain_tags::TAG_DSM_SOFI_FULFILLMENT;
use dsm::economic::register::{economic_root_register_key, position_seed};
use dsm::sofi::conformance::{
    fulfillment_conformance, ConformanceEvidence, ConformanceMissing, FulfillmentConformance,
    FulfillmentConformanceError,
};
use dsm::sofi::derive;
use dsm::sofi::publication::{Publication, Signed};
use dsm::sofi::storage::Resolved;
use dsm::sofi::wire::{
    SettlementPreimage, SofiWireError, TraderFulfillmentBody, TraderPrecommitBody, ValidationRef,
};
use dsm::types::error::DsmError;

use dsm::sofi::arith::resolve_objects;
use dsm::sofi::registration::{fulfillment_registered, names_fulfillment_key, Registration};

use crate::sdk::economic_registers::{economic_root_namespace, names_root_key};
use crate::sdk::sofi_evidence::LOCATOR_BUDGET;
use crate::sdk::sofi_publish::{fetch_precommit, fetch_setup};
use crate::sdk::storage_io::{leader_index, read_cell_raw, read_stored_bytes, write_cells_leader_first};
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

/// Everything an install takes: the exercise the trader signed, the `P` it
/// names, `P(E)`, and the exact bytes the trader holds for the closure
/// references that are its own.
#[derive(Debug, Clone, Copy)]
pub struct InstallRequest<'a> {
    pub precommit: &'a TraderPrecommitBody,
    pub precommit_signature: &'a [u8],
    pub preimage: &'a SettlementPreimage,
    pub fulfillment: &'a TraderFulfillmentBody,
    pub fulfillment_signature: &'a [u8],
    /// Bytes the trader holds for the closure references only it can supply
    /// exactly: the registered claim envelope a `SingleRootClaim` names, the
    /// final claim bytes at `K_root(p)` a `ConditionalClaim` names. Core
    /// re-derives every reference from the bytes; nothing here is trusted.
    pub own_objects: &'a BTreeMap<ValidationRef, Vec<u8>>,
}

/// Why nothing was installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallError {
    /// The objects do not have canonical bytes in this shape.
    Wire(SofiWireError),
    /// `FulfillmentConformance(F)` is Invalid, for this reason. Nothing is
    /// written: an installed non-conforming `F` would occupy the position
    /// with an exercise nothing realizes.
    NotConforming(FulfillmentConformanceError),
    /// Rule T5: evidence conformance needs is not in hand. Nothing is
    /// written; what is missing is named.
    Unavailable(ConformanceMissing),
    /// The members could not be read or written.
    Storage(String),
    /// The leader of `s(q)` did not take the pair. The cells wait for it; no
    /// other member stands in, and the copies that did land are carried.
    LeaderUnreached { copies: u32 },
}

impl From<SofiWireError> for InstallError {
    fn from(e: SofiWireError) -> Self {
        Self::Wire(e)
    }
}

impl From<DsmError> for InstallError {
    fn from(e: DsmError) -> Self {
        Self::Storage(e.to_string())
    }
}

/// The two cells of position `q` and the seed their leader is drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub position: u64,
    pub k_ful: D32,
    pub k_root: D32,
    /// `s(q) = H(position-seed; G ‖ DevID ‖ q ‖ R_p)`, with `R_p` the root
    /// the operation was built on — `P.void_root = T°.pre_economic_root`.
    pub seed: D32,
}

/// Where a fulfillment of `precommit` installs. Every input is a field of
/// the two verified objects.
pub fn position_of(
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
) -> Position {
    let q = fulfillment.position();
    Position {
        position: q,
        k_ful: derive::fulfillment_register_key(precommit.genesis(), precommit.device_id(), q),
        k_root: economic_root_register_key(precommit.genesis(), precommit.device_id(), q),
        seed: position_seed(
            precommit.genesis(),
            precommit.device_id(),
            q,
            precommit.void_root(),
        ),
    }
}

/// What the install established: the pair reached the leader, and how many
/// other members took it. Registration is not among these — Core derives it
/// from raw reads (R10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    pub at: Position,
    pub leader_reached: bool,
    pub copies: u32,
}

/// Acquire what `FulfillmentConformance(F)` reads, from storage and the
/// request. Items 1, 2 and 8 come with the request; item 6's setups are
/// fetched under their `ρ` (R8); the closure objects are fetched by the rule
/// of each reference kind. Item 5's earlier attempt keys are resolved by the
/// exercise objects of rebuild step R11 and are not fetched here: an attempt
/// above zero waits, and the producer stops on it.
pub async fn acquire_conformance_evidence(
    set: &StorageSet,
    request: &InstallRequest<'_>,
) -> Result<ConformanceEvidence, DsmError> {
    let mut setups = BTreeMap::new();
    for leg in request.precommit.legs() {
        if let Resolved::Kept(signed) = fetch_setup(set, &leg.setup_ref).await? {
            setups.insert(leg.setup_ref, setup_object_bytes(&signed)?);
        }
    }
    let mut closure = BTreeMap::new();
    for reference in request.preimage.settlement().closure().refs() {
        let bytes = match reference {
            ValidationRef::ContentAddr { addr, .. } => read_stored_bytes(set, addr).await?,
            ValidationRef::Setup { setup_ref } => match fetch_setup(set, setup_ref).await? {
                Resolved::Kept(signed) => Some(setup_object_bytes(&signed)?),
                Resolved::None | Resolved::Unavailable => None,
            },
            ValidationRef::SingleRootClaim { .. } | ValidationRef::ConditionalClaim { .. } => {
                request.own_objects.get(reference).cloned()
            }
        };
        if let Some(bytes) = bytes {
            closure.insert(*reference, bytes);
        }
    }
    Ok(ConformanceEvidence {
        precommit: Some(Signed {
            body: request.precommit.clone(),
            signature: request.precommit_signature.to_vec(),
        }),
        preimage: Some(request.preimage.clone()),
        closure,
        setups,
        prior_attempts: BTreeMap::new(),
    })
}

fn setup_object_bytes(
    signed: &Signed<dsm::sofi::wire::SofiSetupBody>,
) -> Result<Vec<u8>, DsmError> {
    Publication::Setup {
        body: &signed.body,
        signature: &signed.signature,
    }
    .object_bytes()
    .map_err(|e| DsmError::verification(format!("setup object: {e}")))
}

/// Install `F` at its position: conformance first, then the pair at the
/// leader of `s(q)` and the same bytes on the other members.
pub async fn install_fulfillment(
    set: &StorageSet,
    request: &InstallRequest<'_>,
) -> Result<Installed, InstallError> {
    let evidence = acquire_conformance_evidence(set, request).await?;
    match fulfillment_conformance(
        request.fulfillment,
        request.fulfillment_signature,
        &evidence,
    ) {
        FulfillmentConformance::Valid => {}
        FulfillmentConformance::Invalid(why) => return Err(InstallError::NotConforming(why)),
        FulfillmentConformance::Unavailable(what) => return Err(InstallError::Unavailable(what)),
    }
    let at = position_of(request.precommit, request.fulfillment);
    let fulfillment_bytes = Publication::Fulfillment {
        body: request.fulfillment,
        signature: request.fulfillment_signature,
    }
    .object_bytes()?;
    let claim_bytes = derive::resolution_claim(request.precommit, request.fulfillment).encode();
    let entries = [
        (
            TAG_DSM_SOFI_FULFILLMENT.source_bytes().to_vec(),
            at.k_ful,
            fulfillment_bytes,
        ),
        (economic_root_namespace().to_vec(), at.k_root, claim_bytes),
    ];
    let write = write_cells_leader_first(set, &at.seed, &entries).await?;
    if !write.leader_reached {
        return Err(InstallError::LeaderUnreached {
            copies: write.copies,
        });
    }
    Ok(Installed {
        at,
        leader_reached: true,
        copies: write.copies,
    })
}

/// `FulfillmentRegistered` at position `q` of trader `(G, DevID)`, derived
/// from raw reads of the two cells (Part II §13, rebuild step R10). `parent_root`
/// is `R_p`, the root the verifier validated itself, from which `s(q)` and
/// the leader follow. No member computes or writes any of this.
///
/// The recognized view at `K_ful(q)` needs each candidate's `P`: every
/// fulfillment envelope any member holds at the key names one, and those are
/// fetched by id (R8), at most `LOCATOR_BUDGET` of them. A candidate whose
/// `P` is not in hand names nothing yet — the read answers `Unresolved`, and
/// a later read can answer.
pub async fn read_registration(
    set: &StorageSet,
    genesis: &D32,
    device_id: &D32,
    position: u64,
    parent_root: &D32,
) -> Result<Registration, DsmError> {
    let k_ful = derive::fulfillment_register_key(genesis, device_id, position);
    let k_root = economic_root_register_key(genesis, device_id, position);
    let seed = position_seed(genesis, device_id, position, parent_root);
    let leader = leader_index(set, &seed)?;
    let ful_reads = read_cell_raw(set, TAG_DSM_SOFI_FULFILLMENT.source_bytes(), &k_ful).await?;
    let root_reads = read_cell_raw(set, economic_root_namespace(), &k_root).await?;

    // The precommits the candidates name, fetched by id: the only way to
    // learn whose fulfillment a candidate is, and what its C_q would be.
    let mut precommits: BTreeMap<D32, TraderPrecommitBody> = BTreeMap::new();
    let mut examined = 0usize;
    for value in ful_reads.iter().flatten().flatten() {
        let Some((_, signed)) = dsm::sofi::publication::recognize_fulfillment(value) else {
            continue;
        };
        let pid = *signed.body.precommit_id();
        if precommits.contains_key(&pid) {
            continue;
        }
        examined += 1;
        if examined > LOCATOR_BUDGET {
            break;
        }
        if let Resolved::Kept(p) = fetch_precommit(set, &pid).await? {
            precommits.insert(pid, p.body);
        }
    }

    let arity = |e: dsm::sofi::arith::ArityError| DsmError::verification(e.to_string());
    let fulfillment = resolve_objects(&ful_reads, leader, |bytes| {
        names_fulfillment_key(bytes, genesis, device_id, position, &precommits).is_some()
    })
    .map_err(arity)?;
    let root = resolve_objects(&root_reads, leader, |bytes| names_root_key(bytes, &k_root))
        .map_err(arity)?;
    Ok(fulfillment_registered(
        &fulfillment,
        &root,
        genesis,
        device_id,
        position,
        &precommits,
    ))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use std::sync::OnceLock;

    use dsm::ccb::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use dsm::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use dsm::sofi::signature::SigningPayload;
    use dsm::sofi::wire::{SofiResolutionClaim, SofiSetupBody};
    use dsm::types::operations::Operation;
    use serial_test::serial;

    use super::*;
    use crate::sdk::economic_registers::{read_economic_root_cell, register_economic_root};
    use crate::sdk::sofi_publish::publish_produced;
    use crate::sdk::sofi_sdk::{build_fulfillment, draft_route, Produced, ToPublish};
    use crate::sdk::sofi_test_fixtures::{
        all_policies, d, five, token, RouteFixture, DEV, G, OWNER_DEV, OWNER_G, P_CREATE, P_POS,
    };
    use crate::sdk::storage_io::{fake_fleet, fake_registers, leader_index};

    fn keys() -> &'static (Vec<u8>, Vec<u8>) {
        static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        KEYS.get_or_init(|| generate_sphincs_keypair().unwrap())
    }

    fn sign(message: &[u8]) -> Vec<u8> {
        sphincs_sign(&keys().1, message).unwrap()
    }

    fn block_on<T>(f: impl core::future::Future<Output = T>) -> T {
        crate::runtime::get_runtime().block_on(f)
    }

    /// A two-hop route whose legs carry the `ρ` of real setups, everything
    /// published to the fake fleet — the setups too, when asked — and the
    /// signed exercise ready to install.
    struct Rig {
        set: StorageSet,
        precommit: TraderPrecommitBody,
        p_sig: Vec<u8>,
        preimage: SettlementPreimage,
        fulfillment: TraderFulfillmentBody,
        f_sig: Vec<u8>,
        own: BTreeMap<ValidationRef, Vec<u8>>,
        setups: Vec<SofiSetupBody>,
    }

    fn produced_setup(body: &SofiSetupBody) -> Produced {
        Produced {
            operation: Operation::SofiSetup {
                setup_body: body.encode(),
                signature: Vec::new(),
            },
            signs: SigningPayload::SetupDigest(derive::setup_signing_digest(body)),
            publish: vec![ToPublish::Setup(body.clone())],
        }
    }

    fn rig(publish_setups: bool) -> Rig {
        fake_fleet::reset();
        fake_registers::reset();
        let set = five();
        let setups: Vec<SofiSetupBody> = (0..2)
            .map(|j| {
                let vault_id = derive::vault_id(&OWNER_G, &OWNER_DEV, P_CREATE + j as u64);
                SofiSetupBody::new(
                    G,
                    DEV,
                    P_POS - 1,
                    vault_id,
                    d(0x0B),
                    d(0x0C),
                    ALG,
                    &keys().0,
                )
                .unwrap()
            })
            .collect();
        let rhos: Vec<D32> = setups.iter().map(derive::setup_ref).collect();
        let fx = RouteFixture::swap_with_setups(
            2,
            set.id(),
            |j| (token(j), token(j + 1)),
            |j, _| rhos[j],
        );
        fx.publish(&set, &all_policies());
        let evidence = fx.acquire(&set);
        let draft = draft_route(
            fx.hops.clone(),
            fx.cores.clone(),
            &fx.ctx(&keys().0),
            fx.realize_root,
            fx.void_root,
            &evidence,
        )
        .unwrap();
        let p_sig = sign(&draft.precommit_signing_digest());
        let attempts: Vec<(D32, u64)> = draft
            .precommit()
            .legs()
            .iter()
            .map(|l| (l.vault_id, 0))
            .collect();
        let produced = build_fulfillment(&draft, p_sig.clone(), &attempts).unwrap();
        let f_sig = sign(produced.signs.bytes());
        block_on(publish_produced(&set, &produced, &f_sig)).unwrap();
        if publish_setups {
            for body in &setups {
                let sig = sign(&derive::setup_signing_digest(body));
                block_on(publish_produced(&set, &produced_setup(body), &sig)).unwrap();
            }
        }
        let fulfillment = produced
            .publish
            .iter()
            .find_map(|p| match p {
                ToPublish::Fulfillment(f) => Some(f.clone()),
                _ => None,
            })
            .unwrap();
        Rig {
            set,
            precommit: draft.precommit().clone(),
            p_sig,
            preimage: draft.preimage().clone(),
            fulfillment,
            f_sig,
            own: BTreeMap::new(),
            setups,
        }
    }

    fn request(r: &Rig) -> InstallRequest<'_> {
        InstallRequest {
            precommit: &r.precommit,
            precommit_signature: &r.p_sig,
            preimage: &r.preimage,
            fulfillment: &r.fulfillment,
            fulfillment_signature: &r.f_sig,
            own_objects: &r.own,
        }
    }

    fn pair_bytes(r: &Rig) -> (Vec<u8>, Vec<u8>) {
        (
            Publication::Fulfillment {
                body: &r.fulfillment,
                signature: &r.f_sig,
            }
            .object_bytes()
            .unwrap(),
            derive::resolution_claim(&r.precommit, &r.fulfillment).encode(),
        )
    }

    fn ful_ns() -> &'static [u8] {
        TAG_DSM_SOFI_FULFILLMENT.source_bytes()
    }

    fn all_members(set: &StorageSet) -> Vec<String> {
        set.members().iter().map(|m| m.member_id.clone()).collect()
    }

    /// Stage 7 of §31: over evidence acquired from the fleet, conformance is
    /// Valid, and the pair lands at the leader of `s(q)` — the leader an
    /// ordinary claim at `q` would race at — and on every other member, both
    /// halves each. `C_q` is what Core reads as final at `K_root(q)`.
    #[test]
    #[serial]
    fn a_conforming_fulfillment_installs_both_halves_at_the_leader_of_its_position() {
        let r = rig(true);
        let installed = block_on(install_fulfillment(&r.set, &request(&r))).unwrap();
        assert!(installed.leader_reached);
        assert_eq!(installed.copies, 4);
        let at = installed.at;
        assert_eq!(at.position, r.precommit.position() + 1);
        assert_eq!(
            at.seed,
            position_seed(&G, &DEV, at.position, r.precommit.void_root()),
            "the seed consumes the root the operation was built on"
        );
        let (f_bytes, c_bytes) = pair_bytes(&r);
        assert_eq!(
            fake_registers::holders(&r.set, ful_ns(), &at.k_ful, &f_bytes),
            all_members(&r.set)
        );
        assert_eq!(
            fake_registers::holders(&r.set, economic_root_namespace(), &at.k_root, &c_bytes),
            all_members(&r.set)
        );
        // The claim is computed from the two verified objects, never supplied.
        let claim = SofiResolutionClaim::decode(&c_bytes).unwrap();
        assert_eq!(claim.fulfillment_id, derive::fulfillment_id(&r.fulfillment));
        assert_eq!(&claim.realize_root, r.precommit.realize_root());
        assert_eq!(&claim.void_root, r.precommit.void_root());
        // Final at K_root(q), as the register reader derives it (leader first,
        // two copies): the object naming the key is C_q.
        assert_eq!(
            block_on(read_economic_root_cell(&r.set, &at.k_root, &at.seed)).unwrap(),
            Some(c_bytes)
        );
        let _ = leader_index(&r.set, &at.seed).unwrap();
    }

    /// Rule T5 at the install: with the setups unpublished, conformance waits
    /// on exactly them, and nothing is written anywhere.
    #[test]
    #[serial]
    fn nothing_is_installed_while_conformance_waits() {
        let r = rig(false);
        let at = position_of(&r.precommit, &r.fulfillment);
        assert_eq!(
            block_on(install_fulfillment(&r.set, &request(&r))),
            Err(InstallError::Unavailable(ConformanceMissing::Setup {
                setup_ref: r.precommit.legs()[0].setup_ref,
            }))
        );
        for reads in [
            fake_registers::get_cells(&r.set, ful_ns(), &at.k_ful),
            fake_registers::get_cells(&r.set, economic_root_namespace(), &at.k_root),
        ] {
            assert!(
                reads.iter().all(|m| m.as_deref() == Some(&[][..])),
                "no member holds anything"
            );
        }
        let _ = &r.setups;
    }

    /// A fulfillment conformance refuses is refused before anything is
    /// written: the position stays open for the exercise that conforms.
    #[test]
    #[serial]
    fn a_non_conforming_fulfillment_is_refused_before_anything_is_written() {
        let r = rig(true);
        let wrong = TraderFulfillmentBody::new(
            *r.fulfillment.precommit_id(),
            r.fulfillment.policy_fulfillment_set().to_vec(),
            r.fulfillment.attempts().to_vec(),
            r.fulfillment.position() + 1,
            ALG,
            &keys().0,
        )
        .unwrap();
        let wrong_sig = sign(&derive::fulfillment_signing_digest(&wrong));
        let mut req = request(&r);
        req.fulfillment = &wrong;
        req.fulfillment_signature = &wrong_sig;
        assert_eq!(
            block_on(install_fulfillment(&r.set, &req)),
            Err(InstallError::NotConforming(
                FulfillmentConformanceError::PositionNotSuccessor {
                    expected: r.precommit.position() + 1,
                    got: r.precommit.position() + 2,
                }
            ))
        );
        let at = position_of(&r.precommit, &wrong);
        assert!(fake_registers::get_cells(&r.set, ful_ns(), &at.k_ful)
            .iter()
            .all(|m| m.as_deref() == Some(&[][..])));
    }

    /// PositionPairAtomic (TLA `DSM_SofiSuccessorCells`, Lean
    /// `position_pair_atomic`): no member ever holds one half of a position.
    /// A member that is down takes neither; a member that cannot take
    /// `K_root(q)` takes neither, because the pair is one transaction.
    /// Mutation: the pair written as two single puts — the member that
    /// refused `K_root(q)` then holds `F` alone.
    #[test]
    #[serial]
    fn no_member_ever_holds_one_half_of_a_position() {
        let r = rig(true);
        let at = position_of(&r.precommit, &r.fulfillment);
        let leader = leader_index(&r.set, &at.seed).unwrap();
        let others: Vec<&str> = r
            .set
            .members()
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != leader)
            .map(|(_, m)| m.member_id.as_str())
            .collect();
        fake_registers::fail_member(others[0], true);
        fake_registers::fail_cell(others[1], economic_root_namespace(), &at.k_root);
        let installed = block_on(install_fulfillment(&r.set, &request(&r))).unwrap();
        assert!(installed.leader_reached);
        assert_eq!(installed.copies, 2);
        let (f_bytes, c_bytes) = pair_bytes(&r);
        let holds_f = fake_registers::holders(&r.set, ful_ns(), &at.k_ful, &f_bytes);
        let holds_c =
            fake_registers::holders(&r.set, economic_root_namespace(), &at.k_root, &c_bytes);
        assert_eq!(holds_f, holds_c, "both halves or neither, at every member");
        assert_eq!(holds_f.len(), 3);
        assert!(!holds_f.iter().any(|m| m == others[0]));
        assert!(!holds_f.iter().any(|m| m == others[1]));
    }

    /// §7.2: one seed serves both — an ordinary claim at the same `q` races
    /// at the same leader, and the member keeps what it is given. `C_q`, the
    /// leader's first object naming the key, stays what Core reads as final;
    /// the later claim is held, not refused, and is nothing at the cell.
    #[test]
    #[serial]
    fn an_ordinary_claim_at_the_same_position_races_at_the_same_leader_and_is_kept() {
        let r = rig(true);
        let installed = block_on(install_fulfillment(&r.set, &request(&r))).unwrap();
        let at = installed.at;
        let later = b"an ordinary claim envelope, arriving second".to_vec();
        let claimed = block_on(register_economic_root(
            &r.set,
            &G,
            &DEV,
            at.position,
            r.precommit.void_root(),
            &later,
        ))
        .unwrap();
        assert_eq!(claimed.accepted(), 5, "kept everywhere, refused nowhere");
        assert_eq!(
            fake_registers::holders(&r.set, economic_root_namespace(), &at.k_root, &later).len(),
            5
        );
        let (_, c_bytes) = pair_bytes(&r);
        assert_eq!(
            block_on(read_economic_root_cell(&r.set, &at.k_root, &at.seed)).unwrap(),
            Some(c_bytes),
            "the first object naming the key at the leader is what is final"
        );
    }

    // ── R10: FulfillmentRegistered, derived from the two cells ─────────────

    /// Part II §13: after the install, the two cells' final values ARE the
    /// registration — nothing else was written anywhere, and the reader
    /// derives the fact from raw reads with the same leader an install used.
    #[test]
    #[serial]
    fn a_registration_is_derived_from_the_two_cells_and_no_member_writes_it() {
        let r = rig(true);
        let at = position_of(&r.precommit, &r.fulfillment);
        assert_eq!(
            block_on(read_registration(
                &r.set,
                &G,
                &DEV,
                at.position,
                r.precommit.void_root()
            ))
            .unwrap(),
            Registration::Unresolved,
            "an open position"
        );
        block_on(install_fulfillment(&r.set, &request(&r))).unwrap();
        assert_eq!(
            block_on(read_registration(
                &r.set,
                &G,
                &DEV,
                at.position,
                r.precommit.void_root()
            ))
            .unwrap(),
            Registration::Registered(Signed {
                body: r.fulfillment.clone(),
                signature: r.f_sig.clone(),
            })
        );
        // Exactly the two values, one per cell, at every member: no
        // registration record exists to be read.
        for reads in [
            fake_registers::get_cells(&r.set, ful_ns(), &at.k_ful),
            fake_registers::get_cells(&r.set, economic_root_namespace(), &at.k_root),
        ] {
            assert!(reads.iter().all(|m| m.as_ref().map(|v| v.len()) == Some(1)));
        }
    }

    /// `LeaderHeld` is not `Final`: the pair at the leader and one copy is
    /// not a registration, and becomes one once two other members hold it.
    #[test]
    #[serial]
    fn held_at_the_leader_but_not_copied_is_not_registered() {
        let r = rig(true);
        let at = position_of(&r.precommit, &r.fulfillment);
        let leader = leader_index(&r.set, &at.seed).unwrap();
        let others: Vec<String> = r
            .set
            .members()
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != leader)
            .map(|(_, m)| m.member_id.clone())
            .collect();
        for m in &others[..3] {
            fake_registers::fail_member(m, true);
        }
        let installed = block_on(install_fulfillment(&r.set, &request(&r))).unwrap();
        assert_eq!(installed.copies, 1);
        let read = || {
            block_on(read_registration(
                &r.set,
                &G,
                &DEV,
                at.position,
                r.precommit.void_root(),
            ))
            .unwrap()
        };
        assert_eq!(read(), Registration::Unresolved, "one copy is not final");
        for m in &others[..3] {
            fake_registers::fail_member(m, false);
        }
        // Anyone may carry the same bytes to the members not reached — one
        // half at a time here, so that each cell's finality is isolated.
        let (f_bytes, c_bytes) = pair_bytes(&r);
        let carry_to: Vec<usize> = r
            .set
            .members()
            .iter()
            .enumerate()
            .filter(|(_, m)| others[..2].contains(&m.member_id))
            .map(|(i, _)| i)
            .collect();
        for i in &carry_to {
            fake_registers::put_cell_to_member(
                &r.set,
                *i,
                economic_root_namespace(),
                &at.k_root,
                &c_bytes,
            )
            .unwrap();
        }
        assert_eq!(
            read(),
            Registration::Unresolved,
            "K_root(q) final beside a merely leader-held F is not a registration"
        );
        for i in &carry_to {
            fake_registers::put_cell_to_member(&r.set, *i, ful_ns(), &at.k_ful, &f_bytes).unwrap();
        }
        assert_eq!(
            read(),
            Registration::Registered(Signed {
                body: r.fulfillment.clone(),
                signature: r.f_sig.clone(),
            }),
            "leader plus two copies at both cells"
        );
    }

    /// PairMutualExclusion: a claim that reached the leader of `K_root(q)`
    /// first — here another fulfillment's `C_q'`, standing for any ordinary
    /// transition at `q` — settles that this `F` is never registered, even
    /// though `F` itself is final at `K_ful(q)`.
    #[test]
    #[serial]
    fn a_claim_first_at_the_root_cell_settles_that_the_fulfillment_never_registers() {
        let r = rig(true);
        let at = position_of(&r.precommit, &r.fulfillment);
        let leader = leader_index(&r.set, &at.seed).unwrap();
        let rival_f = TraderFulfillmentBody::new(
            *r.fulfillment.precommit_id(),
            r.fulfillment.policy_fulfillment_set().to_vec(),
            r.fulfillment
                .attempts()
                .iter()
                .map(|a| dsm::sofi::wire::AttemptEntry {
                    vault_id: a.vault_id,
                    attempt: a.attempt + 1,
                })
                .collect(),
            r.fulfillment.position(),
            ALG,
            &keys().0,
        )
        .unwrap();
        let rival_claim = derive::resolution_claim(&r.precommit, &rival_f).encode();
        fake_registers::put_cell(
            &r.set,
            leader,
            economic_root_namespace(),
            &at.k_root,
            &rival_claim,
        );
        block_on(install_fulfillment(&r.set, &request(&r))).unwrap();
        assert_eq!(
            block_on(read_registration(
                &r.set,
                &G,
                &DEV,
                at.position,
                r.precommit.void_root()
            ))
            .unwrap(),
            Registration::NeverRegistered {
                fulfillment: Signed {
                    body: r.fulfillment.clone(),
                    signature: r.f_sig.clone(),
                },
                settled_at: dsm::sofi::registration::PositionCell::Root,
            }
        );
    }

    /// Bytes that are not an object naming `K_ful(q)` — garbage, and a
    /// well-formed fulfillment of a precommit nobody published — are nothing
    /// at the cell, however early they arrived at the leader: the trader's
    /// own `F` is the leader's first RECOGNIZED object and registers.
    #[test]
    #[serial]
    fn a_fulfillment_that_names_no_published_precommit_is_nothing_at_the_key() {
        let r = rig(true);
        let at = position_of(&r.precommit, &r.fulfillment);
        let leader = leader_index(&r.set, &at.seed).unwrap();
        fake_registers::put_cell(&r.set, leader, ful_ns(), &at.k_ful, b"not an envelope");
        let orphan = TraderFulfillmentBody::new(
            d(0x0F),
            r.fulfillment.policy_fulfillment_set().to_vec(),
            r.fulfillment.attempts().to_vec(),
            r.fulfillment.position(),
            ALG,
            &keys().0,
        )
        .unwrap();
        let orphan_bytes = Publication::Fulfillment {
            body: &orphan,
            signature: &sign(&derive::fulfillment_signing_digest(&orphan)),
        }
        .object_bytes()
        .unwrap();
        fake_registers::put_cell(&r.set, leader, ful_ns(), &at.k_ful, &orphan_bytes);
        block_on(install_fulfillment(&r.set, &request(&r))).unwrap();
        assert_eq!(
            block_on(read_registration(
                &r.set,
                &G,
                &DEV,
                at.position,
                r.precommit.void_root()
            ))
            .unwrap(),
            Registration::Registered(Signed {
                body: r.fulfillment.clone(),
                signature: r.f_sig.clone(),
            })
        );
    }
}
