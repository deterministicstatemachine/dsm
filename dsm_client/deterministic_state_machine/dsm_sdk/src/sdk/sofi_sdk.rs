// SPDX-License-Identifier: MIT OR Apache-2.0

//! SoFi v8 producers: setup, vault creation, trade, route and close.
//!
//! Each one assembles canonical objects and hands back the operation plus the
//! exact digest the caller must sign. No key material enters this module: a
//! builder that signed would be a second place where the signing digest is
//! decided, and the whole point of `m_P` / `m_F` is that there is one.
//!
//! ## What a producer refuses
//!
//! Everything `sofi::admission` refuses — routes beyond the beta hop cap, and
//! the reserved DSM-succession authority — because a producer that can build
//! what admission will not execute is a way to strand a trader's operation
//! (R16-6, R18-1). The objects stay canonical either way; what changes is that
//! nothing here emits one.
//!
//! Dark: nothing calls these yet.

use dsm::sofi::admission::{admissible, NotAdmissible};
use dsm::sofi::derive;
use dsm::sofi::wire::{
    OwnerAuthority, ParentClaimRef, PreEClosureIndex, PrecommitLeg, SettlementBody,
    SettlementPreimage, SofiSetupBody, SofiWireError, SwapHop, TraderCore, TraderFulfillmentBody,
    TraderPrecommitBody, VaultCreation, VaultGenesisPreimage,
};
use dsm::types::operations::Operation;

type D32 = [u8; 32];

/// Why an operation could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The objects do not have canonical bytes in this shape.
    Wire(SofiWireError),
    /// Beta will not execute this, so nothing here will build it.
    NotAdmissible(NotAdmissible),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "{e}"),
            Self::NotAdmissible(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<SofiWireError> for BuildError {
    fn from(e: SofiWireError) -> Self {
        Self::Wire(e)
    }
}

/// A produced operation: the transition, what must be published for anyone to
/// verify it, and the digest the caller signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Produced {
    /// The operation, with an EMPTY signature. The caller signs
    /// [`Self::signing_digest`] and calls `Operation::with_signature`.
    pub operation: Operation,
    /// Content-addressed objects a verifier needs and cannot derive: the
    /// precommit and the settlement preimage for a fulfillment, nothing for a
    /// setup or a creation.
    pub publish: Vec<Vec<u8>>,
    /// The protocol digest this operation's signature covers.
    pub signing_digest: D32,
}

/// The relationship setup (F1). Non-economic: it establishes the right to
/// trade with one vault, and moves nothing.
pub fn build_setup(body: &SofiSetupBody) -> Result<Produced, BuildError> {
    Ok(Produced {
        operation: Operation::SofiSetup {
            setup_body: body.encode(),
            signature: Vec::new(),
        },
        publish: Vec::new(),
        signing_digest: derive::setup_signing_digest(body),
    })
}

/// The owner's vault creation at `p_create` (P15-12).
///
/// `vault_id` is recomputed from the preimage rather than accepted from the
/// caller, so a creation cannot name a vault its own identity does not derive.
pub fn build_vault_create(
    preimage: &VaultGenesisPreimage,
    amount_a: u64,
    amount_b: u64,
) -> Result<Produced, BuildError> {
    let vault_id = preimage.vault_id();
    let genesis_root = dsm::sofi::lineage::genesis_root(&vault_id, &preimage.state)?;
    let creation = VaultCreation {
        vault_id,
        genesis_root,
        amount_a,
        amount_b,
    };
    let genesis_bytes = preimage.encode()?;
    let creation_bytes = creation.encode();
    // The operation's own bytes are what the owner signs, so the digest is
    // over exactly what the transition commits.
    let signing_digest =
        *blake3::hash(&[genesis_bytes.clone(), creation_bytes.clone()].concat()).as_bytes();
    Ok(Produced {
        operation: Operation::SofiVaultCreate {
            genesis_preimage: genesis_bytes,
            creation: creation_bytes,
            signature: Vec::new(),
        },
        publish: Vec::new(),
        signing_digest,
    })
}

/// Everything a fulfillment needs that is not the settlement itself.
#[derive(Debug, Clone)]
pub struct TraderContext<'a> {
    pub genesis: D32,
    pub device_id: D32,
    /// The trader's position `p`; the fulfillment lands at `p + 1`.
    pub position: u64,
    pub parent_claim: ParentClaimRef,
    pub storage_set_id: D32,
    pub signature_alg: u16,
    pub claimant_public_key: &'a [u8],
    /// `T°`, already built against the trader's own pre-root.
    pub trader_core: TraderCore,
    /// The attempt index chosen for each vault, at exercise time.
    pub attempts: Vec<(D32, u64)>,
}

/// The one path every exercise takes: assemble `P(E)`, derive `E`, build `P`,
/// then `F`. A trade, a route and a close differ only in the settlement body
/// handed in — which is exactly the claim the operation surface makes.
fn build_fulfillment(
    settlement: SettlementBody,
    ctx: &TraderContext<'_>,
    cores: Vec<dsm::sofi::wire::DlvCore>,
    legs: Vec<PrecommitLeg>,
    realize_root: D32,
    void_root: D32,
) -> Result<Produced, BuildError> {
    // Refused here, before anything is assembled: a producer that builds what
    // admission will not run strands the trader's operation.
    admissible(&settlement).map_err(BuildError::NotAdmissible)?;

    let preimage = SettlementPreimage::new(settlement, ctx.trader_core.clone(), cores)?;
    let e = derive::recompute_e(&preimage)?;
    let precommit = TraderPrecommitBody::new(
        ctx.genesis,
        ctx.device_id,
        ctx.position,
        ctx.parent_claim,
        e,
        legs,
        realize_root,
        void_root,
        ctx.storage_set_id,
        ctx.signature_alg,
        ctx.claimant_public_key,
    )?;
    let precommit_id = derive::precommit_id(&precommit);

    // The policy-fulfillment set is DERIVED from P and the shadows E commits,
    // so a producer cannot choose it: a complete set is the only admissible
    // one, and there is no half-fulfillment.
    let shadow_cores: Vec<D32> = preimage
        .dlv_cores()
        .iter()
        .map(|core| core.encode().map(|b| derive::dlv_core_digest(&b)))
        .collect::<Result<_, _>>()?;
    let mut policy_set: Vec<D32> =
        dsm::sofi::conformance::derive_policy_fulfillments(&precommit, &shadow_cores)
            .map_err(|_| SofiWireError::Cardinality {
                field: "policy fulfillment set",
                min: 1,
                max: usize::MAX,
                got: shadow_cores.len(),
            })?
            .iter()
            .map(derive::policy_fulfillment_id)
            .collect();
    policy_set.sort();

    let mut attempts: Vec<dsm::sofi::wire::AttemptEntry> = ctx
        .attempts
        .iter()
        .map(|(vault_id, attempt)| dsm::sofi::wire::AttemptEntry {
            vault_id: *vault_id,
            attempt: *attempt,
        })
        .collect();
    attempts.sort_by_key(|a| a.vault_id);
    let fulfillment = TraderFulfillmentBody::new(
        precommit_id,
        policy_set,
        attempts,
        dsm::sofi::wire::next_position(ctx.position)?,
        ctx.signature_alg,
        ctx.claimant_public_key,
    )?;

    Ok(Produced {
        operation: Operation::SofiFulfill {
            fulfillment_body: fulfillment.encode(),
            precommit_id: precommit_id.to_vec(),
            signature: Vec::new(),
        },
        // A verifier needs P and P(E); it derives everything else.
        publish: vec![precommit.encode(), preimage.encode()?],
        signing_digest: derive::fulfillment_signing_digest(&fulfillment),
    })
}

/// A single-vault trade.
pub fn build_trade(
    hop: SwapHop,
    core: dsm::sofi::wire::DlvCore,
    ctx: &TraderContext<'_>,
    realize_root: D32,
    void_root: D32,
) -> Result<Produced, BuildError> {
    build_route(vec![hop], vec![core], ctx, realize_root, void_root)
}

/// A route over one or more vaults. Beta executes at most two hops, and this
/// refuses to build a third rather than leaving the trader holding an
/// operation nothing will run.
pub fn build_route(
    hops: Vec<SwapHop>,
    cores: Vec<dsm::sofi::wire::DlvCore>,
    ctx: &TraderContext<'_>,
    realize_root: D32,
    void_root: D32,
) -> Result<Produced, BuildError> {
    let (first, last) = match (hops.first(), hops.last()) {
        (Some(f), Some(l)) => (*f, *l),
        _ => {
            return Err(BuildError::Wire(SofiWireError::Cardinality {
                field: "swap hops",
                min: 1,
                max: usize::MAX,
                got: 0,
            }))
        }
    };
    let mut sorted_cores = cores;
    sorted_cores.sort_by_key(|c| *c.vault_id());
    let core_digests: Vec<D32> = sorted_cores
        .iter()
        .map(|c| c.encode().map(|b| derive::dlv_core_digest(&b)))
        .collect::<Result<_, _>>()?;
    let mut legs: Vec<PrecommitLeg> = hops
        .iter()
        .map(|h| PrecommitLeg {
            vault_id: h.vault_id,
            parent_root: h.parent_root,
            setup_ref: h.setup_ref,
        })
        .collect();
    legs.sort_by_key(|l| l.vault_id);
    let settlement = SettlementBody::Swap {
        token_in: first.token_in,
        amount_in: first.amount_in,
        token_out: last.token_out,
        exact_out: last.amount_out,
        hops,
        trader_core: derive::trader_core_digest(&ctx.trader_core.encode()?),
        dlv_cores: core_digests,
        closure: PreEClosureIndex::new(Vec::new())?,
    };
    build_fulfillment(settlement, ctx, sorted_cores, legs, realize_root, void_root)
}

/// A full close of one vault by its origin owner.
///
/// The authority is not a parameter: `OriginOwner` is the only branch this
/// protocol activates, and a producer that took the reserved branch as an
/// argument would be a way to build what nothing executes (R18-1).
#[allow(clippy::too_many_arguments)]
pub fn build_close(
    vault_id: D32,
    parent_root: D32,
    setup_ref: D32,
    reserve_a: u64,
    reserve_b: u64,
    core: dsm::sofi::wire::DlvCore,
    ctx: &TraderContext<'_>,
    realize_root: D32,
    void_root: D32,
) -> Result<Produced, BuildError> {
    let settlement = SettlementBody::Close {
        vault_id,
        parent_root,
        setup_ref,
        owner_authority: OwnerAuthority::Origin,
        reserve_a,
        reserve_b,
        trader_core: derive::trader_core_digest(&ctx.trader_core.encode()?),
        dlv_core: derive::dlv_core_digest(&core.encode()?),
        closure: PreEClosureIndex::new(Vec::new())?,
    };
    build_fulfillment(
        settlement,
        ctx,
        vec![core],
        vec![PrecommitLeg {
            vault_id,
            parent_root,
            setup_ref,
        }],
        realize_root,
        void_root,
    )
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use dsm::economic::tree::{EconomicSmt, ECONOMIC_SMT_HEIGHT};
    use dsm::sofi::wire::{CoreEntry, DlvCore, VaultStateLeaf, VAULT_STATUS_ACTIVE};

    const G: D32 = [0x11; 32];
    const DEV: D32 = [0x22; 32];
    const P_POS: u64 = 5;
    const ALG: u16 = 0x0001;

    fn d(byte: u8) -> D32 {
        [byte; 32]
    }

    fn entry(key: D32) -> CoreEntry {
        CoreEntry::Mutation {
            key,
            pre: d(0x41),
            post: d(0x42),
            path: vec![[0u8; 32]; ECONOMIC_SMT_HEIGHT],
        }
    }

    fn trader_core() -> TraderCore {
        TraderCore::new(G, DEV, P_POS + 1, d(0x61), vec![entry(d(0x71))]).unwrap()
    }

    fn dlv_core(vault: u8) -> DlvCore {
        DlvCore::new(d(vault), d(0x62), G, DEV, d(0x63), vec![entry(d(0x72))]).unwrap()
    }

    fn hop(vault: u8) -> SwapHop {
        SwapHop {
            vault_id: d(vault),
            parent_root: d(0x62),
            setup_ref: d(0x55),
            token_in: d(0x40),
            amount_in: 100,
            token_out: d(0x41),
            amount_out: 90,
        }
    }

    fn ctx(attempts: Vec<(D32, u64)>) -> TraderContext<'static> {
        TraderContext {
            genesis: G,
            device_id: DEV,
            position: P_POS,
            parent_claim: ParentClaimRef::SingleRoot { claim_ref: d(0x66) },
            storage_set_id: d(0x77),
            signature_alg: ALG,
            claimant_public_key: &[0x01; 64],
            trader_core: trader_core(),
            attempts,
        }
    }

    /// A producer hands back an UNSIGNED operation and the exact digest to
    /// sign. It never holds a key, so there is one place the signing digest is
    /// decided and it is the protocol's.
    #[test]
    fn a_trade_produces_an_unsigned_operation_and_its_protocol_digest() {
        let produced = build_trade(
            hop(0xC1),
            dlv_core(0xC1),
            &ctx(vec![(d(0xC1), 0)]),
            d(0xA1),
            d(0x61),
        )
        .unwrap();
        assert!(
            produced.operation.get_signature().is_none(),
            "a producer does not sign"
        );
        let signed = produced.operation.with_signature(vec![0xAB; 8]);
        assert_eq!(signed.get_signature(), Some(vec![0xAB; 8]));
        // P and P(E) are published; everything else a verifier derives.
        assert_eq!(produced.publish.len(), 2);
        assert_ne!(produced.signing_digest, [0u8; 32]);
    }

    /// The same path builds a close, and the operation is the same VARIANT —
    /// which branch it is lives in `B°`, not in the operation's name.
    #[test]
    fn a_close_is_the_same_operation_variant_as_a_trade() {
        let close = build_close(
            d(0xC1),
            d(0x62),
            d(0x55),
            1_000,
            2_000,
            dlv_core(0xC1),
            &ctx(vec![(d(0xC1), 0)]),
            d(0xA1),
            d(0x61),
        )
        .unwrap();
        assert!(matches!(close.operation, Operation::SofiFulfill { .. }));
        let trade = build_trade(
            hop(0xC1),
            dlv_core(0xC1),
            &ctx(vec![(d(0xC1), 0)]),
            d(0xA1),
            d(0x61),
        )
        .unwrap();
        assert!(matches!(trade.operation, Operation::SofiFulfill { .. }));
        // Same variant, different commitments: the branch is in the bytes.
        assert_ne!(close.signing_digest, trade.signing_digest);
    }

    /// A producer refuses what beta will not execute, rather than leaving the
    /// trader holding an operation nothing runs.
    #[test]
    fn a_producer_refuses_a_route_beta_will_not_execute() {
        let hops = vec![hop(0xC1), hop(0xC2), hop(0xC3)];
        let cores = vec![dlv_core(0xC1), dlv_core(0xC2), dlv_core(0xC3)];
        let attempts = vec![(d(0xC1), 0), (d(0xC2), 0), (d(0xC3), 0)];
        let refused = build_route(hops, cores, &ctx(attempts), d(0xA1), d(0x61));
        assert!(
            matches!(
                refused,
                Err(BuildError::NotAdmissible(NotAdmissible::TooManyLegs {
                    legs: 3,
                    max: 2
                }))
            ),
            "got {refused:?}"
        );
    }

    /// Two hops — the beta cap — still build.
    #[test]
    fn a_two_hop_route_builds() {
        let hops = vec![hop(0xC1), hop(0xC2)];
        let cores = vec![dlv_core(0xC1), dlv_core(0xC2)];
        let attempts = vec![(d(0xC1), 0), (d(0xC2), 0)];
        let produced = build_route(hops, cores, &ctx(attempts), d(0xA1), d(0x61)).unwrap();
        assert!(matches!(produced.operation, Operation::SofiFulfill { .. }));
    }

    /// R18-1: no producer emits the reserved authority. It is not a parameter,
    /// so there is nothing to pass — the type system is the refusal.
    #[test]
    fn no_producer_can_emit_the_reserved_owner_authority() {
        let produced = build_close(
            d(0xC1),
            d(0x62),
            d(0x55),
            1_000,
            2_000,
            dlv_core(0xC1),
            &ctx(vec![(d(0xC1), 0)]),
            d(0xA1),
            d(0x61),
        )
        .unwrap();
        // Decode what the producer actually built and check the branch.
        let preimage = SettlementPreimage::decode(&produced.publish[1]).unwrap();
        match preimage.settlement() {
            SettlementBody::Close {
                owner_authority, ..
            } => {
                assert_eq!(*owner_authority, OwnerAuthority::Origin);
                assert!(owner_authority.is_activated());
            }
            _ => panic!("a close"),
        }
    }

    /// A setup and a creation are their own operations, and a creation's vault
    /// id is RECOMPUTED from the preimage rather than taken from the caller.
    #[test]
    fn setup_and_creation_produce_their_own_operations() {
        let setup =
            SofiSetupBody::new(G, DEV, P_POS, d(0xC1), d(0x66), d(0x67), ALG, &[0x01; 64]).unwrap();
        let produced = build_setup(&setup).unwrap();
        assert!(matches!(produced.operation, Operation::SofiSetup { .. }));
        assert_eq!(
            produced.signing_digest,
            derive::setup_signing_digest(&setup)
        );

        let state = VaultStateLeaf {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: P_POS,
            market_policy: d(0x31),
            fee_policy: d(0x32),
            release_policy: d(0x33),
            storage_set_id: d(0x77),
            generation: 0,
            reserve_a: 1_000,
            reserve_b: 2_000,
            status: VAULT_STATUS_ACTIVE,
        };
        let preimage = VaultGenesisPreimage {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: P_POS,
            state: state.clone(),
        };
        let created = build_vault_create(&preimage, 1_000, 2_000).unwrap();
        let Operation::SofiVaultCreate { creation, .. } = &created.operation else {
            panic!("a creation")
        };
        let decoded = VaultCreation::decode(creation).unwrap();
        assert_eq!(decoded.vault_id, preimage.vault_id());
        // And R_0 is the tree holding exactly the state leaf.
        let mut tree = EconomicSmt::new();
        tree.insert(
            derive::vault_state_key(&preimage.vault_id()),
            derive::vault_state_leaf_value(&state).unwrap(),
        );
        assert_eq!(decoded.genesis_root, tree.root());
    }
}
