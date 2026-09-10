// SPDX-License-Identifier: Apache-2.0

//! IS THIS DLV PARENT STILL AVAILABLE TO A COMPETING CANDIDATE?
//!
//! This module answers OCCUPANCY and nothing else. Whether a bound bundle's
//! successor actually became economic state is a separate question with a
//! successor-kind-specific answer, and the frontier walk asks it separately.
//! Conflating the two is the defect the whole 5c-1 cut exists to remove: under
//! a write-once settlement slot, "this generation is consumed" and "this
//! generation composed" were one fact, and they are not.
//!
//! Two layers, deliberately separated:
//!
//! - [`observe_parent_key`] reads the register. One key, `q` counted answers,
//!   five possible verdicts. No bundle is fetched, because occupancy does not
//!   depend on the bundle's contents.
//! - [`observe_parent_binding`] resolves the bound bundle and checks it against
//!   THIS parent. That check is load-bearing rather than defensive: the binding
//!   register is application-blind (§22 #12), so a proposer may bind a bundle
//!   that does not contain this `c_n` at this key, and a member reconfigured
//!   into another set keeps serving rows written under the old one.
//!
//! `k_v = H(DSM/binding-keyset ‖ c_n)` is derived from `c_n` ALONE, and `c_n`
//! already commits the vault id, the generation, the reserves and the pair. So
//! the three coordinate checks the old slot walk performed separately —
//! "names a different cell", "a different storage set", "a different parent
//! state" — mostly collapse into *we read the right key*, and the ones that
//! remain are the ones an application-blind register cannot enforce.
//!
//! **Nothing here returns a `Result`.** A transport failure IS
//! `Unavailable`; a bundle that cannot be resolved IS `Unresolvable`. An error
//! channel beside the verdict is an invitation to collapse uncertainty into
//! "the parent is free", which is the one reading that is never safe.

use dsm::dlv::successor_validity::{OutcomeClass, Reason};
use dsm::dlv::binding_observation::{
    observe_single_key_with_read, BindingObservation, CanonicalQuorum, ChosenBinding, KeyRead,
};
use dsm::dlv::settlement_bundle::{self, BundleShape, ConsumedDlvTransition, SettlementBundle};

use crate::sdk::quorum_bind_runner::{binding_transport, read_binding_attributed};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::dlv_lineage_quarantine as quarantine;

/// What the vault's committed set says about the binding of one parent state.
///
/// Occupancy only. `BoundBy` does NOT mean the successor was realized.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ParentOccupancy {
    /// `q` attributed members each explicitly hold nothing at `k(c_n)`: the
    /// parent is available to a competing candidate right now.
    Free,
    /// A binding-final bundle owns this parent, resolved and checked against it.
    BoundBy(Box<BoundParent>),
    /// The parent could not be resolved to a bound bundle, WITH the class of
    /// the fact that stopped it.
    ///
    /// This used to be a bare `String` covering Conflict, Undetermined,
    /// Unavailable and every way a chosen record's bundle fails to resolve —
    /// sixteen sites spanning three genuinely different responses (quarantine,
    /// retry, refuse) reduced to one. All of them fail closed, which is why the
    /// collapse was survivable; none of them mean the same thing, which is why
    /// amendment 2c-C3 requires them apart.
    Unresolvable(OccupancyRefusal),
}

/// Why a parent did not resolve, classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OccupancyRefusal {
    /// The frozen C3 reason, which fixes the class.
    pub reason: Reason,
    /// Human-readable detail. Diagnostics only — never branched on.
    pub detail: String,
}

impl OccupancyRefusal {
    pub(crate) fn new(reason: Reason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// The class this refusal carries.
    pub(crate) fn class(&self) -> OutcomeClass {
        self.reason.class()
    }
}

impl core::fmt::Display for OccupancyRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.detail)
    }
}

/// The bundle that owns a parent, already checked against THAT parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundParent {
    pub bundle: SettlementBundle,
    /// The exact bytes fetched by `value_digest` — `Canon(B)`, re-hashed.
    pub canon: Vec<u8>,
    /// `b` — equal to the record's `value_digest`.
    pub bundle_digest: [u8; 32],
    pub bundle_addr: [u8; 32],
    /// The transition consuming THIS parent. Located by `parent_binding ==
    /// c_n` (2c-A.1 ruling 7), never assumed to be index 0.
    pub transition_ix: usize,
    /// Where that transition's nested successor sits in `canon` — the
    /// supplied operand of `VDS.COMMON.10.a`, never re-encoded.
    pub successor_span: core::ops::Range<usize>,
    pub shape: BundleShape,
}

impl BoundParent {
    pub fn transition(&self) -> Option<&ConsumedDlvTransition> {
        self.bundle.transitions().get(self.transition_ix)
    }

    /// The exact canonical bytes of `V_{n+1}` as the bundle carries them.
    pub fn successor_bytes(&self) -> &[u8] {
        &self.canon[self.successor_span.clone()]
    }
}

/// ── THE HARDWARE-PROOF SURFACE ───────────────────────────────────────────────
///
/// One narrow `pub` entry point for the live rig gate, and nothing more.
///
/// The rig used to reconstruct quorum semantics in shell — tally digests across
/// nodes, compare counts to a hardcoded `QUORUM=2`. That is a SECOND
/// implementation of the decision this protocol turns on, in a language with no
/// type for a `BindingRecord`, and it can drift from Class K silently. So the
/// probe runs the PRODUCTION path — the same attribution rule, the same
/// [`observe_single_key`], the same bundle resolution — and the script asserts
/// its output instead of deriving its own verdict.
///
/// Deliberately narrow: this exposes ONE question about ONE parent. The rest of
/// this module stays `pub(crate)`, because a tooling requirement is not a reason
/// to make composition internals public.
#[derive(Debug, Clone, PartialEq)]
pub struct BindingProbe {
    pub resource_key: [u8; 32],
    pub verdict: &'static str,
    pub tx_id: Option<[u8; 32]>,
    pub value_digest: Option<[u8; 32]>,
    pub value_addr: Option<[u8; 32]>,
    pub round_counter: Option<u64>,
    pub round_proposer: Option<[u8; 32]>,
    pub holders: Option<u32>,
    /// Whether the bound bundle actually names this vault at this parent. Only
    /// meaningful when the verdict is `BOUND_FINAL`; `None` otherwise.
    pub bundle_parent_matches: Option<bool>,
    pub detail: Option<String>,
}

/// Probe one vault parent through the production observer.
pub async fn probe_parent_binding(
    set: &StorageSet,
    vault_id: &[u8; 32],
    generation: u64,
    parent_c_n: &[u8; 32],
    storage_set_id: &[u8; 32],
    committed_quorum: u32,
) -> BindingProbe {
    let resource_key = settlement_bundle::resource_key(parent_c_n);
    // 2c-C3.1 ruling D, effect 5: a quarantined key is reported as such and
    // never resolved to a value — on the probe exactly as on the walk.
    if let Ok(Some(root)) = quarantine::refusing_root(vault_id, generation, parent_c_n) {
        return BindingProbe {
            resource_key,
            verdict: "LINEAGE_QUARANTINED",
            tx_id: None,
            value_digest: None,
            value_addr: None,
            round_counter: None,
            round_proposer: None,
            holders: None,
            bundle_parent_matches: None,
            detail: Some(quarantine::describe_refusal(&root, generation)),
        };
    }
    let observation = observe_parent_key(set, parent_c_n, committed_quorum).await;
    let mut probe = BindingProbe {
        resource_key,
        verdict: match &observation {
            BindingObservation::Free => "FREE",
            BindingObservation::BoundFinal(_) => "BOUND_FINAL",
            BindingObservation::Conflict { .. } => "CONFLICT",
            BindingObservation::Undetermined { .. } => "UNDETERMINED",
            BindingObservation::Unavailable { .. } => "UNAVAILABLE",
        },
        tx_id: None,
        value_digest: None,
        value_addr: None,
        round_counter: None,
        round_proposer: None,
        holders: None,
        bundle_parent_matches: None,
        detail: None,
    };
    if let BindingObservation::BoundFinal(c) = &observation {
        probe.tx_id = Some(c.tx_id);
        probe.value_digest = Some(c.value_digest);
        probe.value_addr = Some(c.value_addr);
        probe.round_counter = Some(c.round.counter);
        probe.round_proposer = Some(c.round.proposer_id);
        probe.holders = Some(c.holders);
        // The same resolution the walk performs: fetch, re-hash, and check the
        // bundle against THIS parent. A chosen value whose bundle names another
        // parent is exactly what an application-blind register permits.
        match observe_parent_binding(
            set,
            vault_id,
            generation,
            parent_c_n,
            storage_set_id,
            committed_quorum,
        )
        .await
        {
            ParentOccupancy::BoundBy(_) => probe.bundle_parent_matches = Some(true),
            ParentOccupancy::Unresolvable(why) => {
                probe.bundle_parent_matches = Some(false);
                probe.detail = Some(why.to_string());
            }
            // Unreachable: the key was BoundFinal a moment ago. Report rather
            // than assert — a race here is information, not a panic.
            ParentOccupancy::Free => {
                probe.bundle_parent_matches = Some(false);
                probe.detail = Some("the key became free between reads".into());
            }
        }
    }
    probe
}

impl BindingProbe {
    /// One `key=value` per line — the shape the rig script asserts against.
    pub fn render(&self, parent_c_n: &[u8; 32]) -> String {
        let b32 = crate::util::text_id::encode_base32_crockford;
        let mut out = String::new();
        out.push_str(&format!("parent_c_n={}\n", b32(parent_c_n)));
        out.push_str(&format!("resource_key={}\n", b32(&self.resource_key)));
        out.push_str(&format!("verdict={}\n", self.verdict));
        if let Some(v) = self.tx_id {
            out.push_str(&format!("tx_id={}\n", b32(&v)));
        }
        if let Some(v) = self.value_digest {
            out.push_str(&format!("value_digest={}\n", b32(&v)));
        }
        if let Some(v) = self.value_addr {
            out.push_str(&format!("value_addr={}\n", b32(&v)));
        }
        if let Some(v) = self.round_counter {
            out.push_str(&format!("round_counter={v}\n"));
        }
        if let Some(v) = self.round_proposer {
            out.push_str(&format!("round_proposer={}\n", b32(&v)));
        }
        if let Some(v) = self.holders {
            out.push_str(&format!("holders={v}\n"));
        }
        if let Some(v) = self.bundle_parent_matches {
            out.push_str(&format!("bundle_parent_matches={v}\n"));
        }
        if let Some(d) = &self.detail {
            out.push_str(&format!("detail={d}\n"));
        }
        out
    }
}

/// Probe EVERY parent this vault's composition consumed, plus its frontier.
///
/// One call, because the c_n values a rig would otherwise have to supply are
/// exactly what the composition already computed — and re-deriving them in a
/// shell or Python harness would mean re-implementing `H_dom(DSM/vault-state,
/// CCB(V_n))` outside the code that defines it.
///
/// This is the whole public surface the hardware proof needs: it composes the
/// vault the way any third party does, then asks the production observer about
/// each parent. `compose_discovered_vault` and `ComposedVaultState` stay
/// `pub(crate)`.
pub async fn probe_vault_bindings(
    vault_id: &[u8; 32],
    token_a: &[u8; 32],
    token_b: &[u8; 32],
    fee_bps: u32,
) -> Result<Vec<(u64, [u8; 32], BindingProbe)>, String> {
    let composed = crate::sdk::vault_state_composition::compose_discovered_vault(
        vault_id, token_a, token_b, fee_bps,
    )
    .await
    .map_err(|e| e.to_string())?;
    let catalog = crate::sdk::storage_set::StorageSetCatalog::from_env_config()
        .map_err(|e| format!("storage catalog: {e}"))?;
    let set = catalog
        .resolve(&composed.storage_set_id)
        .cloned()
        .ok_or_else(|| "the vault's committed storage set does not resolve here".to_string())?;
    let quorum = set.quorum();
    let mut out = Vec::new();
    // Every CONSUMED parent: each must be bound, by a bundle that names it.
    for folded in &composed.folded_parents {
        let probe = probe_parent_binding(
            &set,
            vault_id,
            folded.generation,
            &folded.c_n,
            &composed.storage_set_id,
            quorum,
        )
        .await;
        out.push((folded.generation, folded.c_n, probe));
    }
    // And the FRONTIER, which is normally free — the proof that exclusivity
    // stopped where the composition says it stopped, rather than the walk
    // simply having run out of evidence.
    let probe = probe_parent_binding(
        &set,
        vault_id,
        composed.sequence,
        &composed.c_n,
        &composed.storage_set_id,
        quorum,
    )
    .await;
    out.push((composed.sequence, composed.c_n, probe));
    Ok(out)
}

/// Read an already-derived resource key at every committed member and classify
/// it at `quorum`.
///
/// The key is a parameter rather than a `c_n`, because the core provenance arm
/// derives it from the parent state IT is validating — a resolver that
/// re-derived the key could answer about a different one than the verifier
/// asked about.
pub(crate) async fn observe_key_at_set(
    set: &StorageSet,
    key: &[u8; 32],
    committed_quorum: u32,
) -> BindingObservation {
    observe_key_at_set_with_read(set, key, committed_quorum)
        .await
        .0
}

/// [`observe_key_at_set`], returning the read the verdict came from (2c-C3.1
/// ruling H) so a finality can be recorded with its evidence.
///
/// 2c-C3.1 ruling F: THE OBSERVER REFUSES A NON-CANONICAL QUORUM ITSELF.
/// Composition validates `q` before it reads; this validates it again at the
/// point the read is classified, so no caller can hand the observer a weaker
/// `q` and make `Conflict` reachable. A read at a `q` the observer cannot
/// stand behind establishes nothing.
pub(crate) async fn observe_key_at_set_with_read(
    set: &StorageSet,
    key: &[u8; 32],
    committed_quorum: u32,
) -> (BindingObservation, KeyRead) {
    let quorum = match CanonicalQuorum::of_committed(set.len(), committed_quorum) {
        Ok(q) => q,
        Err(e) => {
            log::warn!("binding read refused at a non-canonical quorum: {e}");
            return (
                BindingObservation::Unavailable {
                    attributed: 0,
                    required: committed_quorum,
                },
                KeyRead {
                    per_member: Vec::new(),
                },
            );
        }
    };
    let members: Vec<dsm::dlv::quorum_bind::CommittedMember> = set
        .members()
        .iter()
        .map(|m| dsm::dlv::quorum_bind::CommittedMember {
            member_id: m.member_id.as_bytes().to_vec(),
            register_incarnation: m.register_incarnation_id,
        })
        .collect();
    let transport = binding_transport(set);
    let reads = read_binding_attributed(&members, &[*key], transport.as_ref()).await;
    observe_single_key_with_read(&reads, quorum)
}

/// Read `k(c_n)` at every committed member and classify it at the vault's
/// committed `q`.
///
/// Every member is asked rather than the first `q`: a bundle that committed
/// with exactly `q` holders needs the full fan-out to find them.
pub(crate) async fn observe_parent_key(
    set: &StorageSet,
    parent_c_n: &[u8; 32],
    committed_quorum: u32,
) -> BindingObservation {
    observe_parent_key_with_read(set, parent_c_n, committed_quorum)
        .await
        .0
}

/// [`observe_parent_key`], with the read the verdict came from.
pub(crate) async fn observe_parent_key_with_read(
    set: &StorageSet,
    parent_c_n: &[u8; 32],
    committed_quorum: u32,
) -> (BindingObservation, KeyRead) {
    observe_key_at_set_with_read(
        set,
        &settlement_bundle::resource_key(parent_c_n),
        committed_quorum,
    )
    .await
}

/// 2c-C3.1 ruling A: record an OBSERVED qualifying finality the moment it is
/// established, before any use is made of it, compared on VALUE against what
/// this verifier recorded earlier at the same key. A contradiction writes the
/// quarantine root with BOTH evidence objects and refuses.
///
/// Returns the refusal to hand back, or `None` when the finality may be used.
#[allow(clippy::too_many_arguments)]
fn establish_observed_finality(
    set: &StorageSet,
    vault_id: &[u8; 32],
    generation: u64,
    parent_c_n: &[u8; 32],
    storage_set_id: &[u8; 32],
    committed_quorum: u32,
    chosen: &ChosenBinding,
    read: KeyRead,
) -> Option<OccupancyRefusal> {
    let b32 = crate::util::text_id::encode_base32_crockford;
    let evidence = quarantine::Evidence::Observed(quarantine::ObservedEvidence {
        quorum: committed_quorum,
        members: set
            .members()
            .iter()
            .map(|m| quarantine::MemberIdentity {
                member_id: m.member_id.as_bytes().to_vec(),
                register_incarnation: m.register_incarnation_id,
            })
            .collect(),
        read,
        chosen: chosen.clone(),
    })
    .encode();
    let finality = quarantine::ObservedFinality {
        vault_id: *vault_id,
        c_n: *parent_c_n,
        generation,
        value: quarantine::FinalityValue::of(chosen),
        round: chosen.round,
        holders: chosen.holders,
        storage_set_id: *storage_set_id,
        quorum: committed_quorum,
        evidence,
    };
    match quarantine::record_finality(&finality) {
        Ok(quarantine::RecordOutcome::Recorded)
        | Ok(quarantine::RecordOutcome::AlreadyRecordedSameValue) => None,
        Ok(quarantine::RecordOutcome::Contradiction { recorded }) => {
            let mut detail = format!(
                "duplicate binding finality at generation {generation}: this verifier recorded \
                 {} chosen at this parent and now observes {} chosen; the lineage is quarantined",
                b32(&recorded.value.tx_id),
                b32(&chosen.tx_id),
            );
            // Ruling C: the root is written BEFORE the refusal is returned. If
            // it cannot be, the refusal stands and the failure is reported —
            // never downgraded, never silently proceeded past.
            if let Err(e) = quarantine::quarantine_root(&quarantine::QuarantineRoot {
                vault_id: *vault_id,
                root_c_n: *parent_c_n,
                root_generation: generation,
                storage_set_id: *storage_set_id,
                quorum: committed_quorum,
                first_evidence: recorded.evidence,
                second_evidence: finality.evidence,
                insertion_ordinal: 0,
            }) {
                detail.push_str(&format!(
                    "; the quarantine root could NOT be durably written ({e}), so this refusal \
                     stands without its memory until a later observation writes it"
                ));
            }
            Some(OccupancyRefusal::new(
                Reason::DuplicateBindingFinality,
                detail,
            ))
        }
        // A finality that could not be recorded may not be used (ruling A):
        // a local resource failure, so INCOMPLETE, and retryable.
        Err(e) => Some(OccupancyRefusal::new(
            Reason::BindingEvidenceUnavailable,
            format!("could not durably record the binding finality: {e}"),
        )),
    }
}

/// Occupancy of one vault parent, with the owning bundle resolved and bound to
/// that parent.
pub(crate) async fn observe_parent_binding(
    set: &StorageSet,
    vault_id: &[u8; 32],
    generation: u64,
    parent_c_n: &[u8; 32],
    storage_set_id: &[u8; 32],
    committed_quorum: u32,
) -> ParentOccupancy {
    // 2c-C3.1 ruling D, effect 5: a quarantined lineage is NEVER resolved to a
    // value — not by the walk, not by the probe. The durable root is consulted
    // BEFORE the register is read, because the register may now say anything
    // about this key; the root is the fact.
    match quarantine::refusing_root(vault_id, generation, parent_c_n) {
        Ok(None) => {}
        Ok(Some(root)) => {
            return ParentOccupancy::Unresolvable(OccupancyRefusal::new(
                Reason::LineageQuarantined,
                quarantine::describe_refusal(&root, generation),
            ))
        }
        Err(e) => {
            return ParentOccupancy::Unresolvable(OccupancyRefusal::new(
                Reason::BindingEvidenceUnavailable,
                format!("the lineage quarantine table is unreadable: {e}"),
            ))
        }
    }
    let (observation, read) = observe_parent_key_with_read(set, parent_c_n, committed_quorum).await;
    let chosen = match observation {
        BindingObservation::Free => return ParentOccupancy::Free,
        BindingObservation::BoundFinal(c) => {
            if let Some(refusal) = establish_observed_finality(
                set,
                vault_id,
                generation,
                parent_c_n,
                storage_set_id,
                committed_quorum,
                &c,
                read,
            ) {
                return ParentOccupancy::Unresolvable(refusal);
            }
            c
        }
        // A promise in flight, or an accepted record below THIS reader's
        // quorum. Retryable, and never "free": a value already chosen behind a
        // down member lands here, because two quorums intersect but one read
        // need not see the intersection.
        BindingObservation::Undetermined { attributed, .. } => {
            return ParentOccupancy::Unresolvable(OccupancyRefusal::new(
                Reason::BindingUndetermined,
                format!(
                    "the binding for this parent is not yet decided ({attributed} members answered)"
                ),
            ))
        }
        // Req 6.3. Two chosen values at one write-once key is a proven
        // contradiction in the substrate, not a failed check — SAFETY_VIOLATION,
        // never resolved by iteration order and never tie-broken. Unreachable
        // at the canonical quorum the observer insists on (`CanonicalQuorum`);
        // retained as the refusal it always was. The trigger that IS reachable
        // is the temporal one above.
        BindingObservation::Conflict { chosen, .. } => {
            return ParentOccupancy::Unresolvable(OccupancyRefusal::new(
                Reason::DuplicateBindingFinality,
                format!(
                    "the binding key for this parent holds {} chosen values",
                    chosen.len()
                ),
            ))
        }
        BindingObservation::Unavailable {
            attributed,
            required,
        } => {
            return ParentOccupancy::Unresolvable(OccupancyRefusal::new(
                Reason::BindingEvidenceUnavailable,
                format!(
                    "only {attributed} of the vault's members answered the binding key \
                     ({required} required)"
                ),
            ))
        }
    };

    // Each site now names the class of the fact it observed. The INVALID ones
    // are decidable from bytes already in hand; the INCOMPLETE ones are the two
    // fetch outcomes, where nothing was learned at all.
    let unresolvable = |reason: Reason, what: &str| {
        ParentOccupancy::Unresolvable(OccupancyRefusal::new(reason, what))
    };

    // The record's two identity fields must agree with each other before either
    // is used to fetch anything.
    let expected_addr = dsm::storage_object::immutable_addr_from_inner(
        dsm::common::domain_tags::TAG_DSM_SETTLEMENT_BUNDLE,
        &chosen.value_digest,
    );
    if expected_addr != chosen.value_addr {
        return unresolvable(
            Reason::BundleNotCanonical,
            "the bound record's digest and address disagree",
        );
    }

    // Fetch by the record's own value identity. `fetch_immutable_payload`
    // re-hashes the bytes to the requested inner identity (Req 15.3).
    let bytes = match crate::sdk::storage_io::fetch_immutable_payload(
        dsm::common::domain_tags::TAG_DSM_SETTLEMENT_BUNDLE,
        &chosen.value_digest,
    )
    .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            return unresolvable(
                Reason::BindingEvidenceUnavailable,
                "its bound bundle is not retrievable",
            )
        }
        Err(_) => {
            return unresolvable(
                Reason::BindingEvidenceUnavailable,
                "its bound bundle could not be fetched",
            )
        }
    };
    // Strict decode and the whole-bundle round trip under the frozen encoder
    // (2c-A.1 ruling 8): a non-canonical nested successor is refused here,
    // before any verifier reads it. The identity is over exactly the bytes
    // that were fetched.
    let decoded = match settlement_bundle::decode_canonical(&bytes) {
        Ok(d) => d,
        Err(e) => {
            return unresolvable(
                Reason::BundleNotCanonical,
                &format!("its bound bundle is not canonical: {e}"),
            )
        }
    };
    let bundle_digest = settlement_bundle::bundle_digest(&bytes);
    let bundle_addr = settlement_bundle::bundle_addr(&bytes);
    if bundle_digest != chosen.value_digest || bundle_addr != chosen.value_addr {
        return unresolvable(
            Reason::BundleNotCanonical,
            "its bound bundle does not hash to the record's identity",
        );
    }
    let bundle = decoded.bundle;
    let shape = settlement_bundle::shape(&bundle);

    // 2c-B's `G1`-`G4`, HERE, on the consuming side. 2c-C4 §2.1 says these gate
    // the bundle's structural validity so that "a bundle whose carried evidence
    // disagrees with itself is refused before any verifier reads it" — and this
    // is where a FOREIGN bundle first becomes readable: fetched from the
    // register, canonically decoded, hashed to the record's identity.
    //
    // The producer checks its own output, which is worth having and is not this.
    // A producer that means harm simply does not check, so a self-check gates
    // nothing on the consuming side; only this does. The conjuncts refuse a
    // preimage that does not decode, does not re-encode identically, is not a
    // Unilateral settle, carries a short field, or names a successor that is
    // not the tip of its own carried inputs.
    if let Some(terms) = bundle.market_terms() {
        if let Err(e) = dsm::dlv::market_evidence::check_market_evidence(terms) {
            return unresolvable(
                Reason::BundleNotCanonical,
                &format!("its bound bundle's successor evidence disagrees with itself: {e}"),
            );
        }
    }

    // The bundle carries no storage set and no quorum (registry §5.19):
    // binding authority is `V_n`'s own fields 14 and 15 — the set this key
    // was just read at, at its canonical quorum.
    //
    // AND IT NAMES THIS PARENT. The register never inspects the value it holds,
    // so a proposer can bind a bundle at k(c_n) whose transition names some
    // other c_n. The transition is located by `parent_binding == c_n` (2c-A.1
    // ruling 7); its successor must be THIS vault's next generation.
    let Some(transition_ix) = bundle
        .transitions()
        .iter()
        .position(|t| t.parent_binding == *parent_c_n)
    else {
        return unresolvable(
            Reason::StaleParent,
            "its bound bundle names a different parent state",
        );
    };
    let Some(t) = bundle.transitions().get(transition_ix) else {
        return unresolvable(
            Reason::BundleNotCanonical,
            "its bound bundle lost the transition it just named",
        );
    };
    if t.successor.vault_id != *vault_id {
        // VDS.COMMON.1.a — the successor is some other vault's state.
        return unresolvable(
            Reason::VaultMismatch,
            "its bound bundle consumes no leg of this vault",
        );
    }
    if t.successor.generation != generation.saturating_add(1) {
        return unresolvable(
            Reason::GenerationMismatch,
            "its bound bundle's successor is not this parent's next generation",
        );
    }
    let Some(successor_span) = decoded.successor_spans.get(transition_ix).cloned() else {
        return unresolvable(
            Reason::BundleNotCanonical,
            "its bound bundle lost the successor span it just decoded",
        );
    };
    // `storage_set_id` is the walk's, not the bundle's; it is no longer
    // compared against anything the bundle carries.
    let _ = storage_set_id;

    ParentOccupancy::BoundBy(Box::new(BoundParent {
        bundle,
        canon: bytes,
        bundle_digest,
        bundle_addr,
        transition_ix,
        successor_span,
        shape,
    }))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::sdk::binding_fleet_double;
    use crate::sdk::settlement_bind::bind_settlement;
    use crate::sdk::storage_set::{StorageMember, StorageSet};
    use dsm::dlv::quorum_bind::Outcome;
    use dsm::storage::binding_record::Round;
    use serial_test::serial;

    const VAULT: [u8; 32] = [0x77; 32];
    const C_N: [u8; 32] = [0xC0; 32];
    const GEN: u64 = 3;

    fn test_set(n: u8) -> StorageSet {
        StorageSet::new(
            (0..n)
                .map(|i| StorageMember {
                    member_id: format!("dsm-node-{i}"),
                    register_incarnation_id: [i + 1; 32],
                    endpoint: format!("http://127.0.0.1:808{i}"),
                })
                .collect(),
        )
        .unwrap()
    }

    fn fleet_tuples(set: &StorageSet) -> Vec<(String, Vec<u8>, [u8; 32])> {
        set.members()
            .iter()
            .map(|m| {
                (
                    m.endpoint.clone(),
                    m.member_id.as_bytes().to_vec(),
                    m.register_incarnation_id,
                )
            })
            .collect()
    }

    /// A canonical market bundle consuming `vault` at `c_n` into its next
    /// generation.
    fn market_bundle(vault: [u8; 32], c_n: [u8; 32]) -> SettlementBundle {
        dsm::ccb::settlement::fixtures::market_bundle(
            c_n,
            dsm::ccb::settlement::fixtures::successor_of(c_n, vault, GEN + 1, 1, 1),
            [0x0C; 32],
        )
    }

    fn init() -> StorageSet {
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init");
        crate::sdk::storage_io::fake_fleet::reset();
        let set = test_set(3);
        binding_fleet_double::reset_with(&fleet_tuples(&set));
        set
    }

    async fn bind(set: &StorageSet, b: &SettlementBundle, c_n: [u8; 32]) {
        let out = bind_settlement(set, [7; 32], b, VAULT, c_n).await.unwrap();
        assert_eq!(out, Ok(Outcome::Committed));
    }

    fn all_members() -> [&'static str; 3] {
        ["dsm-node-0", "dsm-node-1", "dsm-node-2"]
    }

    // ── 2c-C3.1 ────────────────────────────────────────────────────────────

    /// Ruling A: a bound parent is recorded as a finality the moment it is
    /// observed, and re-observing the SAME value writes nothing new.
    #[tokio::test]
    #[serial]
    async fn a_bound_parent_is_recorded_and_reobserving_it_is_not_a_contradiction() {
        let set = init();
        let b = market_bundle(VAULT, C_N);
        bind(&set, &b, C_N).await;
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        assert!(matches!(occ, ParentOccupancy::BoundBy(_)), "{occ:?}");
        let canon = settlement_bundle::canon(&b).unwrap();
        let recorded = quarantine::observed_finality(&VAULT, &C_N)
            .unwrap()
            .expect("recorded at the moment it was established");
        assert_eq!(
            recorded.value.tx_id,
            settlement_bundle::bundle_digest(&canon)
        );
        assert_eq!(recorded.generation, GEN);
        let again = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        assert!(matches!(again, ParentOccupancy::BoundBy(_)), "{again:?}");
        assert!(quarantine::roots_for_vault(&VAULT).unwrap().is_empty());
    }

    /// Rulings A, B, D, E at the observer: a SECOND chosen value at a key this
    /// verifier recorded is duplicate finality; the root is written with both
    /// evidence objects; and from then on the key is never resolved again —
    /// not with the second value, not with the first restored, and not on the
    /// probe.
    #[tokio::test]
    #[serial]
    async fn a_second_chosen_value_at_a_recorded_key_quarantines_and_is_never_resolved_again() {
        let set = init();
        let b = market_bundle(VAULT, C_N);
        bind(&set, &b, C_N).await;
        assert!(matches!(
            observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await,
            ParentOccupancy::BoundBy(_)
        ));
        let a = quarantine::observed_finality(&VAULT, &C_N)
            .unwrap()
            .unwrap();

        // Every member breaks its register and serves B at the same key.
        let k = settlement_bundle::resource_key(&C_N);
        let b_digest = [0xB1u8; 32];
        let b_addr = dsm::storage_object::immutable_addr_from_inner(
            dsm::common::domain_tags::TAG_DSM_SETTLEMENT_BUNDLE,
            &b_digest,
        );
        binding_fleet_double::plant_committed(
            &all_members(),
            &[k],
            b_digest,
            b_digest,
            b_addr,
            Round {
                counter: a.round.counter + 10,
                proposer_id: [0xB1; 32],
            },
        );
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        let ParentOccupancy::Unresolvable(why) = occ else {
            panic!("expected the duplicate-finality refusal, got {occ:?}");
        };
        assert_eq!(why.reason, Reason::DuplicateBindingFinality);
        assert_eq!(why.class(), OutcomeClass::SafetyViolation);

        let roots = quarantine::roots_for_vault(&VAULT).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].root_c_n, C_N);
        assert_eq!(roots[0].root_generation, GEN);
        let first = quarantine::Evidence::decode(&roots[0].first_evidence).unwrap();
        let second = quarantine::Evidence::decode(&roots[0].second_evidence).unwrap();
        assert_eq!(first.value(), a.value, "the first evidence is A");
        assert_eq!(second.value().tx_id, b_digest, "the second evidence is B");
        let quarantine::Evidence::Observed(o) = &second else {
            panic!("the second finality was observed")
        };
        o.recompute().expect("the preserved read reproduces B");

        // Never resolved again: with B still served, with A restored, and on
        // the probe.
        let refused = |occ: ParentOccupancy| {
            let ParentOccupancy::Unresolvable(why) = occ else {
                panic!("expected the durable refusal, got {occ:?}");
            };
            assert_eq!(why.reason, Reason::LineageQuarantined);
        };
        refused(observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await);
        binding_fleet_double::plant_committed(
            &all_members(),
            &[k],
            a.value.tx_id,
            a.value.value_digest,
            a.value.value_addr,
            a.round,
        );
        refused(observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await);
        let probe = probe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        assert_eq!(probe.verdict, "LINEAGE_QUARANTINED");
        assert!(probe.tx_id.is_none() && probe.value_digest.is_none());
        // Both continuations and everything beyond, by the generation bound;
        // a parent below the root is not refused by it.
        refused(
            observe_parent_binding(&set, &VAULT, GEN + 1, &[0xD1; 32], &set.id(), set.quorum())
                .await,
        );
        refused(
            observe_parent_binding(&set, &VAULT, GEN + 7, &[0xD2; 32], &set.id(), set.quorum())
                .await,
        );
        assert_eq!(
            observe_parent_binding(&set, &VAULT, GEN - 1, &[0xD0; 32], &set.id(), set.quorum())
                .await,
            ParentOccupancy::Free
        );
    }

    /// Ruling F: the observer refuses a non-canonical quorum ITSELF, so no
    /// caller can make `Conflict` reachable by passing a weaker `q`.
    #[tokio::test]
    #[serial]
    async fn a_non_canonical_quorum_establishes_nothing_at_the_observer() {
        let set = init();
        let b = market_bundle(VAULT, C_N);
        bind(&set, &b, C_N).await;
        let key = settlement_bundle::resource_key(&C_N);
        assert_eq!(
            observe_key_at_set(&set, &key, 1).await,
            BindingObservation::Unavailable {
                attributed: 0,
                required: 1
            }
        );
        assert!(matches!(
            observe_key_at_set(&set, &key, set.quorum()).await,
            BindingObservation::BoundFinal(_)
        ));
    }

    #[tokio::test]
    #[serial]
    async fn a_parent_nothing_has_bound_is_free() {
        let set = init();
        assert_eq!(
            observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await,
            ParentOccupancy::Free
        );
    }

    #[tokio::test]
    #[serial]
    async fn a_bound_parent_resolves_to_the_bundle_that_owns_it() {
        let set = init();
        let b = market_bundle(VAULT, C_N);
        bind(&set, &b, C_N).await;

        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        let ParentOccupancy::BoundBy(bp) = occ else {
            panic!("expected BoundBy, got {occ:?}");
        };
        let canon = settlement_bundle::canon(&b).unwrap();
        assert_eq!(bp.bundle_digest, settlement_bundle::bundle_digest(&canon));
        assert_eq!(bp.bundle_addr, settlement_bundle::bundle_addr(&canon));
        assert_eq!(bp.shape, BundleShape::Market);
        assert_eq!(bp.transition_ix, 0);
        // And it is occupancy ONLY: nothing here says the successor realized.
        assert_eq!(bp.transition().unwrap().parent_binding, C_N);
        // The successor span is the exact nested bytes, never a re-encoding.
        assert_eq!(
            bp.successor_bytes(),
            bp.transition()
                .unwrap()
                .successor
                .encode()
                .unwrap()
                .as_slice()
        );
    }

    /// Binding another vault's parent leaves THIS parent free. The key is
    /// derived from `c_n`, so the two never share a cell.
    #[tokio::test]
    #[serial]
    async fn binding_one_parent_does_not_occupy_another() {
        let set = init();
        let other_c_n = [0xC1; 32];
        let b = market_bundle(VAULT, other_c_n);
        bind(&set, &b, other_c_n).await;
        assert_eq!(
            observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await,
            ParentOccupancy::Free
        );
    }

    /// THE APPLICATION-BLIND REGISTER. A member never inspects the value it
    /// holds, so a proposer can put a bundle's record at a key the bundle does
    /// not name. Nothing in the read catches that; the parent check does.
    /// A foreign bundle whose carried evidence disagrees with ITSELF is refused
    /// here, on the CONSUMING side — not merely by the producer that built it.
    ///
    /// The bundle is otherwise perfect: canonical, hashing to the record's
    /// identity, naming this exact parent, at the right generation. Only its
    /// `trader_successor` is not the chain tip of its own carried inputs. A
    /// producer's self-check cannot catch this, because a producer that means
    /// harm does not run one.
    #[tokio::test]
    #[serial]
    async fn a_bound_bundle_whose_evidence_contradicts_itself_is_unresolvable() {
        let set = init();
        let honest = market_bundle(VAULT, C_N);
        // Tamper ONLY the carried successor. Everything else — the transition,
        // the parent, the generation, the vault — stays exactly right, so the
        // refusal below can only come from the evidence conjuncts.
        let mut terms = honest.market_terms().expect("market bundle").clone();
        terms.trader_successor = [0xAB; 32];
        let tampered = dsm::ccb::SettlementBundle::market(terms, honest.transitions().to_vec())
            .expect("a self-inconsistent bundle still ENCODES; that is the point");

        let canon = settlement_bundle::canon(&tampered).unwrap();
        let digest = settlement_bundle::bundle_digest(&canon);
        bind(&set, &tampered, C_N).await;
        binding_fleet_double::plant_committed(
            &["dsm-node-0", "dsm-node-1"],
            &[settlement_bundle::resource_key(&C_N)],
            digest,
            digest,
            settlement_bundle::bundle_addr(&canon),
            Round {
                counter: 23,
                proposer_id: [7; 32],
            },
        );
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        assert!(
            matches!(&occ, ParentOccupancy::Unresolvable(w)
                     if w.reason == Reason::BundleNotCanonical
                        && w.class() == OutcomeClass::Invalid),
            "G4 must refuse it on the consuming side, got {occ:?}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn a_bundle_bound_at_a_key_it_does_not_name_is_unresolvable() {
        let set = init();
        let other_c_n = [0xC1; 32];
        let b = market_bundle(VAULT, other_c_n);
        bind(&set, &b, other_c_n).await;

        // Now plant that same committed record at THIS parent's key.
        let canon = settlement_bundle::canon(&b).unwrap();
        let digest = settlement_bundle::bundle_digest(&canon);
        binding_fleet_double::plant_committed(
            &["dsm-node-0", "dsm-node-1"],
            &[settlement_bundle::resource_key(&C_N)],
            digest,
            digest,
            settlement_bundle::bundle_addr(&canon),
            Round {
                counter: 21,
                proposer_id: [7; 32],
            },
        );
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        // A bundle bound at a key it does not name is DECIDABLY FALSE. It was
        // reported as an absence of evidence before amendment 2c-C3.
        assert!(
            matches!(&occ, ParentOccupancy::Unresolvable(w)
                     if w.reason == Reason::StaleParent
                        && w.class() == OutcomeClass::Invalid),
            "got {occ:?}"
        );
    }

    /// Losing quorum establishes NOTHING — and in particular does not establish
    /// that the parent is free.
    #[tokio::test]
    #[serial]
    async fn a_parent_whose_members_cannot_be_reached_is_unresolvable_not_free() {
        let set = init();
        binding_fleet_double::fail_member_id("dsm-node-1");
        binding_fleet_double::fail_member_id("dsm-node-2");
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        // Nothing was learned. This one stays INCOMPLETE, and Req 6.25's code
        // stays with it.
        assert!(
            matches!(&occ, ParentOccupancy::Unresolvable(w)
                     if w.reason == Reason::BindingEvidenceUnavailable
                        && w.class() == OutcomeClass::Incomplete),
            "got {occ:?}"
        );
    }

    /// A record held below this reader's quorum, with no absence quorum either.
    /// Retryable, and emphatically not free — the value may already be chosen
    /// behind the member that did not answer.
    #[tokio::test]
    #[serial]
    async fn an_undecided_binding_is_unresolvable_not_free() {
        let set = init();
        binding_fleet_double::plant_committed(
            &["dsm-node-0"],
            &[settlement_bundle::resource_key(&C_N)],
            [0xAB; 32],
            [0xAB; 32],
            [0xCD; 32],
            Round {
                counter: 21,
                proposer_id: [7; 32],
            },
        );
        binding_fleet_double::fail_member_id("dsm-node-2");
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        // Mid-flight is its OWN reason, distinct from "could not reach a
        // quorum to find out" — reading it as free would compose past a live
        // bind, reading it as a forgery would make every concurrent settle
        // permanently invalid.
        assert!(
            matches!(&occ, ParentOccupancy::Unresolvable(w)
                     if w.reason == Reason::BindingUndetermined
                        && w.class() == OutcomeClass::Incomplete),
            "got {occ:?}"
        );
    }

    /// A member that echoes another member's identity is uncountable, so two
    /// honest answers plus one impostor cannot reach a three-member quorum.
    #[tokio::test]
    #[serial]
    async fn an_answer_that_names_the_wrong_member_does_not_count() {
        let set = init();
        binding_fleet_double::fail_member_id("dsm-node-2");
        binding_fleet_double::set_echo("http://127.0.0.1:8081", b"dsm-node-0".to_vec(), [1; 32]);
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        assert!(
            matches!(&occ, ParentOccupancy::Unresolvable(w)
                     if w.reason == Reason::BindingEvidenceUnavailable
                        && w.class() == OutcomeClass::Incomplete),
            "got {occ:?}"
        );
    }
}
