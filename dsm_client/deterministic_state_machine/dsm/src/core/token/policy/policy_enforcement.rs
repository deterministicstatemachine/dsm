// SPDX-License-Identifier: MIT OR Apache-2.0

//! src/core/token/policy/policy_enforcement.rs
//! Policy Enforcement Engine (protobuf-only; binary comparisons; no hex/base64/JSON).
//!
//! Enforces what a token's committed policy says (SoFi §47–§54): the supply
//! it was created with and the operations its flags permit. The enforcer's
//! view of a policy is derived here from the parsed blob
//! ([`enforced_policy`]) and nowhere else.
//!
//! Determinism rules:
//! - No time of any kind.
//! - No alternate paths.

use std::collections::HashMap;

use crate::types::{
    error::DsmError,
    operations::Operation,
    policy_types::{PolicyCondition, PolicyFile, TokenPolicy},
};

/// Minimal error type for policy enforcement failures that are not simply allow/deny decisions
#[derive(Debug)]
pub struct EnforcementError {
    pub message: String,
}

impl core::fmt::Display for EnforcementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EnforcementError {}

/// Result of policy enforcement
#[derive(Debug, Clone)]
pub struct EnforcementResult {
    pub allowed: bool,
    pub reason: String,
    pub conditions: Vec<String>,
    pub context: HashMap<String, String>,
}

impl EnforcementResult {
    #[inline]
    pub fn allowed(reason: &str) -> Self {
        Self {
            allowed: true,
            reason: reason.to_string(),
            conditions: Vec::new(),
            context: HashMap::new(),
        }
    }

    #[inline]
    pub fn denied(reason: &str) -> Self {
        Self {
            allowed: false,
            reason: reason.to_string(),
            conditions: Vec::new(),
            context: HashMap::new(),
        }
    }

    #[inline]
    pub fn with_context(mut self, k: &str, v: &str) -> Self {
        self.context.insert(k.to_string(), v.to_string());
        self
    }

    #[inline]
    pub fn is_success(&self) -> bool {
        self.allowed
    }
}

/// Policy enforcement context: the operation type and the binary data the
/// SDK derived from the operation itself.
#[derive(Debug, Clone)]
pub struct EnforcementContext {
    pub operation_type: String,
    pub data: HashMap<String, Vec<u8>>,
}

impl EnforcementContext {
    pub fn new(operation_type: &str) -> Self {
        Self {
            operation_type: operation_type.to_string(),
            data: HashMap::new(),
        }
    }

    pub fn with_data(mut self, key: &str, value: Vec<u8>) -> Self {
        self.data.insert(key.to_string(), value);
        self
    }

    /// The operation's amount, derived by the SDK from the operation itself:
    /// `amount_u64`, exactly 8 bytes little-endian.
    pub fn amount_witness(&self) -> Option<u64> {
        let bytes = self.data.get("amount_u64")?;
        <[u8; 8]>::try_from(bytes.as_slice())
            .ok()
            .map(u64::from_le_bytes)
    }
}

/// The enforcer's view of a parsed policy blob.
///
/// SOLE constructor. It is a pure function of the parsed (and therefore of
/// the committed) policy, so every device that reads the same policy bytes
/// derives the same view: there is no second place that decides what a
/// token's policy means.
pub fn enforced_policy(parsed: &crate::economic::token_policy::TokenPolicy) -> PolicyFile {
    // Name, version and author are display fields: the policy's identity is
    // its commitment, never anything stated here.
    let mut file = PolicyFile::new(&parsed.ticker, "1.0.0", "committed policy");
    if let Some(description) = parsed.description.as_ref() {
        file.description = Some(description.clone());
    }
    // CONDITIONS, not metadata: conditions are what the enforcer evaluates.
    // The whole supply exists from creation (SoFi §51): no unit is issued
    // after it.
    file.add_condition(PolicyCondition::SupplyCap {
        max_supply: parsed.genesis_supply,
    });
    // What each flag governs (SoFi §49, §54): `transferable` every transfer
    // (vault creation and SoFi legs are refused in Core, at genesis
    // acceptance and route validation), `burn_enabled` burns only. Creation
    // is always the creator's own (Amendment S8, checked at the genesis
    // release). The signer set the blob carries authorizes only what the
    // policy's own rules name, and the standard release rule names none
    // (§47), so no condition is built from it.
    file.add_condition(PolicyCondition::OperationRestriction {
        allowed_operations: permitted_operations(parsed.transferable, parsed.burn_enabled),
    });
    file.add_metadata("token_name", &parsed.ticker);
    file
}

/// The operations a token's policy permits, from its two flags.
pub fn permitted_operations(transferable: bool, burn_enabled: bool) -> Vec<String> {
    let mut ops = vec!["create_token".to_string()];
    if transferable {
        ops.extend(["transfer", "lock", "unlock"].map(String::from));
    }
    if burn_enabled {
        ops.push("burn".to_string());
    }
    ops
}

/// Policy enforcement engine
#[derive(Debug, Default)]
pub struct PolicyEnforcer;

/// Context keys carrying what the supply cap is evaluated against.
pub mod witness_keys {
    pub const AMOUNT: &str = "amount_le";
    /// Circulating supply DERIVED from canonical state (never a cached count):
    /// [`super::circulating_supply`].
    pub const CIRCULATING: &str = "circulating_le";
}

/// The circulating supply of the asset under `policy_commit`, folded over a
/// device's chain history — never a cached counter, which a restored snapshot
/// could misreport. A token's whole supply is released at creation (SoFi §51),
/// so:
///
///   circulating = Σ CreateToken.initial_supply − Σ Burn
///                 (for operations naming this policy_commit)
///
/// A burn past what the history created (units received from another device)
/// floors at zero.
///
/// `None` when the history could not be read in full (`history` is the read's
/// failure). That is not the same as zero: a figure from partial history is a
/// figure about another chain. `None` also when the creations pass what a
/// balance carries, which no history whose every creation the cap admitted
/// reaches. Absent is what [`witness_keys::CIRCULATING`] then carries, and the
/// cap refuses a creation it cannot evaluate.
pub fn circulating_supply<'a, E>(
    policy_commit: &[u8; 32],
    history: Result<impl IntoIterator<Item = &'a Operation>, E>,
) -> Option<u64> {
    let Ok(operations) = history else {
        return None;
    };
    let mut circulating: u64 = 0;
    for operation in operations {
        match operation {
            Operation::CreateToken {
                initial_supply,
                policy_commit: pc,
                ..
            } if pc == policy_commit => {
                circulating = circulating.checked_add(initial_supply.value())?;
            }
            Operation::Burn {
                amount,
                policy_commit: pc,
                ..
            } if pc == policy_commit => {
                circulating = circulating.saturating_sub(amount.value());
            }
            _ => {}
        }
    }
    Some(circulating)
}

impl PolicyEnforcer {
    pub fn new() -> Self {
        Self
    }

    pub async fn enforce_policy(
        &self,
        policy: &TokenPolicy,
        operation_type: &str,
        context_data: &HashMap<String, Vec<u8>>,
    ) -> Result<EnforcementResult, DsmError> {
        let mut ctx = EnforcementContext::new(operation_type);
        for (k, v) in context_data {
            ctx = ctx.with_data(k, v.clone());
        }
        for condition in &policy.file.conditions {
            let res = self.check_condition(condition, &ctx).await?;
            if !res.allowed {
                return Ok(res);
            }
        }
        Ok(EnforcementResult::allowed(
            "All policy conditions satisfied",
        ))
    }

    /// Evaluate one condition. Exposed so the authority/supply guarantees can
    /// be asserted directly rather than only through a full policy round trip
    /// — these are security properties and deserve pointed tests.
    pub async fn check_condition(
        &self,
        condition: &PolicyCondition,
        ctx: &EnforcementContext,
    ) -> Result<EnforcementResult, DsmError> {
        match condition {
            PolicyCondition::OperationRestriction { allowed_operations } => {
                // Match the case-sensitive canonical encoding: `["transfer"]`
                // and `["Transfer"]` are distinct policies.
                let allowed = allowed_operations
                    .iter()
                    .any(|op| op == &ctx.operation_type);
                if allowed {
                    Ok(EnforcementResult::allowed("Operation permitted"))
                } else {
                    Ok(EnforcementResult::denied("Operation not permitted"))
                }
            }

            PolicyCondition::SupplyCap { max_supply } => {
                // Only creation brings supply into being: nothing is minted
                // after genesis (SoFi §48).
                if ctx.operation_type != "create_token" {
                    return Ok(EnforcementResult::allowed(
                        "SupplyCap does not gate this operation",
                    ));
                }
                let (Some(amount_le), Some(circ_le)) = (
                    ctx.data.get(witness_keys::AMOUNT),
                    ctx.data.get(witness_keys::CIRCULATING),
                ) else {
                    // Fail closed: without the derived circulating supply the
                    // cap cannot be evaluated, and guessing would enforce it
                    // against the wrong number.
                    return Ok(EnforcementResult::denied(
                        "Supply cap cannot be evaluated without circulating supply",
                    ));
                };
                let (Ok(a), Ok(c)) = (
                    <[u8; 8]>::try_from(amount_le.as_slice()),
                    <[u8; 8]>::try_from(circ_le.as_slice()),
                ) else {
                    return Ok(EnforcementResult::denied("Supply context malformed"));
                };
                let amount = u64::from_le_bytes(a) as u128;
                let circulating = u64::from_le_bytes(c) as u128;
                if circulating.saturating_add(amount) <= *max_supply {
                    Ok(EnforcementResult::allowed("Within supply cap"))
                } else {
                    Ok(EnforcementResult::denied(
                        "Creation would exceed the token's maximum supply",
                    ))
                }
            }

            PolicyCondition::BitcoinTapConstraint { .. } => {
                // Configuration-only; tap safety is enforced at vault creation
                // and fractional exit time, not during generic policy enforcement.
                Ok(EnforcementResult::allowed(
                    "Bitcoin tap constraint parameter",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economic::token_policy::{Release, TokenPolicy as ParsedTokenPolicy};
    use crate::types::policy_types::{PolicyAnchor, PolicyCondition, PolicyFile, TokenPolicy};

    /// What the circulating supply folds to on fixed histories: creations add,
    /// burns subtract and never below zero, operations naming another policy
    /// do not count, and a history that could not be read has no figure.
    /// MUTATION CONTROL: a fold that ignores burns turns this red.
    #[test]
    fn the_circulating_supply_folds_creations_less_burns_for_its_policy_alone() {
        use crate::types::token_types::Balance;
        let create = |policy_commit: [u8; 32], supply: u64| Operation::CreateToken {
            token_id: b"PINNED".to_vec(),
            initial_supply: Balance::amount(supply),
            policy_commit,
            fee_amount: 10,
            name: "Pinned".into(),
            symbol: "PIN".into(),
            decimals: 2,
            metadata_uri: None,
            signature: Vec::new(),
        };
        let burn = |policy_commit: [u8; 32], amount: u64| Operation::Burn {
            amount: Balance::amount(amount),
            token_id: b"PINNED".to_vec(),
            policy_commit,
            token_policy: Vec::new(),
            message: "burn".into(),
        };
        let fold = |policy_commit: &[u8; 32], history: &[Operation]| {
            circulating_supply(
                policy_commit,
                Ok::<_, std::convert::Infallible>(history.iter()),
            )
        };
        let (p, q) = ([0x51u8; 32], [0x52u8; 32]);
        let history = [
            create(p, 1_000),
            burn(p, 300),
            create(q, 50),
            burn(q, 10),
            Operation::Noop,
        ];
        assert_eq!(fold(&p, &history), Some(700));
        assert_eq!(fold(&q, &history), Some(40));
        assert_eq!(fold(&[0x53; 32], &history), Some(0));
        assert_eq!(fold(&p, &[]), Some(0));
        assert_eq!(
            fold(&p, &[create(p, 100), burn(p, 250), create(p, 40)]),
            Some(40),
            "a burn past what this chain created floors at zero",
        );
        assert_eq!(
            circulating_supply(
                &p,
                Err::<std::iter::Empty<&Operation>, _>("a row does not decode"),
            ),
            None,
            "a history read short has no figure, not a figure of zero",
        );
        assert_eq!(
            fold(&p, &[create(p, u64::MAX), create(p, 1)]),
            None,
            "creations past what a balance carries have no figure",
        );
        assert_eq!(
            fold(&p, &[create(p, u64::MAX), create(p, 1), burn(p, 1)]),
            None,
            "creations past what a balance carries have no figure",
        );
    }

    fn fungible_fixture() -> ParsedTokenPolicy {
        ParsedTokenPolicy {
            ticker: "DSM".into(),
            alias: "DSM Token".into(),
            decimals: 8,
            genesis_supply: 1_000_000,
            release: Release::AllAtCreation {
                creator_genesis: [0x31; 32],
                creator_device_id: [0x32; 32],
                threshold: 1,
                signers: vec![vec![0xAB; 64]],
            },
            description: Some("A test token".into()),
            icon_url: Some("dsm:icon".into()),
            burn_enabled: true,
            transferable: true,
            allowlist_device_ids: Vec::new(),
        }
    }

    /// SoFi §49, §54: a token's operation restriction is exactly its two
    /// flags — transfers (and the lock operation types) when transferable,
    /// burns when burn-enabled, creation always — and the signer set builds
    /// no condition, because the standard release rule names it for nothing
    /// (§47).
    #[test]
    fn the_policy_permits_exactly_what_its_flags_name() {
        for (transferable, burn_enabled) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let parsed = ParsedTokenPolicy {
                transferable,
                burn_enabled,
                ..fungible_fixture()
            };
            let file = enforced_policy(&parsed);
            let restrictions: Vec<&Vec<String>> = file
                .conditions
                .iter()
                .filter_map(|c| match c {
                    PolicyCondition::OperationRestriction { allowed_operations } => {
                        Some(allowed_operations)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                restrictions.len(),
                1,
                "one restriction ({transferable}, {burn_enabled})"
            );
            let ops = restrictions[0];
            let has = |op: &str| ops.iter().any(|o| o == op);
            assert!(has("create_token"));
            assert_eq!(has("transfer"), transferable);
            assert_eq!(has("lock"), transferable);
            assert_eq!(has("unlock"), transferable);
            assert_eq!(has("burn"), burn_enabled);
            assert_eq!(
                file.conditions.len(),
                2,
                "the supply cap and the restriction, and nothing built from the signer set"
            );
            assert!(file.conditions.contains(&PolicyCondition::SupplyCap {
                max_supply: 1_000_000
            }));
        }
    }

    // OperationRestriction is case-sensitive, so enforcement aligns with the
    // case-sensitive canonical sort that goes into a policy's bytes.
    #[tokio::test]
    async fn operation_restriction_is_case_sensitive() -> Result<(), Box<dyn std::error::Error>> {
        let enforcer = PolicyEnforcer::new();

        let mut pf = PolicyFile::new("OP", "1.0.0", "a");
        pf.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["transfer".into()],
        });
        let pol = TokenPolicy::new_with_anchor(pf, PolicyAnchor::from_bytes([0x0F; 32]));

        let ctx = HashMap::new();

        // Exact-case match — must allow.
        let res = enforcer.enforce_policy(&pol, "transfer", &ctx).await?;
        assert!(res.allowed, "exact-case operation must be allowed");

        // Uppercase variant — must reject (the committed bytes see only
        // "transfer"; allowing "Transfer" would diverge enforcement from
        // the committed permission set).
        let res = enforcer.enforce_policy(&pol, "Transfer", &ctx).await?;
        assert!(
            !res.allowed,
            "uppercase \"Transfer\" must NOT match a policy committed to \"transfer\""
        );

        // Mixed case — must reject.
        let res = enforcer.enforce_policy(&pol, "TraNsFeR", &ctx).await?;
        assert!(
            !res.allowed,
            "mixed-case \"TraNsFeR\" must NOT match a policy committed to \"transfer\""
        );

        Ok(())
    }
}
