// SPDX-License-Identifier: MIT OR Apache-2.0
//! The beta SoFi routing profile: what a route may name and what a bundle may
//! carry, as three limits that are DIFFERENT DIMENSIONS of the routing model
//! and are therefore never derived from one another.
//!
//! SoFi V2 §9.1 keeps sequential depth (`max_hops`) and same-pair horizontal
//! fanout (`max_fanout`) as independent, finite, committed bounds; the bundle
//! cardinality (`|{T_v}|`) is a third. They are spelled out separately because
//! they move separately. Amendment 2c-H H12 sets both the depth and the bundle
//! cardinality to two BY DECISION — with fanout 1, one route-wide bundle over
//! two vaults is exactly two hops — and pins them equal by test; raising the
//! transition count to admit split liquidity on one leg must never, by
//! aliasing, also admit deeper sequential routes, or the reverse. A one-hop route across three LPs is `(1 hop, 3 transitions, fanout
//! 3)`; a two-hop route across two LPs each is `(2 hops, 4 transitions,
//! fanout 2)`.
//!
//! The execution boundary (`dlv.unlockRouted`) refuses a signed route deeper
//! than [`BETA_MAX_HOPS`] before any composition, publication, fence or bind;
//! the binder (`route.findAndBindBestPath`) searches no deeper, so the wallet
//! never signs, and never publishes `X` for, a route the profile cannot settle.
//! A route of two hops settles as ONE route-wide settlement — one bundle
//! carrying every `T_v`, one `QuorumBind` over the complete sorted `K(B)`, one
//! trader advance (§6.5, §6.6, §7.2, §9.7, §16.2) — never hop by hop, because
//! §16.2 forbids exactly that emulation.

/// Sequential route depth the SDK will bind and execute in beta: two, by the
/// owner's 2c-H ruling (H12). Equal to [`BETA_MAX_TRANSITIONS`] by decision and
/// pinned so by a test, never defined as it.
pub(crate) const BETA_MAX_HOPS: usize = 2;

/// Vault transitions one settlement bundle may carry in beta: two, by the
/// owner's 2c-H ruling (H12). This equals `dsm::ccb::MAX_TRANSITIONS` — the
/// core's cardinality fence — and a test pins that equality, so the two cannot
/// drift apart silently; it is not defined AS that constant, so raising one
/// never raises the other.
pub(crate) const BETA_MAX_TRANSITIONS: usize = 2;

/// Independent DLVs one same-pair allocation leg may draw from in beta.
pub(crate) const BETA_MAX_FANOUT: usize = 1;

/// The depth the binder searches for a caller asking for `requested_max_hops`:
/// `0` means "the profile's depth", anything else is clamped to it. Pure, so
/// the clamp is testable on its own — the handler's pair-scoped discovery
/// already bounds a beta route to one hop, which means a handler test cannot
/// tell whether this clamp is load-bearing; this function can.
pub(crate) fn bounded_search_depth(requested_max_hops: u32) -> usize {
    let asked = requested_max_hops as usize;
    if asked == 0 {
        BETA_MAX_HOPS
    } else {
        asked.min(BETA_MAX_HOPS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SDK's transition limit and the core's bundle cardinality are the
    /// same number by agreement, not by aliasing. If either moves without the
    /// other, this is the test that says so.
    #[test]
    fn the_sdk_transition_limit_agrees_with_the_core_bundle_cardinality() {
        assert_eq!(BETA_MAX_TRANSITIONS, dsm::ccb::MAX_TRANSITIONS);
    }

    /// The binder never searches deeper than the profile: `0` is the profile's
    /// depth, `1` is honoured, and any larger request is clamped, never
    /// refused and never honoured.
    #[test]
    fn the_search_depth_is_clamped_to_the_profile() {
        assert_eq!(bounded_search_depth(0), BETA_MAX_HOPS);
        assert_eq!(bounded_search_depth(1), 1);
        assert_eq!(bounded_search_depth(2), 2);
        assert_eq!(bounded_search_depth(3), BETA_MAX_HOPS);
        assert_eq!(bounded_search_depth(99), BETA_MAX_HOPS);
        assert_eq!(bounded_search_depth(u32::MAX), BETA_MAX_HOPS);
    }

    /// Beta executes two hops, a bundle carries two transitions, and a leg
    /// draws from one DLV (2c-H H12). The three are stated separately; this
    /// pins the profile so a change to any one is a visible decision.
    #[test]
    fn the_beta_profile_is_two_hops_two_transitions_fanout_one() {
        assert_eq!(
            (BETA_MAX_HOPS, BETA_MAX_TRANSITIONS, BETA_MAX_FANOUT),
            (2, 2, 1)
        );
    }

    /// With fanout 1 a route's transitions ARE its hops, so the two limits
    /// agree — by this test, never by one being defined as the other (H12).
    #[test]
    fn the_depth_and_the_bundle_cardinality_agree_by_decision() {
        assert_eq!(BETA_MAX_FANOUT, 1);
        assert_eq!(BETA_MAX_HOPS, BETA_MAX_TRANSITIONS);
    }
}
