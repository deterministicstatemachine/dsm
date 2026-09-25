// SPDX-License-Identifier: MIT OR Apache-2.0

//! The market-leg rule of a committed token policy (SoFi §49): whether its
//! asset may be a leg of a DLV at all. The policy itself — its blob, its rules
//! and its one parser — is [`crate::economic::token_policy`].

use crate::economic::token_policy::TokenPolicy;

/// Why a committed policy refuses its asset as a DLV market leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarketLegRefusal {
    /// The committed policy marks the asset non-transferable. A market
    /// successor moves control of units between the owner and an arbitrary
    /// counterparty — exactly the movement `transferable: false` forbids —
    /// so admitting the asset as an AMM leg would bypass the committed
    /// restriction through the market door.
    NotTransferable,
}

impl core::fmt::Display for MarketLegRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotTransferable => write!(
                f,
                "the committed policy marks the asset non-transferable, so it \
                 cannot be a market leg — a DLV successor moves control between parties"
            ),
        }
    }
}

impl std::error::Error for MarketLegRefusal {}

/// Decide whether the committed policy permits its asset as a DLV MARKET LEG
/// (fund, settle, owner-apply, close) — the "applicable token policy"
/// conjunct SoFi Def 4.1 / Req 4.4 / Req 4.6 place on every market successor
/// and every release.
///
/// The matrix is deliberately small, and what it does NOT consult is a
/// ruling, not an omission (owner, 2026-08-30 — the CoinGecko model): token
/// anchors are PUBLIC identifiers, discovery is external, adoption is open —
/// anyone holding the anchor may root to the token. Consequently:
///
/// - `allowlist_device_ids` is ISSUANCE-RECIPIENT-scoped (who may receive
///   issuance) and has no market meaning — an allowlisted-issuance asset
///   trades freely once issued (§49).
/// - `burn_enabled` governs burns only (§54), the supply fields the
///   creation, and the signer set only what a release rule names (§47);
///   none of them is the market's business.
/// - `transferable` is the ONE movement-relevant commitment the policy
///   carries, and it binds here.
///
/// Rooting itself is the caller's precondition: this function takes a PARSED
/// policy, so reaching it already required the canonical bytes that re-hash
/// to the leg's commit. ERA and dBTC are pre-rooted on every device by
/// construction and never reach this matrix.
pub fn check_market_leg_permitted(policy: &TokenPolicy) -> Result<(), MarketLegRefusal> {
    if !policy.transferable {
        return Err(MarketLegRefusal::NotTransferable);
    }
    Ok(())
}
