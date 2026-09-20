// SPDX-License-Identifier: Apache-2.0

//! Pure-crypto vault primitives that outlive the old market: the deployed
//! beta storage profile, the one route arithmetic, and the owner-signed
//! baseline over the canonical state identity. No proto, I/O or runtime
//! state lives here.

pub mod beta_storage_profile; // the deployed five-member beta profile — fixed, not a formula
pub mod route_commit;
// vault_state_anchor (V1) and vault_state_anchor_v2 are DELETED by the
// state-identity cut. Their names and domains are burned, never reused; the
// only anchor form is V3 below, whose sole content is c_n.
pub mod vault_state_anchor_v3; // Def 6.4a — owner baseline over c_n; the only anchor form after the cut
