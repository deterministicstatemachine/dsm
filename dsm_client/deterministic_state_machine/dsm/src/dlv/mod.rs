// SPDX-License-Identifier: Apache-2.0

//! Pure vault primitives: the one constant-product arithmetic (SoFi §19.5)
//! and the owner-signed baseline over the canonical state identity. No proto, I/O or runtime
//! state lives here.

pub mod route_commit;
// vault_state_anchor (V1) and vault_state_anchor_v2 are DELETED by the
// state-identity cut. Their names and domains are burned, never reused; the
// only anchor form is V3 below, whose sole content is c_n.
pub mod vault_state_anchor_v3; // Def 6.4a — owner baseline over c_n; the only anchor form after the cut
