// SPDX-License-Identifier: Apache-2.0

//! Economic write-once registers.
//!
//! Two independent one-shot registers, each following the settlement-slot
//! discipline (first-write-wins, exact bytes, attribution before storage) but
//! sharing NOTHING settlement-flavoured: their own tables, routes, headers and
//! domains. A shared domain is a shared meaning, and neither of these is a
//! settlement.
//!
//! ## Read attribution is part of the API contract
//!
//! Every response carries this node's configured member id in `x-dsm-node-id`
//! (the blanket response-header layer in `main.rs`). For these registers that
//! echo is NORMATIVE, not informational: a client establishing quorum counts
//! a response ONLY when the echoed id equals the member it queried, and a
//! response without the echo is uncountable. Nodes never sign anything here —
//! attribution under the crash-fault model is the configured member endpoint
//! answering as itself, not cryptographic node identity.

pub mod faucet_ticket;
pub mod root_register;
