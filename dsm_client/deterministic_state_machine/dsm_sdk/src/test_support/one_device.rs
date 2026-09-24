// SPDX-License-Identifier: MIT OR Apache-2.0

//! One device on the network's pinned set of storage nodes, for tests of a
//! single device's flows against the fleet.
//!
//! The device is created as wallet creation creates it, its directory entry
//! published on the fleet, and its router built as a device builds its own
//! ([`economic_fixtures::empty_router_with`]). The nodes are the storage
//! node's own code on Postgres ([`NodeSet`]). For two devices, see
//! [`super::two_device::Pair`].

use crate::economic_fixtures::{self, FleetGuard, TestIdentity};
use crate::handlers::app_router_impl::AppRouterImpl;
use crate::sdk::core_sdk::CoreSDK;
use crate::test_support::nodes::NodeSet;

pub struct Device {
    pub nodes: NodeSet,
    pub fleet: FleetGuard,
    pub router: AppRouterImpl,
    pub identity: TestIdentity,
}

impl Device {
    /// Start the nodes, and create and publish a device holding nothing.
    pub async fn start(seed: u8) -> Self {
        economic_fixtures::use_test_storage_dir();
        let nodes = NodeSet::start().await;
        let fleet = economic_fixtures::point_sdk_at(&nodes.members());
        let (router, identity) = economic_fixtures::empty_router_with(&fleet, seed, false).await;
        Self {
            nodes,
            fleet,
            router,
            identity,
        }
    }

    /// As [`start`](Self::start), then fund the device with one faucet
    /// admission: admitted position 1, 100 ERA.
    pub async fn funded(seed: u8) -> Self {
        let device = Self::start(seed).await;
        assert_eq!(
            economic_fixtures::claim_era(&device.router).await,
            1,
            "the funding claim is economic position 1"
        );
        device
    }

    pub fn core(&self) -> &CoreSDK {
        &self.router.core_sdk
    }

    /// The device's spendable ERA as the canonical state machine holds it.
    pub fn era_balance(&self) -> u64 {
        self.core()
            .device_head()
            .expect("a created device has a head")
            .balance(&dsm::core::token::token_state_manager::era_policy_commit())
    }
}

/// The network's pinned nodes, served on the SDK runtime, and the device's
/// environment config naming them: for code that builds its transport over the
/// configured fleet. Started from a thread of its own, so it serves whether or
/// not the caller runs inside a Tokio runtime.
pub struct Fleet {
    nodes: NodeSet,
    config: FleetGuard,
}

impl Fleet {
    pub fn start() -> Self {
        let nodes = std::thread::spawn(|| crate::runtime::get_runtime().block_on(NodeSet::start()))
            .join()
            .expect("start the nodes");
        let config = economic_fixtures::point_sdk_at(&nodes.members());
        Self { nodes, config }
    }

    /// The endpoints the device's config names — the running nodes'.
    pub fn endpoints(&self) -> Vec<String> {
        let endpoints = self.config.endpoints();
        assert_eq!(
            endpoints,
            self.nodes.endpoints(),
            "the config names the running nodes"
        );
        endpoints
    }
}
