// SPDX-License-Identifier: MIT OR Apache-2.0
//! A router made by one entry point and called through by another, as the
//! app's is: `JNI_OnLoad` installs a value in a global, and `Probe.query()`
//! dispatches to it through a trait object. Reached from `query` through the
//! value `JNI_OnLoad` made: the process holds it.

use crate::Example;
use std::sync::OnceLock;

/// The installed router's type.
pub struct Installed;

impl Example for Installed {
    fn static_fn() -> usize {
        70
    }
    fn instance_fn(&self) -> usize {
        71
    }
}

static ROUTER: OnceLock<Box<dyn Example + Send + Sync>> = OnceLock::new();

/// Called from `JNI_OnLoad`.
pub fn install() {
    ROUTER.get_or_init(|| Box::new(Installed));
}

/// Declared by `Probe.query()`: dispatches to whatever was installed.
/// `JNI_OnLoad` runs before any other call, so a router missing here is a
/// broken invariant, and says so.
#[no_mangle]
pub extern "system" fn Java_fixture_Probe_query() -> usize {
    ROUTER
        .get()
        .expect("JNI_OnLoad installs the router before any call")
        .instance_fn()
}
