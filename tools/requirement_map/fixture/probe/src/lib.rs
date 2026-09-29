// SPDX-License-Identifier: MIT OR Apache-2.0
//! The requirement map's dispatch fixture. Each shape has one expected reading
//! in `../expected.tsv`, which `make requirement-map-fixture` checks through
//! the map's real pipeline: a trait's associated function runs on dispatch
//! evidence (a type argument, a qualified path, a value) without any value;
//! its method runs only on a value that reached code constructs.

/// One associated function, one method.
pub trait Example {
    fn static_fn() -> u32;
    fn instance_fn(&self) -> u32;
}

/// Dispatched on only as a call's type argument; never constructed.
pub struct Named;
/// Dispatched on only through a qualified path; never constructed.
pub struct Qualified;
/// Constructed, then used by value.
pub struct Built;
/// Only named, in a type annotation.
pub struct Never;

impl Example for Named {
    fn static_fn() -> u32 {
        1
    }
    fn instance_fn(&self) -> u32 {
        2
    }
}

impl Example for Qualified {
    fn static_fn() -> u32 {
        3
    }
    fn instance_fn(&self) -> u32 {
        4
    }
}

impl Example for Built {
    fn static_fn() -> u32 {
        5
    }
    fn instance_fn(&self) -> u32 {
        6
    }
}

impl Example for Never {
    fn static_fn() -> u32 {
        7
    }
    fn instance_fn(&self) -> u32 {
        8
    }
}

fn fold<H: Example>() -> u32 {
    H::static_fn()
}

fn run_instance<H: Example>(value: &H) -> u32 {
    value.instance_fn()
}

/// The entry point: `Probe.entry()` in `../kotlin/Probe.kt` declares it.
#[no_mangle]
pub extern "C" fn Java_fixture_Probe_entry() -> u32 {
    let via_type_argument = fold::<Named>();
    let via_qualified_path = <Qualified as Example>::static_fn();
    let built = Built;
    let via_value = run_instance(&built);
    let annotated: Option<Never> = None;
    via_type_argument + via_qualified_path + via_value + u32::from(annotated.is_some())
}

/// Nothing calls this.
pub fn unused() -> u32 {
    9
}
