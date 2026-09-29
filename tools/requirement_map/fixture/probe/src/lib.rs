// SPDX-License-Identifier: MIT OR Apache-2.0
//! The requirement map's adversarial fixture. Each shape has one expected
//! reading in `../../expected.tsv`, which `make requirement-map-fixture`
//! checks through the map's real pipeline, and the mutation cases in
//! `../../mutations.toml` change one thing each and name what must move and
//! what must not.
//!
//! Here: a trait's associated function runs on dispatch evidence (a type
//! argument, a qualified path) without any value; its method runs only on a
//! value that reached code constructs; a type only named does neither.

pub mod gates;
pub mod macros;
pub mod objects;
pub mod outside;
pub mod paths;
pub mod receivers;
pub mod roots;
pub mod scopes;
pub mod twins;

/// One associated function, one method.
pub trait Example {
    fn static_fn() -> usize
    where
        Self: Sized;
    fn instance_fn(&self) -> usize;
}

/// Dispatched on only as a call's type argument; never constructed.
pub struct Named;
/// Dispatched on only through a qualified path; never constructed.
pub struct Qualified;
/// Constructed, then used by value; nothing dispatches `static_fn` on it.
pub struct Built;
/// Only named, in a type annotation.
pub struct Never;

impl Example for Named {
    fn static_fn() -> usize {
        1
    }
    fn instance_fn(&self) -> usize {
        2
    }
}

impl Example for Qualified {
    fn static_fn() -> usize {
        3
    }
    fn instance_fn(&self) -> usize {
        4
    }
}

impl Example for Built {
    fn static_fn() -> usize {
        5
    }
    fn instance_fn(&self) -> usize {
        6
    }
}

impl Example for Never {
    fn static_fn() -> usize {
        7
    }
    fn instance_fn(&self) -> usize {
        8
    }
}

fn fold<H: Example>() -> usize {
    H::static_fn()
}

fn run_instance<H: Example>(value: &H) -> usize {
    value.instance_fn()
}

/// The entry point: `Probe.entry()` in `../../kotlin/Probe.kt` declares it.
#[no_mangle]
pub extern "C" fn Java_fixture_Probe_entry() -> usize {
    let via_type_argument = fold::<Named>();
    let via_qualified_path = <Qualified as Example>::static_fn();
    let built = Built;
    let via_value = run_instance(&built);
    let annotated: Option<Never> = None;
    via_type_argument
        + via_qualified_path
        + via_value
        + usize::from(annotated.is_some())
        + receivers::entry()
        + paths::entry()
        + objects::entry()
        + outside::entry()
        + scopes::entry()
        + twins::entry()
        + macros::entry()
        + gates::entry()
}

/// Called only as `crate::through_crate()` inside a macro's body.
pub fn through_crate() -> usize {
    52
}

/// Nothing calls this.
pub fn unused() -> usize {
    9
}
