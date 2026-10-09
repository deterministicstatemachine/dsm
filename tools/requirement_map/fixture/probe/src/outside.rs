// SPDX-License-Identifier: MIT OR Apache-2.0
//! Outside traits: a method taking `self` (`Display::fmt`) runs only on a
//! value reached code makes, an associated function (`Default::default`) only
//! on a dispatch by type. `to_string` reaches `fmt` through a blanket impl
//! and `T::default()` through a bound, neither of which the index shows.
//! Two impls of one trait on one type share a path, which names both.

use std::fmt;

/// Named in a signature, never made, never dispatched on.
pub struct OnlyNamed;
/// Made in reached code.
pub struct Made;
/// Dispatched on as a call's type argument.
pub struct Dispatched;

impl fmt::Display for OnlyNamed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("named")
    }
}

impl Default for OnlyNamed {
    fn default() -> Self {
        OnlyNamed
    }
}

/// Two impls of one trait on one type: `Made::From::from` names both.
impl From<u8> for Made {
    fn from(_: u8) -> Self {
        Made
    }
}

impl From<u16> for Made {
    fn from(_: u16) -> Self {
        Made
    }
}

impl fmt::Display for Made {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("made")
    }
}

impl Default for Dispatched {
    fn default() -> Self {
        Dispatched
    }
}

fn describe(shown: Option<&OnlyNamed>) -> usize {
    shown.iter().map(|s| s.to_string().len()).sum()
}

fn make<T: Default>() -> T {
    T::default()
}

pub fn entry() -> usize {
    let made = Made;
    let dispatched = make::<Dispatched>();
    describe(None) + made.to_string().len() + std::mem::size_of_val(&dispatched)
}
