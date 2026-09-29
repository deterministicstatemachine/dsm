// SPDX-License-Identifier: MIT OR Apache-2.0
//! Calls written as paths: a trait method called through its trait's path
//! (`Example::instance_fn(&value)`), through a qualified path
//! (`<T as Example>::instance_fn(&value)`), and an inherent method called
//! through its type's path. A type only constructed is no evidence for its
//! associated functions: nothing dispatches `static_fn` on it. A constant
//! named only inside a format string (the index records no reference for
//! it), and two functions that call each other.

use crate::Example;

pub struct ByTraitPath;
pub struct ByQualifiedPath;
pub struct Inherent;

impl Example for ByTraitPath {
    fn static_fn() -> usize {
        10
    }
    fn instance_fn(&self) -> usize {
        11
    }
}

impl Example for ByQualifiedPath {
    fn static_fn() -> usize {
        12
    }
    fn instance_fn(&self) -> usize {
        13
    }
}

impl Inherent {
    pub fn get(&self) -> usize {
        14
    }
    pub fn never_called(&self) -> usize {
        15
    }
}

/// Named only as `{CAPTURED}` in a format string.
pub const CAPTURED: usize = 16;

fn ping(n: usize) -> usize {
    match n {
        0 => 0,
        _ => pong(n - 1),
    }
}

fn pong(n: usize) -> usize {
    ping(n)
}

pub fn entry() -> usize {
    let a = ByTraitPath;
    let b = ByQualifiedPath;
    let c = Inherent;
    Example::instance_fn(&a)
        + <ByQualifiedPath as Example>::instance_fn(&b)
        + Inherent::get(&c)
        + format!("{CAPTURED}").len()
        + ping(2)
}
