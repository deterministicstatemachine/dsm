// SPDX-License-Identifier: MIT OR Apache-2.0
//! Scopes: an impl written inside a function, a block item that shadows a
//! module item of the same name, an import shadowed by a local binding, and a
//! module named like a struct's field. Each name reaches only the item it
//! resolves to. Two block items of one name in one function share a symbol
//! the function does not tell apart.

use crate::Example;

/// Shadowed inside `entry` by a block item of the same name; nothing calls it.
pub fn helper() -> usize {
    30
}

pub mod count {
    /// Named like `Tally::count`; nothing calls it.
    pub fn value() -> usize {
        31
    }
}

pub mod imported {
    /// Imported below; `entry` binds a local of the same name, and only
    /// `unreached_user` calls this.
    pub fn shadowed() -> usize {
        32
    }
}

use imported::shadowed;

/// Nothing calls this: the import's only use.
pub fn unreached_user() -> usize {
    shadowed()
}

pub struct Tally {
    pub count: usize,
}

pub fn two_blocks() -> usize {
    let first = {
        fn twice_named() -> usize {
            36
        }
        twice_named()
    };
    let second = {
        fn twice_named() -> usize {
            37
        }
        twice_named()
    };
    first + second
}

pub fn entry() -> usize {
    fn helper() -> usize {
        33
    }
    struct Local;
    impl Example for Local {
        fn static_fn() -> usize {
            34
        }
        fn instance_fn(&self) -> usize {
            35
        }
    }
    let shadowed = helper();
    let tally = Tally { count: shadowed };
    Local.instance_fn() + tally.count + two_blocks()
}
