// SPDX-License-Identifier: MIT OR Apache-2.0
//! Macros: one that defines a function without calling it, one that writes
//! an impl (whose method, named by the macro's own tokens, the index holds no
//! definition of), one whose body calls a function (which the index does not
//! expand), one whose body uses common names (`new`, `len`) that match
//! unrelated free functions only in name, one whose body calls through
//! `self::` and `crate::`, one whose body calls through `Self::`, and one
//! invocation that writes two functions around one call.

use crate::Example;

macro_rules! define {
    ($name:ident, $value:expr) => {
        pub fn $name() -> usize {
            $value
        }
    };
}

define!(defined_and_called, 40);
define!(defined_never_called, 41);

macro_rules! implement {
    ($ty:ident, $value:expr) => {
        pub struct $ty;
        impl Example for $ty {
            fn static_fn() -> usize {
                $value
            }
            fn instance_fn(&self) -> usize {
                $value + called_by_generated()
            }
        }
    };
}

implement!(Generated, 42);

macro_rules! calls_inside {
    () => {
        only_the_macro_calls()
    };
}

/// Called only from the method `implement!` writes.
pub fn called_by_generated() -> usize {
    49
}

/// Called only from inside `calls_inside!`'s body.
pub fn only_the_macro_calls() -> usize {
    43
}

macro_rules! common_names {
    ($items:expr) => {{
        let error = $items.len();
        error + Vec::<usize>::new().len() + usize::from(1u8) + usize::default()
    }};
}

/// Named like what `common_names!` calls or binds; nothing calls these.
pub fn len() -> usize {
    44
}
pub fn new() -> usize {
    45
}
pub fn from() -> usize {
    46
}
pub fn default() -> usize {
    47
}
pub fn error() -> usize {
    48
}

macro_rules! qualified_calls {
    () => {
        self::through_self() + crate::through_crate()
    };
}

/// Called only as `self::through_self()` inside `qualified_calls!`'s body.
pub fn through_self() -> usize {
    51
}

macro_rules! through_self_type {
    () => {
        Self::named_by_self_type()
    };
}

macro_rules! pair {
    ($first:ident, $second:ident, $value:expr) => {
        pub fn $first() -> usize {
            $value
        }
        pub fn $second() -> usize {
            $value + 1
        }
    };
}

pair!(paired_first, paired_second, from_the_pair());

/// Called only in `pair!`'s invocation, which writes two functions over one
/// extent: the index does not say which of them makes the call.
pub fn from_the_pair() -> usize {
    55
}

/// Its method is called only through `Self::` inside `through_self_type!`'s body.
pub struct Templated;

impl Templated {
    fn named_by_self_type() -> usize {
        53
    }
    pub fn run() -> usize {
        through_self_type!()
    }
}

pub fn entry() -> usize {
    let generated = Generated;
    let items = [1usize, 2];
    defined_and_called()
        + calls_inside!()
        + generated.instance_fn()
        + common_names!(items)
        + qualified_calls!()
        + Templated::run()
        + paired_first()
}
