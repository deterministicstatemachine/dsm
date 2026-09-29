// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trait objects: a value boxed as `dyn Example` and called through the
//! object. The type behind the object is constructed, so its method runs; a
//! type that implements the trait and is never constructed does not. An
//! outside trait implemented on the trait object itself names a type the
//! index holds no symbol for.

use crate::Example;

pub struct Boxed;
pub struct NeverBoxed;

impl Example for Boxed {
    fn static_fn() -> usize {
        20
    }
    fn instance_fn(&self) -> usize {
        21
    }
}

impl Example for NeverBoxed {
    fn static_fn() -> usize {
        22
    }
    fn instance_fn(&self) -> usize {
        23
    }
}

fn call(object: &dyn Example) -> usize {
    object.instance_fn()
}

pub fn entry() -> usize {
    let boxed: Box<Boxed> = Box::new(Boxed);
    call(boxed.as_ref())
}

impl std::fmt::Debug for dyn Example {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an example")
    }
}
