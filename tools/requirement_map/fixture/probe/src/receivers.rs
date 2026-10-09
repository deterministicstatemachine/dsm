// SPDX-License-Identifier: MIT OR Apache-2.0
//! Receivers: a method taking `&self`, `&mut self` or `self` runs only on a
//! value reached code constructs. The same impl on a type nothing constructs
//! stays Indeterminate, whatever its receiver.

pub trait Receivers {
    fn by_ref(&self) -> usize;
    fn by_mut(&mut self) -> usize;
    fn by_value(self) -> usize;
}

/// Constructed, then used through all three receivers.
pub struct Held;
/// Never constructed.
pub struct Unheld;

impl Receivers for Held {
    fn by_ref(&self) -> usize {
        1
    }
    fn by_mut(&mut self) -> usize {
        2
    }
    fn by_value(self) -> usize {
        3
    }
}

impl Receivers for Unheld {
    fn by_ref(&self) -> usize {
        4
    }
    fn by_mut(&mut self) -> usize {
        5
    }
    fn by_value(self) -> usize {
        6
    }
}

fn all<R: Receivers>(mut value: R) -> usize {
    value.by_ref() + value.by_mut() + value.by_value()
}

pub fn entry() -> usize {
    all(Held)
}
