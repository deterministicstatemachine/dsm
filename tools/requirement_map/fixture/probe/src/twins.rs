// SPDX-License-Identifier: MIT OR Apache-2.0
//! Two types share a name in different modules, and each implements an
//! outside trait. The index names an outside trait's impl by its `Self`
//! type's bare name only, so which `Twin` each `Display` impl belongs to is
//! not decided: both stay Indeterminate even though both types are built.

pub mod left {
    pub struct Twin;
    impl core::fmt::Display for Twin {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("left")
        }
    }
}

pub mod right {
    pub struct Twin;
    impl core::fmt::Display for Twin {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("right")
        }
    }
}

pub fn entry() -> usize {
    format!("{}{}", left::Twin, right::Twin).len()
}
