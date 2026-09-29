// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the shipped build does not compile: code gated on `debug_assertions`
//! (the index compiles without it, as the release build does), a `cfg(test)`
//! module, and code gated on a feature only this crate's dev-dependency on
//! itself enables, which the index compiles and the artifact does not: an
//! item, and a statement calling an item that is not gated itself. A gate
//! that also names a condition this map does not evaluate (the pointer width)
//! leaves what it holds undecided.

#[cfg(not(debug_assertions))]
pub fn release_only() -> usize {
    60
}

#[cfg(debug_assertions)]
pub fn debug_only() -> usize {
    61
}

#[cfg(feature = "leak")]
pub fn leaked() -> usize {
    62
}

/// Not gated itself: only a statement the `leak` feature gates calls it, so
/// the shipped build compiles it and never calls it.
pub fn called_under_leak() -> usize {
    63
}

/// Not gated itself: only a statement under an undecided gate calls it.
pub fn called_under_undecided() -> usize {
    64
}

#[cfg(any(feature = "leak", target_pointer_width = "16"))]
pub fn undecided_item() -> usize {
    65
}

/// Twins under opposite gates this map cannot decide, called from a site it
/// compiles for certain: which one the build compiles, and so which the call
/// reaches, is undecided (the index holds only the first).
#[cfg(any(feature = "leak", target_pointer_width = "64"))]
pub fn undecided_twin() -> usize {
    66
}

#[cfg(not(any(feature = "leak", target_pointer_width = "64")))]
pub fn undecided_twin() -> usize {
    67
}

pub fn entry() -> usize {
    #[cfg(not(debug_assertions))]
    let chosen = release_only();
    #[cfg(debug_assertions)]
    let chosen = debug_only();
    #[cfg(feature = "leak")]
    let leaked_call = called_under_leak();
    #[cfg(not(feature = "leak"))]
    let leaked_call = 0;
    #[cfg(any(feature = "leak", target_pointer_width = "16"))]
    let undecided_call = called_under_undecided() + undecided_item();
    #[cfg(not(any(feature = "leak", target_pointer_width = "16")))]
    let undecided_call = 0;
    chosen + leaked_call + undecided_call + undecided_twin()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_only() {
        assert!(matches!(super::entry(), 60 | 61));
    }
}
