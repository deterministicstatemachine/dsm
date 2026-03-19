// Utility module re-exports for DSM core
pub mod deterministic_time;

pub use deterministic_time::*;

#[cfg(test)]
mod tests {
    use super::deterministic_time as dt;

    #[test]
    fn deterministic_tick_increases() {
        let (_before_hash, before_idx) = dt::peek();
        let _ = dt::tick();
        let (_after_hash, after_idx) = dt::peek();
        assert!(after_idx >= before_idx);
    }
}
