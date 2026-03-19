use anyhow::{anyhow, Result};
use std::path::PathBuf;

mod dsm_adapter;
mod vectors;

use vectors::VectorRunner;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let root = if args.len() >= 2 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("tests/vectors/v1")
    };

    if !root.exists() {
        return Err(anyhow!("vector root does not exist: {}", root.display()));
    }

    // Default: run against real DSM core adapter.
    let mut api = dsm_adapter::DsmCoreAdapter::new();

    // Optional: allow a noop mode if explicitly requested (feature-gated so it doesn't warn).
    // Usage:
    //   cargo run -p dsm_vector_runner --features noop_api -- --noop tests/vectors/v1
    #[cfg(feature = "noop_api")]
    if args.iter().any(|a| a == "--noop") {
        api = dsm_adapter::DsmCoreAdapter::new();
    }

    let mut runner = VectorRunner::new(root);
    let results = runner.run_all(&mut api)?;

    let mut pass = 0usize;
    let mut fail = 0usize;

    for r in results {
        if r.passed {
            pass += 1;
            println!("PASS {}", r.case_id);
        } else {
            fail += 1;
            println!(
                "FAIL {} @{} expected={} got={}",
                r.case_id,
                r.case_dir.display(),
                r.expected.code.as_str(),
                r.got.code.as_str()
            );
            if let Some(msg) = &r.got.debug {
                println!("  debug={}", msg);
            }
        }
    }

    if fail != 0 {
        return Err(anyhow!(
            "vector run failed: {} passed, {} failed",
            pass,
            fail
        ));
    }

    println!("OK {} passed, {} failed", pass, fail);
    Ok(())
}
