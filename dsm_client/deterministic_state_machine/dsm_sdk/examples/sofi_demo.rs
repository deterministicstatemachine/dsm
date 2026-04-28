// SPDX-License-Identifier: MIT OR Apache-2.0
//! SoFi backend demo — interactive CLI walkthrough of the AMM trade
//! pipeline.
//!
//! Run with:
//!
//!     cargo run -p dsm_sdk --example sofi_demo --features demos
//!
//! Self-contained: no frontend, no network, no real storage nodes.
//! The `demos` Cargo feature exposes the in-process mock storage
//! backend the chunk-#1/#3 publish flows use under `#[cfg(test)]`,
//! so the full pipeline runs in a single process.
//!
//! What you'll see
//! ---------------
//!   1. Bob publishes an AMM routing-vault advertisement.
//!   2. Alice discovers it.
//!   3. Alice runs path search.
//!   4. Alice binds + signs (SPHINCS+) the RouteCommit.
//!   5. Alice publishes the external commitment X.
//!   6. The chunk #4/#5 eligibility gate passes.
//!   7. The chunk #7 AMM re-simulation gate passes.
//!   8. Trade 1 settles; reserves advance per constant-product.
//!   9. Stale-reserves attack — rejected at the chunk #7 gate
//!      with a typed `OutputMismatch`.
//!  10. Fresh route — Trade 2 settles.
//!
//! On any internal failure the demo aborts with a non-zero exit code
//! and prints the failing step.

#![allow(clippy::disallowed_methods)]

#[cfg(not(feature = "demos"))]
fn main() {
    eprintln!(
        "sofi_demo requires the `demos` feature.\n\
         Run with: cargo run -p dsm_sdk --example sofi_demo --features demos"
    );
    std::process::exit(2);
}

#[cfg(feature = "demos")]
#[tokio::main]
async fn main() {
    use dsm_sdk::sdk::amm_demo::run_amm_e2e_demo;

    println!();
    println!("══════════════════════════════════════════════════════════════════");
    println!("                  SoFi Backend Demo — End-to-End                  ");
    println!("══════════════════════════════════════════════════════════════════");
    println!();
    println!("Running the AMM trade pipeline in a single process.  No frontend,");
    println!("no network — every chunk's gate fires inside this binary.");
    println!();

    let report = match run_amm_e2e_demo().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!();
            eprintln!("DEMO FAILED: {e}");
            eprintln!();
            std::process::exit(1);
        }
    };

    for (i, step) in report.steps.iter().enumerate() {
        println!("  ┌─ {}", step.label);
        for line in step.detail.lines() {
            println!("  │   {line}");
        }
        if i + 1 < report.steps.len() {
            println!("  │");
        } else {
            println!();
        }
    }

    println!("══════════════════════════════════════════════════════════════════");
    println!("                              Summary                              ");
    println!("══════════════════════════════════════════════════════════════════");
    println!();
    println!(
        "  Initial reserves          : ({:>10}, {:>10})",
        report.initial_reserve_a, report.initial_reserve_b
    );
    println!(
        "  Trade 1: input  → output  : ({:>10}, {:>10})",
        report.trade_1_input, report.trade_1_output
    );
    println!(
        "  Reserves after Trade 1    : ({:>10}, {:>10})",
        report.trade_1_post_reserve_a, report.trade_1_post_reserve_b
    );
    println!(
        "  Stale attack: claimed/live: ({:>10}, {:>10}) ← typed reject",
        report.stale_attack_expected_output, report.stale_attack_simulated_output,
    );
    println!(
        "  Trade 2: input  → output  : ({:>10}, {:>10})",
        report.trade_2_input, report.trade_2_output
    );
    println!();
    println!("  Two settled trades + one rejected stale-reserves attack.");
    println!("  Every gate fired correctly.  SoFi protocol layer: working.");
    println!();
}
