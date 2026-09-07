// SPDX-License-Identifier: Apache-2.0

//! THE LIVE BINDING PROBE — the hardware rig's window onto QuorumBind.
//!
//! `scripts/dlv_market_rig_proof.sh` used to prove exclusivity by reading the
//! settlement-slot endpoint and tallying digests across nodes in shell. That
//! mechanism is retired, and re-implementing its replacement in Bash would be
//! worse than porting it: quorum, attribution and "chosen at a key" would exist
//! twice, in two languages, and the copy with no `BindingRecord` type would be
//! the one deciding whether a live proof passes.
//!
//! So the rig asks THIS, which runs the production observer, and asserts the
//! answer. If Class K's notion of chosen ever changes, the gate changes with it
//! — because it is the same code.
//!
//! ```text
//! dlv_binding_probe <vault_id_b32> <parent_c_n_b32> <generation> [storage_set_id_b32]
//! ```
//!
//! Emits `key=value` lines and exits 0 whenever the READ succeeded — including
//! `verdict=FREE`. A non-zero exit means the probe could not ask, never that
//! the answer was unwelcome: the script decides which verdicts are acceptable,
//! and conflating "could not ask" with "wrong answer" is the exact defect the
//! four-valued observation exists to prevent.

use dsm_sdk::sdk::binding_occupancy::probe_vault_bindings;
use dsm_sdk::util::text_id::decode_base32_crockford;

/// The probe's four arguments, parsed. Named because a bare tuple of three
/// arrays and an int is unreadable at the call site and trips the complexity
/// lint besides.
struct ProbeArgs {
    vault_id: [u8; 32],
    token_a: [u8; 32],
    token_b: [u8; 32],
    fee_bps: u32,
}

fn arg32(v: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = decode_base32_crockford(v).ok_or_else(|| format!("{what} is not base32"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("{what} is not 32 bytes (got {})", bytes.len()))
}

fn main() -> std::process::ExitCode {
    // The runtime is built by hand rather than through `#[tokio::main]`: the
    // macro unwraps its construction, and a diagnostic tool that panics on a
    // runtime failure tells an operator nothing about what went wrong.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dlv_binding_probe: could not start a runtime: {e}");
            return std::process::ExitCode::from(3);
        }
    };
    runtime.block_on(run())
}

async fn run() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: dlv_binding_probe <vault_id_b32> <token_a_b32> <token_b_b32> <fee_bps>");
        return std::process::ExitCode::from(2);
    }
    let parsed = (|| -> Result<ProbeArgs, String> {
        Ok(ProbeArgs {
            vault_id: arg32(&args[1], "vault_id")?,
            token_a: arg32(&args[2], "token_a")?,
            token_b: arg32(&args[3], "token_b")?,
            fee_bps: args[4]
                .parse::<u32>()
                .map_err(|e| format!("fee_bps is not a u32: {e}"))?,
        })
    })();
    let a = match parsed {
        Ok(v) => v,
        Err(e) => {
            eprintln!("dlv_binding_probe: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    match probe_vault_bindings(&a.vault_id, &a.token_a, &a.token_b, a.fee_bps).await {
        Ok(rows) => {
            let last = rows.len().saturating_sub(1);
            for (i, (generation, c_n, probe)) in rows.iter().enumerate() {
                // The last row is the FRONTIER; the rest were consumed.
                println!(
                    "== generation={generation} role={}",
                    if i == last { "frontier" } else { "consumed" }
                );
                print!("{}", probe.render(c_n));
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            // Could not ASK. Never conflated with an unwelcome answer: the
            // script decides which verdicts are acceptable, and a composition
            // that fails closed is not the same as a parent that is free.
            eprintln!("dlv_binding_probe: {e}");
            std::process::ExitCode::from(3)
        }
    }
}
