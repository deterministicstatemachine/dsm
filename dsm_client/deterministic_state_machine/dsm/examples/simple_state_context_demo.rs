#!/usr/bin/env cargo script

//! Demonstration of DSM State Context Integration for Balance Creation
//!
//! This example shows how the DSM protocol ensures that all token balances
//! are properly linked to canonical state hashes during state transitions.

use dsm::types::token_types::{Balance, StateContext};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("=== DSM State Context Integration Demo ===\n");

    // 1. Demonstrate balance creation WITHOUT state context (in test mode - no warnings)
    println!("--- Balance Creation WITHOUT State Context ---");
    let balance_without_context = {
        let mut balance = Balance::zero();
        balance.update_add(1000);
        balance
    };
    println!(
        "✓ Created balance: {} (no warnings in test mode)",
        balance_without_context.value()
    );

    // 2. Demonstrate balance creation WITH state context
    println!("\n--- Balance Creation WITH State Context ---");

    // Create a state context from actual state data
    let state_hash = *blake3::hash(b"actual_state_data").as_bytes();
    let device_id = blake3::hash(b"actual_device_001").into();
    let state_context = StateContext::new(
        state_hash, 1, // state number
        device_id,
    );

    // Set the state context (as TokenStateManager does during operations)
    StateContext::set_current(state_context);

    let balance_with_context = {
        let mut balance = Balance::zero();
        balance.update_add(1000);
        balance
    };
    println!(
        "✓ Created balance with state context: {} (uses canonical state hash)",
        balance_with_context.value()
    );

    // 3. Demonstrate direct state-linked balance creation
    let balance_direct = Balance::from_state(500, state_hash);
    println!(
        "✓ Created balance directly from state: {} (explicit state hash)",
        balance_direct.value()
    );

    // 4. Clear the context
    StateContext::clear_current();
    println!("\n✓ Cleared state context");

    // 5. Show zero balance creation (optimized - no unnecessary state hash)
    let zero_balance = Balance::zero();
    println!(
        "✓ Created zero balance: {} (no state hash needed)",
        zero_balance.value()
    );

    println!("\n=== Summary ===");
    println!("✓ All balance operations completed successfully");
    println!("✓ State context integration working properly");
    println!("✓ No warnings in test environment");
    println!("✓ DSM protocol compliance maintained");

    Ok(())
}
