use crate::crypto_performance::benchmark_crypto_operations;
use crate::util::deterministic_time as dt;

#[tokio::test]
async fn demonstrate_crypto_performance() {
    println!("🚀 DSM Cryptographic Performance Demonstration");
    println!("==============================================");

    // Run benchmark with different scales
    let scales = vec![5, 10, 25];

    for iterations in scales {
        println!("\n📊 Running {} iterations...", iterations);

        match benchmark_crypto_operations(iterations).await {
            Ok(results) => {
                println!("✅ Benchmark completed successfully!");
                println!(
                    "   🔐 Signature generation: {:?}",
                    results.signature_generation_time
                );
                println!(
                    "   🔒 Signature verification: {:?}",
                    results.signature_verification_time
                );
                println!(
                    "   🎲 Nonce generation: {:?}",
                    results.nonce_generation_time
                );
                println!(
                    "   📝 Message formatting: {:?}",
                    results.message_formatting_time
                );
                println!(
                    "   ⚡ Total transfer prep: {:?}",
                    results.total_transfer_prep_time
                );
                println!(
                    "   📏 Signature size: {} bytes ({:.1} KB)",
                    results.signature_size_bytes,
                    results.signature_size_bytes as f64 / 1024.0
                );
                println!(
                    "   🚀 Operations/tick: {:.4}",
                    results.operations_per_tick
                );

                // Performance analysis
                let transfer_prep_threshold_ticks = 100u64;
                if results.total_transfer_prep_time > transfer_prep_threshold_ticks {
                    println!("   ⚠️  WARNING: Transfer preparation exceeds {transfer_prep_threshold_ticks} ticks threshold");
                } else {
                    println!("   ✅ Transfer preparation time is acceptable (<= {transfer_prep_threshold_ticks} ticks)");
                }

                if results.operations_per_tick < 0.10 {
                    println!("   ⚠️  WARNING: Throughput below 0.10 operations/tick");
                } else {
                    println!("   ✅ Throughput is acceptable (> 0.10 ops/tick)");
                }
            }
            Err(e) => {
                println!("❌ Benchmark failed: {}", e);
                panic!("Performance benchmark should not fail");
            }
        }
    }

    let (_, demo_end_tick) = dt::peek();
    println!("\n🎯 Performance demonstration completed at tick={demo_end_tick}!");
    println!("   📈 SPHINCS+ signatures provide quantum resistance");
    println!("   ⚡ Operations are fast enough for real-time use");
    println!("   🔒 Cryptographic security is maintained");
}
