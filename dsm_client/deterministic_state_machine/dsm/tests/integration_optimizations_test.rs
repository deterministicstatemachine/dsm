//! Integration Tests for DSM Optimizations (minimal, API-aligned)
//!
//! These smoke tests validate core helpers compile and behave sanely.

use dsm::crypto::{
    streaming_signature::{StreamingSignature, StreamingSignatureProcessor, StreamingConfig},
    device_memory_manager::{DeviceMemoryManager, DeviceMemoryConfig},
};
// Performance monitor moved out; omit heavy metrics dependency in core tests.

#[test]
fn test_streaming_signature_basic() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("tokio runtime build failed: {e}"));

    runtime.block_on(async {
        let large_signature = vec![1u8; 2048];
        let streaming_sig = StreamingSignature::from_signature(&large_signature, "SPHINCS+")
            .unwrap_or_else(|e| panic!("streaming signature failed: {e}"));
        assert_eq!(streaming_sig.total_size(), 2048);
        assert_eq!(streaming_sig.chunk_count(), 2);

        for i in 0..streaming_sig.chunk_count() {
            let chunk = streaming_sig
                .get_chunk(i)
                .unwrap_or_else(|| panic!("missing chunk at index {i}"));
            assert!(streaming_sig.verify_chunk(i, chunk));
        }

        let reconstructed = streaming_sig
            .reconstruct()
            .unwrap_or_else(|e| panic!("reconstruct failed: {e}"));
        assert_eq!(reconstructed, large_signature);

        let processor = StreamingSignatureProcessor::new(StreamingConfig::default());
        let mut seen = 0usize;
        processor
            .process_signature(&large_signature, "SPHINCS+", |chunk, idx| {
                assert_eq!(idx, seen);
                assert!(!chunk.is_empty());
                seen += 1;
                Ok(())
            })
            .await
            .unwrap_or_else(|e| panic!("process failed: {e}"));
        assert_eq!(seen, streaming_sig.chunk_count());
    });
}

#[test]
fn test_device_memory_manager_smoke() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("tokio runtime build failed: {e}"));

    runtime.block_on(async {
        let manager = DeviceMemoryManager::new(DeviceMemoryConfig {
            max_memory_bytes: 1024 * 1024,
            max_signature_cache: 10,
            max_key_cache: 5,
            chunk_size: 1024,
            aggressive_cleanup: true,
        });

        let sig = vec![1u8; 1024];
        manager
            .cache_signature("sig1".into(), sig.clone())
            .await
            .unwrap_or_else(|e| panic!("cache failed: {e}"));
        let got = manager.get_signature("sig1").await;
        assert!(got.is_some());

        let buf = manager.get_buffer(512).await;
        assert_eq!(buf.capacity(), 512);
    });
}
