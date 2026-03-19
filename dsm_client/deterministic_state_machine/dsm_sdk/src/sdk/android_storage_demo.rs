//! # Android Storage Demo
//!
//! Example usage of the `AndroidCompatibleStorage` wrapper for local
//! development and testing. The production mobile app communicates with
//! remote storage nodes via the HTTP protobuf API and does not use
//! local `StorageInterface` implementations.

#[cfg(feature = "storage")]
use dsm::interfaces::{AndroidCompatibleStorage, StorageInterface};

/// Example function showing how to use the Android-compatible storage wrapper
/// This function can be called from JNI to demonstrate the ZSTD-free storage
/// NOTE: This is not used in mobile app - mobile uses HTTP API to remote storage nodes
#[cfg(feature = "storage")]
pub async fn demo_android_storage() -> Result<String, String> {
    // Create the Android-compatible storage (no ZSTD)
    let mut storage = AndroidCompatibleStorage::new("/tmp/android_demo.db".to_string());
    
    // Open the database with Android-compatible settings
    storage.open().map_err(|e| format!("Failed to open storage: {:?}", e))?;
    
    // Test basic operations
    let key = b"test_key";
    let value = b"test_value_android_compatible";
    
    // Store data
    storage.store(key, value).await
        .map_err(|e| format!("Failed to store: {:?}", e))?;
    
    // Retrieve data
    let retrieved = storage.retrieve(key).await
        .map_err(|e| format!("Failed to retrieve: {:?}", e))?;
    
    // Verify data
    if retrieved == value {
        Ok("Android-compatible storage working! No ZSTD issues.".to_string())
    } else {
        Err("Data mismatch in storage".to_string())
    }
}

#[cfg(not(feature = "storage"))]
pub async fn demo_android_storage() -> Result<String, String> {
    Ok("Storage demo not available - mobile app uses HTTP API to remote storage nodes".to_string())
}
