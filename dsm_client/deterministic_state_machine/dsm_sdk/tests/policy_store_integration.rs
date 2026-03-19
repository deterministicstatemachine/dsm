#![allow(clippy::disallowed_methods)]
use std::sync::Arc;
use dsm::cpta::policy_store::{PolicyStore, PolicyPersistence};
use dsm::types::policy_types::PolicyFile;
use dsm_sdk::storage::policy_fs::FsPolicyPersistence;

#[tokio::test]
async fn test_real_fs_policy_persistence() {
    // 1. Setup real persistence with a temp directory
    let temp_dir = tempfile::tempdir().unwrap();
    // FsPolicyPersistence uses HOME env var to find .dsm_config
    // We override HOME for this test process
    unsafe {
        std::env::set_var("HOME", temp_dir.path());
    }

    let persistence = Arc::new(FsPolicyPersistence::new());

    // 2. Create a policy
    let mut file = PolicyFile::new("Test Policy", "1.0", "Alice");
    file.with_description("A real policy on disk");

    let anchor = file.generate_anchor().expect("Anchor generation failed");
    let bytes = file.to_bytes().expect("Serialization failed");

    // 3. Write directly to persistence (simulating policy creation/distribution)
    persistence
        .write(&anchor, &bytes)
        .await
        .expect("Write failed");

    // 4. Use PolicyStore to read it back
    let store = PolicyStore::new(persistence);
    let loaded = store.get_policy(&anchor).await.expect("Load failed");

    assert_eq!(loaded.file.name, "Test Policy");
    assert_eq!(loaded.anchor, anchor);

    // 5. Verify file exists on disk
    // The path logic in FsPolicyPersistence is: $HOME/.dsm_config/policies/p_<escaped_anchor>.cpta (non-unix) or just bytes (unix)
    // We can just check if list_anchors returns it
    let anchors = store.list_policy_anchors().await.expect("List failed");
    assert!(anchors.contains(&anchor));
}
