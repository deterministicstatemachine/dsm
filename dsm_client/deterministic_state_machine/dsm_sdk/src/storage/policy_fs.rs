//! # File-System Policy Persistence
//!
//! Implements [`PolicyPersistence`]
//! using the local filesystem to store and retrieve CPTA policy anchors.

use std::path::PathBuf;
use async_trait::async_trait;
use dsm::cpta::policy_store::PolicyPersistence;
use dsm::types::error::DsmError;
use dsm::types::policy_types::PolicyAnchor;

#[derive(Debug)]
pub struct FsPolicyPersistence {
    base_dir: PathBuf,
}

impl FsPolicyPersistence {
    pub fn new() -> Self {
        let home_dir = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());

        let base_dir = PathBuf::from(home_dir).join(".dsm_config").join("policies");
        let _ = std::fs::create_dir_all(&base_dir);

        Self { base_dir }
    }

    fn get_policy_path(&self, anchor: &PolicyAnchor) -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            // macOS enforces UTF-8 filenames. Use Base32.
            let name = format!("p_{}.cpta", anchor.to_base32());
            self.base_dir.join(name)
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            use std::os::unix::ffi::OsStringExt;
            let mut name = anchor.to_path_component_bytes();
            name.extend_from_slice(b".cpta");
            let os = std::ffi::OsString::from_vec(name);
            self.base_dir.join(os)
        }
        #[cfg(not(unix))]
        {
            // Fallback for non-Unix (Windows)
            let name = format!("p_{}.cpta", anchor.to_base32());
            self.base_dir.join(name)
        }
    }
}

impl Default for FsPolicyPersistence {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PolicyPersistence for FsPolicyPersistence {
    async fn read(&self, anchor: &PolicyAnchor) -> Result<Vec<u8>, DsmError> {
        let path = self.get_policy_path(anchor);
        tokio::fs::read(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                DsmError::not_found(
                    "Policy",
                    Some("No policy file found for anchor".to_string()),
                )
            } else {
                DsmError::storage(format!("Failed to read policy file: {e}"), Some(e))
            }
        })
    }

    async fn write(&self, anchor: &PolicyAnchor, data: &[u8]) -> Result<(), DsmError> {
        let path = self.get_policy_path(anchor);
        tokio::fs::write(&path, data)
            .await
            .map_err(|e| DsmError::storage(format!("Failed to write policy file: {e}"), Some(e)))
    }

    async fn delete(&self, anchor: &PolicyAnchor) -> Result<(), DsmError> {
        let path = self.get_policy_path(anchor);
        if path.exists() {
            tokio::fs::remove_file(&path).await.map_err(|e| {
                DsmError::storage(format!("Failed to delete policy file: {e}"), Some(e))
            })?;
        }
        Ok(())
    }

    async fn list_anchors(&self) -> Result<Vec<PolicyAnchor>, DsmError> {
        let mut anchors = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.base_dir)
            .await
            .map_err(|e| DsmError::storage(format!("Failed to read policies dir: {e}"), Some(e)))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| DsmError::storage(format!("Dir entry error: {e}"), Some(e)))?
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("cpta") {
                continue;
            }

            #[cfg(target_os = "macos")]
            {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("p_") && name.ends_with(".cpta") {
                        let base32_part = &name[2..name.len() - 5];
                        if let Ok(anchor) = PolicyAnchor::from_base32(base32_part) {
                            anchors.push(anchor);
                        }
                    }
                }
            }

            #[cfg(all(unix, not(target_os = "macos")))]
            {
                use std::os::unix::ffi::OsStrExt;
                if let Some(stem) = path.file_stem() {
                    let raw = stem.as_bytes();
                    if let Some(anchor) = PolicyAnchor::from_path_component_bytes(raw) {
                        anchors.push(anchor);
                    }
                }
            }

            #[cfg(not(unix))]
            {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("p_") && name.ends_with(".cpta") {
                        let base32_part = &name[2..name.len() - 5];
                        if let Ok(anchor) = PolicyAnchor::from_base32(base32_part) {
                            anchors.push(anchor);
                        }
                    }
                }
            }
        }
        Ok(anchors)
    }
}
