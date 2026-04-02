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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_anchor(byte: u8) -> PolicyAnchor {
        PolicyAnchor::from_bytes([byte; 32])
    }

    // ── Constructor ────────────────────────────────────────────────

    #[test]
    fn new_creates_instance() {
        let p = FsPolicyPersistence::new();
        assert!(p.base_dir.ends_with("policies"));
    }

    #[test]
    fn default_creates_instance() {
        let p = FsPolicyPersistence::default();
        assert!(p.base_dir.ends_with("policies"));
    }

    // ── get_policy_path ────────────────────────────────────────────

    #[test]
    fn policy_path_ends_with_cpta() {
        let p = FsPolicyPersistence::new();
        let anchor = make_anchor(0x42);
        let path = p.get_policy_path(&anchor);
        assert!(
            path.to_string_lossy().ends_with(".cpta"),
            "path should have .cpta extension: {:?}",
            path
        );
    }

    #[test]
    fn policy_path_deterministic() {
        let p = FsPolicyPersistence::new();
        let anchor = make_anchor(0xAB);
        let p1 = p.get_policy_path(&anchor);
        let p2 = p.get_policy_path(&anchor);
        assert_eq!(p1, p2);
    }

    #[test]
    fn policy_path_differs_for_different_anchors() {
        let p = FsPolicyPersistence::new();
        let a1 = make_anchor(0x01);
        let a2 = make_anchor(0x02);
        assert_ne!(p.get_policy_path(&a1), p.get_policy_path(&a2));
    }

    #[test]
    fn policy_path_is_under_base_dir() {
        let p = FsPolicyPersistence::new();
        let anchor = make_anchor(0xFF);
        let path = p.get_policy_path(&anchor);
        assert!(
            path.starts_with(&p.base_dir),
            "path {:?} must be under {:?}",
            path,
            p.base_dir
        );
    }

    // ── Async CRUD (uses temp dir) ─────────────────────────────────

    #[tokio::test]
    async fn write_and_read_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };
        let anchor = make_anchor(0xAA);
        let data = b"policy-content-bytes";

        p.write(&anchor, data).await.unwrap();
        let read_back = p.read(&anchor).await.unwrap();
        assert_eq!(read_back, data);
    }

    #[tokio::test]
    async fn read_missing_returns_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };
        let anchor = make_anchor(0xBB);
        let err = p.read(&anchor).await.unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("not_found") || msg.contains("NotFound") || msg.contains("No policy"),
            "expected not-found error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn delete_removes_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };
        let anchor = make_anchor(0xCC);

        p.write(&anchor, b"data").await.unwrap();
        assert!(p.read(&anchor).await.is_ok());

        p.delete(&anchor).await.unwrap();
        assert!(p.read(&anchor).await.is_err());
    }

    #[tokio::test]
    async fn delete_missing_is_ok() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };
        p.delete(&make_anchor(0xDD)).await.unwrap();
    }

    #[tokio::test]
    async fn list_anchors_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };
        let anchors = p.list_anchors().await.unwrap();
        assert!(anchors.is_empty());
    }

    #[tokio::test]
    async fn list_anchors_after_writes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };

        let a1 = make_anchor(0x01);
        let a2 = make_anchor(0x02);
        p.write(&a1, b"p1").await.unwrap();
        p.write(&a2, b"p2").await.unwrap();

        let anchors = p.list_anchors().await.unwrap();
        assert_eq!(anchors.len(), 2);
    }

    #[tokio::test]
    async fn list_anchors_ignores_non_cpta_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };

        tokio::fs::write(tmp.path().join("noise.txt"), b"not a policy")
            .await
            .unwrap();

        let a = make_anchor(0x10);
        p.write(&a, b"data").await.unwrap();

        let anchors = p.list_anchors().await.unwrap();
        assert_eq!(anchors.len(), 1);
    }

    #[tokio::test]
    async fn write_overwrite() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };
        let anchor = make_anchor(0xEE);

        p.write(&anchor, b"v1").await.unwrap();
        p.write(&anchor, b"v2").await.unwrap();

        let data = p.read(&anchor).await.unwrap();
        assert_eq!(data, b"v2");
    }

    // ── Debug trait ────────────────────────────────────────────────

    #[test]
    fn debug_format() {
        let p = FsPolicyPersistence::new();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("FsPolicyPersistence"));
        assert!(dbg.contains("base_dir"));
    }

    // ── write empty data ───────────────────────────────────────────

    #[tokio::test]
    async fn write_and_read_empty_data() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };
        let anchor = make_anchor(0xFE);
        p.write(&anchor, b"").await.unwrap();
        let data = p.read(&anchor).await.unwrap();
        assert!(data.is_empty());
    }

    // ── write large data ───────────────────────────────────────────

    #[tokio::test]
    async fn write_and_read_large_data() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };
        let anchor = make_anchor(0xFD);
        let big = vec![0xABu8; 64 * 1024];
        p.write(&anchor, &big).await.unwrap();
        let data = p.read(&anchor).await.unwrap();
        assert_eq!(data, big);
    }

    // ── delete then list ───────────────────────────────────────────

    #[tokio::test]
    async fn delete_removes_from_list() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };

        let a1 = make_anchor(0x11);
        let a2 = make_anchor(0x22);
        p.write(&a1, b"d1").await.unwrap();
        p.write(&a2, b"d2").await.unwrap();
        assert_eq!(p.list_anchors().await.unwrap().len(), 2);

        p.delete(&a1).await.unwrap();
        assert_eq!(p.list_anchors().await.unwrap().len(), 1);
    }

    // ── different anchors get different paths ──────────────────────

    #[test]
    fn all_byte_values_produce_valid_paths() {
        let p = FsPolicyPersistence::new();
        for b in [0x00u8, 0x01, 0x2F, 0x5C, 0x7F, 0x80, 0xFE, 0xFF] {
            let anchor = make_anchor(b);
            let path = p.get_policy_path(&anchor);
            assert!(
                path.to_string_lossy().ends_with(".cpta"),
                "byte {b:#04X} must produce valid .cpta path: {path:?}"
            );
        }
    }

    // ── custom base_dir ────────────────────────────────────────────

    #[test]
    fn custom_base_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = FsPolicyPersistence {
            base_dir: tmp.path().to_path_buf(),
        };
        assert_eq!(p.base_dir, tmp.path());
    }
}
