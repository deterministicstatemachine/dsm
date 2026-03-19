//! DSM Code Generator Library
//!
//! Core library providing code generation capabilities for DSM vault and policy clients.
//! Supports multiple target languages with type-safe builders and compile-time safety.

pub mod base32;
pub mod compiler;
pub mod generators;
pub mod schema;

// Re-export commonly used types
pub use generators::*;
pub use schema::*;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Version information for generated code
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GENERATOR_NAME: &str = "dsm-gen";

/// Target programming languages
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize, JsonSchema,
)]
pub enum TargetLanguage {
    #[value(name = "typescript")]
    TypeScript,
    #[value(name = "kotlin")]
    Kotlin,
    #[value(name = "swift")]
    Swift,
    #[value(name = "rust")]
    Rust,
}

impl std::fmt::Display for TargetLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetLanguage::TypeScript => write!(f, "TypeScript"),
            TargetLanguage::Kotlin => write!(f, "Kotlin"),
            TargetLanguage::Swift => write!(f, "Swift"),
            TargetLanguage::Rust => write!(f, "Rust"),
        }
    }
}
