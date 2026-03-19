//! DSM Code Generator Library
//!
//! Core library providing code generation capabilities for DSM vault and policy clients.
//! Supports multiple target languages with type-safe builders and compile-time safety.

pub mod generators;
pub mod schema;

// Re-export commonly used types
pub use generators::*;
pub use schema::*;

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Version information for generated code
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GENERATOR_NAME: &str = "dsm-gen";

/// Configuration for code generation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GenerationConfig {
    pub include_factory: bool,
    pub include_test_vectors: bool,
    pub formatting: FormattingOptions,
    pub typescript: Option<TypeScriptOptions>,
    pub kotlin: Option<KotlinOptions>,
    pub swift: Option<SwiftOptions>,
    pub rust: Option<RustOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FormattingOptions {
    pub include_generation_marker: bool,
    pub include_hash: bool,
    pub line_endings: LineEndings,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum LineEndings {
    Unix,
    Windows,
    Native,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TypeScriptOptions {
    pub module_type: ModuleType,
    pub strict_null_checks: bool,
    pub use_readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum ModuleType {
    CommonJS,
    ES6,
    UMD,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct KotlinOptions {
    pub package_name: String,
    pub use_coroutines: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SwiftOptions {
    pub use_combine: bool,
    pub access_level: AccessLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum AccessLevel {
    Public,
    Internal,
    Private,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RustOptions {
    pub use_tokio: bool,
    pub serde_support: bool,
}

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

impl Default for GenerationConfig {
    fn default() -> Self {
        Self {
            include_factory: false,
            include_test_vectors: false,
            formatting: FormattingOptions {
                include_generation_marker: false,
                include_hash: true,
                line_endings: LineEndings::Native,
            },
            typescript: None,
            kotlin: None,
            swift: None,
            rust: None,
        }
    }
}

/// Generate code for a specific target language
pub fn generate_code(
    spec: &schema::DsmSpecification,
    target: TargetLanguage,
    config: GenerationConfig,
) -> Result<String> {
    let generator =
        generators::create_generator(target, config.include_factory, config.include_test_vectors);
    generator.generate(spec)
}
