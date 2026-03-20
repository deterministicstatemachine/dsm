//! Code generators for different target languages
//!
//! Each generator implements language-specific code generation from DSM specifications.

use crate::schema::{DsmSpecification, PolicySpecification, VaultSpecification};
use crate::TargetLanguage;
use anyhow::Result;

pub mod kotlin;
pub mod rust_gen;
pub mod swift;
pub mod typescript;

pub use kotlin::KotlinGenerator;
pub use rust_gen::RustGenerator;
pub use swift::SwiftGenerator;
pub use typescript::TypeScriptGenerator;

/// Common trait for all code generators
pub trait CodeGenerator {
    /// Generate code from a DSM specification
    fn generate(&self, spec: &DsmSpecification) -> Result<String>;

    /// Get the file extension for generated files
    fn file_extension(&self) -> &'static str;

    /// Get the language name
    fn language_name(&self) -> &'static str;
}

/// Create a generator for the specified target language
pub fn create_generator(
    target: TargetLanguage,
    include_factory: bool,
    include_test_vectors: bool,
) -> Box<dyn CodeGenerator> {
    match target {
        TargetLanguage::TypeScript => Box::new(typescript::TypeScriptGenerator::new(
            include_factory,
            include_test_vectors,
        )),
        TargetLanguage::Kotlin => Box::new(kotlin::KotlinGenerator::new(
            include_factory,
            include_test_vectors,
        )),
        TargetLanguage::Swift => Box::new(swift::SwiftGenerator::new(
            include_factory,
            include_test_vectors,
        )),
        TargetLanguage::Rust => Box::new(rust_gen::RustGenerator::new(
            include_factory,
            include_test_vectors,
        )),
    }
}

/// Sanitize a spec name into a valid identifier across all target languages.
/// Non-alphanumeric characters become `_` (consistent across TS/Kotlin/Swift/Rust).
pub fn sanitize_identifier(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "Vault".to_string()
    } else {
        sanitized
    }
}

/// Extract the base name from a vault spec, stripping the "Vault" suffix if present.
pub fn base_vault_name(spec: &VaultSpecification) -> String {
    let sanitized = sanitize_identifier(&spec.name);
    let suffix = "vault";
    if sanitized.len() >= suffix.len() && sanitized.to_lowercase().ends_with(suffix) {
        sanitized[..sanitized.len() - suffix.len()].to_string()
    } else {
        sanitized
    }
}

/// Extract the base name from a policy spec, stripping the "Policy" suffix if present.
pub fn base_policy_name(spec: &PolicySpecification) -> String {
    let sanitized = sanitize_identifier(&spec.name);
    let suffix = "policy";
    if sanitized.len() >= suffix.len() && sanitized.to_lowercase().ends_with(suffix) {
        sanitized[..sanitized.len() - suffix.len()].to_string()
    } else {
        sanitized
    }
}
