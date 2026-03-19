//! Code generators for different target languages
//!
//! Each generator implements language-specific code generation from DSM specifications.

use crate::schema::DsmSpecification;
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
