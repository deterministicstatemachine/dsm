//! DSM Code Generator - One-click developer tooling for Vault & Policy Clients
//!
//! Per DSM Protocol Blueprint: mirrors Algorand's typed clients but targets
//! DSM's deterministic-state model for drag-and-drop ("dragon-drop")
//! Deterministic Limbo Vaults and Content-Addressed Token Policies.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use dsm_gen::TargetLanguage;
use std::fs;
use std::path::{Path, PathBuf};

// Import library modules as external crate
use dsm_gen::generators;
use dsm_gen::schema::DsmSpecification;

#[derive(Parser)]
#[command(name = "dsm-gen")]
#[command(about = "DSM Code Generator - One-click developer tooling for Vault & Policy Clients")]
#[command(long_about = "
Generate language-specific client code from DSM vault and policy specifications.
Supports TypeScript, Kotlin, Swift, and Rust with type-safe builders and 
compile-time safety.

Examples:
  dsm-gen client vault.yaml --lang ts --out ./dlv_client.ts
  dsm-gen client policy.yaml --lang kotlin,swift
  dsm-gen schema vault --output vault-schema.json
")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output directory (defaults to current directory)
    #[arg(short, long)]
    output_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate client code from specifications
    Client {
        /// Path to vault.yaml or policy.yaml specification
        spec_file: PathBuf,

        /// Target language(s) - comma-separated list
        #[arg(short, long, value_delimiter = ',')]
        lang: Vec<Language>,

        /// Output file path (optional - will auto-generate if not provided)
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Emit Factory class for multi-instance management
        #[arg(long)]
        factory: bool,

        /// Embed golden test vectors for CI
        #[arg(long)]
        test_vectors: bool,
    },

    /// Generate JSON schema for specifications
    Schema {
        /// Type of schema to generate
        #[arg(value_enum)]
        schema_type: SchemaType,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Initialize new DSM project structure
    Init {
        /// Project name
        name: String,
    },

    /// Validate specification files
    Validate {
        /// Path to specification file
        spec_file: PathBuf,
    },

    /// Compile specification to Base32 protobuf blob
    Compile {
        /// Path to vault.yaml or policy.yaml specification
        spec_file: PathBuf,

        /// Deployment mode (posted = storage nodes, local = bilateral)
        #[arg(long, value_enum, default_value = "posted")]
        mode: CompileMode,

        /// Policy anchor (Base32 Crockford, 32 bytes) to bind vault to
        #[arg(long)]
        policy_anchor: Option<String>,

        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum Language {
    #[value(name = "ts")]
    TypeScript,
    #[value(name = "kotlin")]
    Kotlin,
    #[value(name = "swift")]
    Swift,
    #[value(name = "rust")]
    Rust,
}

impl From<Language> for TargetLanguage {
    fn from(lang: Language) -> Self {
        match lang {
            Language::TypeScript => TargetLanguage::TypeScript,
            Language::Kotlin => TargetLanguage::Kotlin,
            Language::Swift => TargetLanguage::Swift,
            Language::Rust => TargetLanguage::Rust,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum CompileMode {
    Posted,
    Local,
}

#[derive(Debug, Clone, ValueEnum)]
enum SchemaType {
    #[value(name = "vault")]
    Vault,
    #[value(name = "policy")]
    Policy,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    match cli.command {
        Commands::Client {
            spec_file,
            lang,
            out,
            factory,
            test_vectors,
        } => {
            generate_client_code(spec_file, lang, out, factory, test_vectors, cli.output_dir)?;
        }

        Commands::Schema {
            schema_type,
            output,
        } => {
            generate_schema(schema_type, output, cli.output_dir)?;
        }

        Commands::Init { name } => {
            init_project(name, cli.output_dir)?;
        }

        Commands::Validate { spec_file } => {
            validate_specification(spec_file)?;
        }

        Commands::Compile {
            spec_file,
            mode,
            policy_anchor: _policy_anchor,
            output,
        } => {
            compile_specification(spec_file, mode, output, cli.output_dir)?;
        }
    }

    Ok(())
}

fn generate_client_code(
    spec_file: PathBuf,
    languages: Vec<Language>,
    output: Option<PathBuf>,
    factory: bool,
    test_vectors: bool,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    if languages.is_empty() {
        anyhow::bail!("No target language specified. Use --lang (ts|kotlin|swift|rust)");
    }

    println!("Generating client code from: {spec_file:?}");

    // Load and validate specification
    let content = fs::read_to_string(&spec_file)
        .with_context(|| format!("Failed to read specification file: {spec_file:?}"))?;

    let spec: DsmSpecification = if spec_file.extension().and_then(|s| s.to_str()) == Some("json") {
        serde_json::from_str(&content).with_context(|| "Failed to parse JSON specification")?
    } else {
        serde_yaml::from_str(&content).with_context(|| "Failed to parse YAML specification")?
    };

    // Generate code for each language
    for lang in languages {
        let target_lang = TargetLanguage::from(lang.clone());
        let generator = generators::create_generator(target_lang, factory, test_vectors);

        let generated_code = generator
            .generate(&spec)
            .with_context(|| format!("Failed to generate code for {lang:?}"))?;

        // Determine output path
        let output_path: PathBuf = if let Some(ref out) = output {
            out.clone()
        } else {
            let ext = generator.file_extension();

            let base_name = spec_file
                .file_stem()
                .unwrap_or_else(|| std::ffi::OsStr::new("generated"))
                .to_string_lossy();

            let filename = format!("{base_name}_client.{ext}");

            if let Some(ref dir) = output_dir {
                dir.join(filename)
            } else {
                PathBuf::from(filename)
            }
        };

        // Write generated code
        ensure_parent_dir(&output_path)?;
        fs::write(&output_path, &generated_code)
            .with_context(|| format!("Failed to write generated code to {output_path:?}"))?;

        let lang_name = generator.language_name();
        println!("Generated {lang_name} client: {output_path:?}");

        // Generate hash for reproducible builds
        let hash = blake3::hash(generated_code.as_bytes());
        let hex = hash.to_hex();
        println!("Code hash (Blake3): {hex}");
    }

    Ok(())
}

fn generate_schema(
    schema_type: SchemaType,
    output: Option<PathBuf>,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    use schemars::schema_for;

    println!("Generating {schema_type:?} schema");

    let schema = schema_for!(DsmSpecification);

    let output_path: PathBuf = if let Some(out) = output {
        out
    } else {
        let filename = format!(
            "{}-schema.json",
            match schema_type {
                SchemaType::Vault => "vault",
                SchemaType::Policy => "policy",
            }
        );

        if let Some(ref dir) = output_dir {
            dir.join(filename)
        } else {
            PathBuf::from(filename)
        }
    };

    let schema_json =
        serde_json::to_string_pretty(&schema).context("Failed to serialize schema")?;

    ensure_parent_dir(&output_path)?;
    fs::write(&output_path, schema_json)
        .with_context(|| format!("Failed to write schema to {output_path:?}"))?;

    println!("Generated schema: {output_path:?}");
    Ok(())
}

fn init_project(
    name: String,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    println!("Initializing DSM project: {name}");

    // Create project directory structure
    let project_dir = if let Some(ref dir) = output_dir {
        dir.join(&name)
    } else {
        PathBuf::from(&name)
    };
    std::fs::create_dir_all(&project_dir)
        .with_context(|| format!("Failed to create project directory: {}", name))?;

    // Create subdirectories
    let vaults_dir = project_dir.join("vaults");
    let policies_dir = project_dir.join("policies");
    let docs_dir = project_dir.join("docs");
    let ci_dir = project_dir.join("ci");

    std::fs::create_dir_all(&vaults_dir)?;
    std::fs::create_dir_all(&policies_dir)?;
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::create_dir_all(&ci_dir)?;

    // Create sample vault.yaml
    let vault_content = r#"type: "vault"
name: "SampleVault"
version: "1.0.0"
description: "A sample vault for DSM project"

fulfillment_condition:
  type: "multi_signature"
  public_keys: ["OWNERKEY1AAAAAAAAAAAAAAAAAAAAAAAAA", "OWNERKEY2AAAAAAAAAAAAAAAAAAAAAAAAA", "OWNERKEY3AAAAAAAAAAAAAAAAAAAAAAAAA"]
  threshold: 2

assets:
  - asset_id: "DSM"
    amount: 1000
    metadata:
      purpose: "sample_asset"
"#;
    std::fs::write(vaults_dir.join("sample-vault.yaml"), vault_content)?;

    // Create sample policy.yaml
    let policy_content = r#"type: "policy"
name: "SamplePolicy"
version: "1.0.0"
description: "Sample policy for DSM transfers"

rules:
  - name: "basic_transfer_check"
    condition:
      condition_type: "amount_limit"
      parameters:
        maxAmount: "1000"
        currency: "DSM"
    action:
      type: "allow"
    priority: 100

  - name: "multi_sig_approval"
    condition:
      condition_type: "signature_required"
      parameters:
        count: "2"
    action:
      type: "require_approval"
    priority: 50
"#;
    std::fs::write(policies_dir.join("sample-policy.yaml"), policy_content)?;

    // Create README.md
    let readme_content = format!(
        r#"# {name}

A DSM (Deterministic State Machine) project.

## Project Structure

- `vaults/` - Vault definitions and configurations
- `policies/` - Policy rules and compliance definitions
- `docs/` - Documentation and specifications
- `ci/` - CI/CD configuration files

## Getting Started

1. Edit the sample vault and policy files in their respective directories
2. Use `dsm-gen` to generate code from your YAML definitions
3. Deploy and test your DSM contracts

## Commands

- Validate a vault: `dsm-gen validate vaults/sample-vault.yaml`
- Validate a policy: `dsm-gen validate policies/sample-policy.yaml`
- Generate a TypeScript client: `dsm-gen client vaults/sample-vault.yaml --lang ts --out src/sample-vault-client.ts`
- Export the JSON schema: `dsm-gen schema vault --output docs/vault-schema.json`
"#
    );
    std::fs::write(project_dir.join("README.md"), readme_content)?;

    // Create .gitignore
    let gitignore_content = r#"# Build artifacts
target/
*.o
*.so
*.dylib

# IDE files
.vscode/
.idea/
*.swp
*.swo

# OS files
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Temporary files
*.tmp
tmp/
"#;
    std::fs::write(project_dir.join(".gitignore"), gitignore_content)?;

    println!("✅ Project '{name}' initialized successfully!");
    println!("📁 Created directories: vaults/, policies/, docs/, ci/");
    println!("📄 Created sample files: sample-vault.yaml, sample-policy.yaml");
    println!("📖 Created README.md and .gitignore");
    println!("\nNext steps:");
    println!("  cd {}", name);
    println!("  # Edit the sample files in vaults/ and policies/");
    println!("  # Run: dsm-gen validate vaults/sample-vault.yaml");
    println!(
        "  # Run: dsm-gen client vaults/sample-vault.yaml --lang ts --out src/sample-vault-client.ts"
    );

    Ok(())
}

fn validate_specification(spec_file: PathBuf) -> Result<()> {
    println!("Validating specification: {spec_file:?}");

    let content = fs::read_to_string(&spec_file)
        .with_context(|| format!("Failed to read specification file: {spec_file:?}"))?;

    let spec: DsmSpecification = if spec_file.extension().and_then(|s| s.to_str()) == Some("json") {
        serde_json::from_str(&content).with_context(|| "Failed to parse JSON specification")?
    } else {
        serde_yaml::from_str(&content).with_context(|| "Failed to parse YAML specification")?
    };

    let mut errors: Vec<String> = Vec::new();

    match &spec {
        DsmSpecification::Vault(vault) => {
            println!("  Type: Vault");
            println!("  Name: {}", vault.name);
            println!("  Version: {}", vault.version);

            if vault.assets.is_empty() {
                errors.push("Vault must have at least one asset".into());
            }
            for asset in &vault.assets {
                if asset.amount == 0 {
                    errors.push(format!("Asset '{}': amount must be > 0", asset.asset_id));
                }
            }
            validate_fulfillment_condition(&vault.fulfillment_condition, &mut errors);
        }
        DsmSpecification::Policy(policy) => {
            println!("  Type: Policy");
            println!("  Name: {}", policy.name);
            println!("  Version: {}", policy.version);

            if policy.rules.is_empty() {
                errors.push("Policy must have at least one rule".into());
            }
            let mut seen_names = std::collections::HashSet::new();
            for rule in &policy.rules {
                if !seen_names.insert(&rule.name) {
                    errors.push(format!("Duplicate rule name: '{}'", rule.name));
                }
            }
        }
    }

    if errors.is_empty() {
        println!("✓ Specification is valid: {spec_file:?}");
        Ok(())
    } else {
        for e in &errors {
            eprintln!("  ✗ {e}");
        }
        anyhow::bail!(
            "Specification has {} validation error(s)",
            errors.len()
        )
    }
}

fn compile_specification(
    spec_file: PathBuf,
    mode: CompileMode,
    output: Option<PathBuf>,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    let content = fs::read_to_string(&spec_file)
        .with_context(|| format!("Failed to read specification file: {spec_file:?}"))?;

    let spec: DsmSpecification = if spec_file.extension().and_then(|s| s.to_str()) == Some("json") {
        serde_json::from_str(&content).with_context(|| "Failed to parse JSON specification")?
    } else {
        serde_yaml::from_str(&content).with_context(|| "Failed to parse YAML specification")?
    };

    let mode_override = Some(match mode {
        CompileMode::Posted => dsm_gen::schema::DeploymentMode::Posted,
        CompileMode::Local => dsm_gen::schema::DeploymentMode::Local,
    });

    let blob = dsm_gen::compiler::compile(&spec, mode_override)
        .with_context(|| "Compilation failed")?;

    // Output
    if let Some(out_path) = output.or_else(|| output_dir.map(|d| {
        let stem = spec_file.file_stem().unwrap_or_default().to_string_lossy();
        d.join(format!("{stem}.b32"))
    })) {
        ensure_parent_dir(&out_path)?;
        fs::write(&out_path, &blob.base32)
            .with_context(|| format!("Failed to write blob to {out_path:?}"))?;
        eprintln!("Compiled {} blob: {out_path:?}", blob.artifact_type);
    } else {
        // stdout
        println!("{}", blob.base32);
    }

    let hash_hex = blake3::Hash::from(blob.hash).to_hex();
    eprintln!("Blob hash (BLAKE3): {hash_hex}");
    eprintln!("Blob size: {} bytes ({} Base32 chars)", blob.bytes.len(), blob.base32.len());

    Ok(())
}

fn validate_fulfillment_condition(
    cond: &dsm_gen::schema::FulfillmentConditionSpec,
    errors: &mut Vec<String>,
) {
    use dsm_gen::schema::FulfillmentConditionSpec;
    match cond {
        FulfillmentConditionSpec::MultiSignature(ms) => {
            if ms.threshold == 0 {
                errors.push("MultiSignature: threshold must be > 0".into());
            }
            if ms.public_keys.is_empty() {
                errors.push("MultiSignature: public_keys must not be empty".into());
            }
            if ms.threshold as usize > ms.public_keys.len() {
                errors.push(format!(
                    "MultiSignature: threshold ({}) exceeds number of keys ({})",
                    ms.threshold,
                    ms.public_keys.len()
                ));
            }
        }
        FulfillmentConditionSpec::BitcoinHtlc(h) => {
            if h.min_confirmations == 0 {
                errors.push("BitcoinHtlc: min_confirmations must be > 0".into());
            }
        }
        FulfillmentConditionSpec::And(a) => {
            if a.conditions.is_empty() {
                errors.push("And: conditions must not be empty".into());
            }
            for c in &a.conditions {
                validate_fulfillment_condition(c, errors);
            }
        }
        FulfillmentConditionSpec::Or(o) => {
            if o.conditions.is_empty() {
                errors.push("Or: conditions must not be empty".into());
            }
            for c in &o.conditions {
                validate_fulfillment_condition(c, errors);
            }
        }
        _ => {}
    }
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create output directory: {parent:?}"))?;
    }

    Ok(())
}
