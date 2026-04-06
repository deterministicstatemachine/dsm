
# ---------------------------------------------------------------------------
# DSM Protocol — Makefile
# All developer tasks run through here. Bash scripts in scripts/ are
# implementation details; this file is the only documented entrypoint.
#
# Usage:
#   make help         — list all targets
#   make menu         — interactive launcher for common tasks
#   make doctor       — check local prerequisites without changing files
#   make setup        — first-time onboarding
#   make build        — Rust workspace build
#   make nodes-up     — start local storage nodes
#   make android      — build debug APK (includes native libs)
#   make install      — build + install APK on all connected adb devices
#   make test         — Rust + frontend tests
#   make clean        — wipe all build artifacts
#
# Windows developers: use scripts/dev.ps1 instead of this Makefile.
#   .\scripts\dev.ps1 help
# Android builds on Windows require WSL2 — see docs/book/03-development-setup.md#windows-setup.
# ---------------------------------------------------------------------------

# Prefer homebrew bash (4+) for associative arrays used by SBOM scripts.
# Fall back to system bash if homebrew isn't installed.
SHELL := $(shell command -v /opt/homebrew/bin/bash 2>/dev/null || echo /bin/bash)
REPO_ROOT := $(shell cd "$(dir $(abspath $(lastword $(MAKEFILE_LIST))))" && pwd)
ANDROID_DIR := $(REPO_ROOT)/dsm_client/android
NDK_DIR := $(REPO_ROOT)/dsm_client/deterministic_state_machine
FRONTEND_DIR := $(REPO_ROOT)/dsm_client/frontend
STORAGE_NODE_DIR := $(REPO_ROOT)/dsm_storage_node
JNILIBS_DIR := $(ANDROID_DIR)/app/src/main/jniLibs
REPO_JNILIBS_DIR := $(NDK_DIR)/jniLibs
CARGO_CONFIG := $(NDK_DIR)/dsm_sdk/.cargo/config.toml
CARGO_CONFIG_TEMPLATE := $(NDK_DIR)/dsm_sdk/.cargo/config.toml.template
ANDROID_LOCAL_PROPERTIES := $(ANDROID_DIR)/local.properties
RUST_TOOLCHAIN_FILE := $(REPO_ROOT)/rust-toolchain.toml
ANDROID_APP_GRADLE := $(ANDROID_DIR)/app/build.gradle.kts

.DEFAULT_GOAL := help

.PHONY: menu
menu: ## Interactive launcher for common developer tasks
	@bash -lc 'set -e; \
		options=(setup doctor build frontend android install test lint nodes-up nodes-down nodes-status clean quit); \
		PS3="Select DSM task: "; \
		select opt in "$${options[@]}"; do \
			case "$$opt" in \
				quit) exit 0 ;; \
				"") echo "Invalid selection" ;; \
				*) $(MAKE) "$$opt"; break ;; \
			esac; \
		done'

.PHONY: help
help: ## Show this help
	@echo ""
	@echo "DSM Protocol — available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ---------------------------------------------------------------------------
# SETUP
# ---------------------------------------------------------------------------

.PHONY: doctor
doctor: ## Check local prerequisites and repo state without changing files
	@echo "==> DSM doctor"
	@PINNED_RUST="$$(sed -n 's/^channel = \"\([^\"]*\)\".*/\1/p' "$(RUST_TOOLCHAIN_FILE)" | head -1)"; \
	command -v cargo >/dev/null 2>&1 && echo "    cargo: $$(cargo --version)" || echo "    MISSING: cargo (install from https://rustup.rs)"; \
	command -v rustc >/dev/null 2>&1 && echo "    rustc: $$(rustc --version)" || echo "    MISSING: rustc (install from https://rustup.rs)"; \
	[ -n "$$PINNED_RUST" ] && echo "    rust toolchain pin: $$PINNED_RUST ($(notdir $(RUST_TOOLCHAIN_FILE)))" || true
	@command -v rustfmt >/dev/null 2>&1 && echo "    rustfmt: installed" || echo "    MISSING: rustfmt (run: rustup component add rustfmt)"
	@command -v cargo-clippy >/dev/null 2>&1 && echo "    clippy: installed" || echo "    MISSING: clippy (run: rustup component add clippy)"
	@command -v protoc >/dev/null 2>&1 && echo "    protoc: $$(protoc --version)" || echo "    MISSING: protoc"
	@command -v node >/dev/null 2>&1 && echo "    node: $$(node --version)" || echo "    MISSING: node"
	@command -v npm >/dev/null 2>&1 && echo "    npm: $$(npm --version)" || echo "    MISSING: npm"
	@BASH_VER=$$(bash --version | head -1 | sed 's/.*version \([0-9]*\).*/\1/'); \
	if [ "$$BASH_VER" -ge 4 ] 2>/dev/null; then \
		echo "    bash: version $$BASH_VER (OK)"; \
	else \
		echo "    bash: version $$BASH_VER (SBOM scripts need bash 4+; brew install bash)"; \
	fi
	@command -v adb >/dev/null 2>&1 && echo "    adb: available" || echo "    adb: optional (needed only for device install/debug)"
	@command -v psql >/dev/null 2>&1 && echo "    psql: available" || echo "    psql: optional until you run local storage nodes"
	@command -v java >/dev/null 2>&1 && echo "    java: $$(java -version 2>&1 | head -1)" || echo "    java: optional until Android builds"
	@command -v cargo-ndk >/dev/null 2>&1 && echo "    cargo-ndk: $$(cargo ndk --version)" || echo "    cargo-ndk: optional until Android builds (install via cargo install cargo-ndk)"
	@GRADLE_NDK_VERSION="$$(sed -n 's/.*ndkVersion = \"\([^\"]*\)\".*/\1/p' "$(ANDROID_APP_GRADLE)" | head -1)"; \
	NDK=""; \
	NDK_SOURCE=""; \
	NDK_VERSION=""; \
	HOST_TAG=""; \
	if [ -n "$$ANDROID_NDK_HOME" ]; then \
		NDK="$$ANDROID_NDK_HOME"; \
		NDK_SOURCE="ANDROID_NDK_HOME"; \
	elif [ -n "$$ANDROID_NDK_ROOT" ]; then \
		NDK="$$ANDROID_NDK_ROOT"; \
		NDK_SOURCE="ANDROID_NDK_ROOT"; \
	fi; \
	if [ -n "$$NDK" ]; then \
		if [ -d "$$NDK" ]; then \
			NDK_VERSION="$$(basename "$$NDK")"; \
			HOST_TAG="$$(ls "$$NDK/toolchains/llvm/prebuilt" 2>/dev/null | head -1)"; \
			echo "    android ndk: $$NDK_SOURCE -> $$NDK"; \
			echo "    android ndk version: $$NDK_VERSION"; \
			[ -n "$$HOST_TAG" ] && echo "    android ndk host tag: $$HOST_TAG" || echo "    android ndk host tag: unresolved"; \
		else \
			echo "    android ndk: $$NDK_SOURCE points to missing directory ($$NDK)"; \
		fi; \
	else \
		echo "    android ndk: not configured (run make setup before Android builds)"; \
	fi; \
	[ -n "$$GRADLE_NDK_VERSION" ] && echo "    gradle ndkVersion: $$GRADLE_NDK_VERSION" || true; \
	if [ -n "$$NDK_VERSION" ] && [ -n "$$GRADLE_NDK_VERSION" ] && [ "$$NDK_VERSION" != "$$GRADLE_NDK_VERSION" ]; then \
		echo "    WARNING: configured NDK version ($$NDK_VERSION) does not match Gradle ndkVersion ($$GRADLE_NDK_VERSION)"; \
	fi
	@SDK=""; \
	SDK_SOURCE=""; \
	if [ -n "$$ANDROID_HOME" ] && [ -d "$$ANDROID_HOME" ]; then \
		SDK="$$ANDROID_HOME"; \
		SDK_SOURCE="ANDROID_HOME"; \
	elif [ -n "$$ANDROID_SDK_ROOT" ] && [ -d "$$ANDROID_SDK_ROOT" ]; then \
		SDK="$$ANDROID_SDK_ROOT"; \
		SDK_SOURCE="ANDROID_SDK_ROOT"; \
	elif [ -f "$(ANDROID_LOCAL_PROPERTIES)" ]; then \
		SDK="$$(sed -n 's/^sdk.dir=//p' "$(ANDROID_LOCAL_PROPERTIES)" | tail -1 | sed 's/\\\\/\\/g; s/\\:/:/g; s/\\ / /g')"; \
		SDK_SOURCE="local.properties"; \
	fi; \
	if [ -n "$$SDK" ] && [ -d "$$SDK" ]; then \
		echo "    android sdk: configured via $$SDK_SOURCE"; \
	else \
		echo "    android sdk: not configured (make setup will try to detect it)"; \
	fi
	@if [ -d "$(FRONTEND_DIR)/node_modules" ]; then \
		echo "    frontend deps: present"; \
	else \
		echo "    frontend deps: missing (run make setup)"; \
	fi
	@CURRENT_NDK="$${ANDROID_NDK_HOME:-$$ANDROID_NDK_ROOT}"; \
	if [ -f "$(CARGO_CONFIG)" ]; then \
		CFG_NDK="$$(sed -n 's/^ANDROID_NDK_ROOT = { value = \"\([^\"]*\)\",.*/\1/p' "$(CARGO_CONFIG)" | head -1)"; \
		CFG_VERSION=""; \
		CFG_HOST_TAG="$$(sed -n 's|.*toolchains/llvm/prebuilt/\([^/]*\)/bin/.*|\1|p' "$(CARGO_CONFIG)" | head -1)"; \
		[ -n "$$CFG_NDK" ] && CFG_VERSION="$$(basename "$$CFG_NDK")"; \
		echo "    android cargo config: present"; \
		[ -n "$$CFG_NDK" ] && echo "      ndk root: $$CFG_NDK" || true; \
		[ -n "$$CFG_VERSION" ] && echo "      ndk version: $$CFG_VERSION" || true; \
		[ -n "$$CFG_HOST_TAG" ] && echo "      host tag: $$CFG_HOST_TAG" || true; \
		if [ -n "$$CURRENT_NDK" ] && [ -n "$$CFG_NDK" ] && [ "$$CFG_NDK" != "$$CURRENT_NDK" ]; then \
			echo "    WARNING: .cargo/config.toml NDK root differs from the current environment"; \
		fi; \
	else \
		echo "    android cargo config: missing (run make setup)"; \
	fi

.PHONY: android-sdk-config
android-sdk-config: ## Detect Android SDK and write ignored local.properties for Gradle
	@SDK=""; \
	if [ -n "$$ANDROID_HOME" ] && [ -d "$$ANDROID_HOME" ]; then \
		SDK="$$ANDROID_HOME"; \
	elif [ -n "$$ANDROID_SDK_ROOT" ] && [ -d "$$ANDROID_SDK_ROOT" ]; then \
		SDK="$$ANDROID_SDK_ROOT"; \
	elif [ -d "$$HOME/Library/Android/sdk" ]; then \
		SDK="$$HOME/Library/Android/sdk"; \
	elif [ -d "$$HOME/Android/sdk" ]; then \
		SDK="$$HOME/Android/sdk"; \
	fi; \
	if [ -z "$$SDK" ]; then \
		echo "WARNING: Android SDK not found. Set ANDROID_HOME or ANDROID_SDK_ROOT, or install the SDK in a standard location."; \
		exit 0; \
	fi; \
	ESCAPED_SDK="$$SDK"; \
	ESCAPED_SDK="$${ESCAPED_SDK//\\/\\\\}"; \
	ESCAPED_SDK="$${ESCAPED_SDK//:/\\:}"; \
	ESCAPED_SDK="$${ESCAPED_SDK// /\\ }"; \
	mkdir -p "$(ANDROID_DIR)"; \
	printf 'sdk.dir=%s\n' "$$ESCAPED_SDK" > "$(ANDROID_LOCAL_PROPERTIES)"; \
	echo "    Android SDK configured for Gradle (local.properties updated)"

.PHONY: setup
setup: ## First-time developer setup: check deps, auto-configure Android, install frontend deps
	@echo "==> Checking prerequisites..."
	@PINNED_RUST="$$(sed -n 's/^channel = \"\([^\"]*\)\".*/\1/p' "$(RUST_TOOLCHAIN_FILE)" | head -1)"; \
	[ -n "$$PINNED_RUST" ] && echo "==> Rust toolchain pin: $$PINNED_RUST ($(notdir $(RUST_TOOLCHAIN_FILE)))" || true
	@command -v cargo >/dev/null 2>&1 || { echo "ERROR: Rust/cargo not found. Install from https://rustup.rs"; exit 1; }
	@command -v rustc >/dev/null 2>&1 || { echo "ERROR: rustc not found. Install from https://rustup.rs"; exit 1; }
	@echo "    cargo: $$(cargo --version)"
	@echo "    rustc: $$(rustc --version)"
	@command -v npm >/dev/null 2>&1 || { echo "ERROR: npm not found. Install Node.js 20+"; exit 1; }
	@command -v protoc >/dev/null 2>&1 || { echo "ERROR: protoc not found. Install protobuf compiler"; exit 1; }
	@command -v adb >/dev/null 2>&1 || echo "WARNING: adb not found — install Android Platform Tools for device installs"
	@$(MAKE) android-sdk-config
	@GRADLE_NDK_VERSION="$$(sed -n 's/.*ndkVersion = \"\([^\"]*\)\".*/\1/p' "$(ANDROID_APP_GRADLE)" | head -1)"; \
	if [ -z "$$ANDROID_NDK_HOME" ] && [ -z "$$ANDROID_NDK_ROOT" ]; then \
		echo "WARNING: ANDROID_NDK_HOME is not set — skipping Android cargo config generation."; \
		echo "  Set it later and re-run 'make setup' before Android builds."; \
	else \
		NDK="$${ANDROID_NDK_HOME:-$$ANDROID_NDK_ROOT}"; \
		[ -d "$$NDK" ] || { echo "ERROR: configured Android NDK path does not exist: $$NDK"; exit 1; }; \
		HOST_TAG="$$(ls "$$NDK/toolchains/llvm/prebuilt" 2>/dev/null | head -1)"; \
		[ -n "$$HOST_TAG" ] || { echo "ERROR: could not detect Android NDK host tag under $$NDK/toolchains/llvm/prebuilt"; exit 1; }; \
		NDK_VERSION="$$(basename "$$NDK")"; \
		echo "==> Android NDK resolved: $$NDK"; \
		echo "    version: $$NDK_VERSION"; \
		echo "    host tag: $$HOST_TAG"; \
		[ -n "$$GRADLE_NDK_VERSION" ] && echo "    gradle ndkVersion: $$GRADLE_NDK_VERSION" || true; \
		if [ -n "$$GRADLE_NDK_VERSION" ] && [ "$$NDK_VERSION" != "$$GRADLE_NDK_VERSION" ]; then \
			echo "WARNING: configured NDK version ($$NDK_VERSION) does not match Gradle ndkVersion ($$GRADLE_NDK_VERSION)."; \
		fi; \
		command -v cargo-ndk >/dev/null 2>&1 || { echo "Installing cargo-ndk..."; cargo install cargo-ndk; }; \
		echo "    cargo-ndk: $$(cargo ndk --version)"; \
		mkdir -p "$$(dirname "$(CARGO_CONFIG)")"; \
		echo "==> Refreshing dsm_client/deterministic_state_machine/dsm_sdk/.cargo/config.toml from template..."; \
		sed \
			-e "s|__NDK_ROOT__|$$NDK|g" \
			-e "s|__NDK_HOST_TAG__|$$HOST_TAG|g" \
			$(CARGO_CONFIG_TEMPLATE) > "$(CARGO_CONFIG).tmp"; \
		mv "$(CARGO_CONFIG).tmp" "$(CARGO_CONFIG)"; \
		echo "    Refreshed: dsm_client/deterministic_state_machine/dsm_sdk/.cargo/config.toml"; \
		echo "    Configured NDK root: $$NDK"; \
		echo "    Configured NDK host tag: $$HOST_TAG"; \
	fi
	@if [ ! -d "$(FRONTEND_DIR)/node_modules" ]; then \
		echo "==> Installing frontend dependencies..."; \
		cd $(FRONTEND_DIR) && \
			[ -s $$HOME/.nvm/nvm.sh ] && . $$HOME/.nvm/nvm.sh; \
			nvm use --silent 2>/dev/null || true; \
			npm ci; \
	else \
		echo "    Frontend dependencies already installed — skipping npm ci"; \
	fi
	@echo "==> Setup complete."

# ---------------------------------------------------------------------------
# BUILD
# ---------------------------------------------------------------------------

.PHONY: build
build: ## Build the full Rust workspace
	cargo build --locked --workspace --all-features

.PHONY: build-release
build-release: ## Build Rust workspace in release mode
	cargo build --locked --workspace --all-features --release

.PHONY: android-libs
android-libs: ## Build native .so libs for all Android ABIs (requires NDK)
	@echo "==> Building Android native libs..."
	@rm -f $(JNILIBS_DIR)/arm64-v8a/libdsm_sdk.so \
	        $(JNILIBS_DIR)/armeabi-v7a/libdsm_sdk.so \
	        $(JNILIBS_DIR)/x86_64/libdsm_sdk.so \
	        $(REPO_JNILIBS_DIR)/arm64-v8a/libdsm_sdk.so \
	        $(REPO_JNILIBS_DIR)/armeabi-v7a/libdsm_sdk.so \
	        $(REPO_JNILIBS_DIR)/x86_64/libdsm_sdk.so
	@mkdir -p $(REPO_JNILIBS_DIR)/arm64-v8a \
	          $(REPO_JNILIBS_DIR)/armeabi-v7a \
	          $(REPO_JNILIBS_DIR)/x86_64
	cd $(NDK_DIR) && \
		DSM_PROTO_ROOT=$(REPO_ROOT)/proto \
		cargo ndk \
			-t arm64-v8a -t armeabi-v7a -t x86_64 \
			-o $(JNILIBS_DIR) \
			--platform 23 \
			build --release --package dsm_sdk --features=jni,bluetooth
	@cp $(NDK_DIR)/target/aarch64-linux-android/release/libdsm_sdk.so $(REPO_JNILIBS_DIR)/arm64-v8a/
	@cp $(NDK_DIR)/target/armv7-linux-androideabi/release/libdsm_sdk.so $(REPO_JNILIBS_DIR)/armeabi-v7a/
	@cp $(NDK_DIR)/target/x86_64-linux-android/release/libdsm_sdk.so $(REPO_JNILIBS_DIR)/x86_64/
	@echo "==> Native libs built."

.PHONY: frontend
frontend: ## Build the React frontend (copies assets into Android)
	@echo "==> Building fresh frontend bundle and deploying assets into Android..."
	cd $(FRONTEND_DIR) && \
		[ -s $$HOME/.nvm/nvm.sh ] && . $$HOME/.nvm/nvm.sh; \
		nvm use --silent 2>/dev/null || true; \
		npm run build:full-deploy
	@echo "==> Frontend built."

.PHONY: android
android: android-sdk-config android-libs frontend ## Build fresh debug APK (native libs + frontend + clean gradle)
	@echo "==> Assembling fresh Android debug APK..."
	cd $(ANDROID_DIR) && ./gradlew clean :app:assembleDebug --no-daemon --console=plain
	@echo "==> APK: $(ANDROID_DIR)/app/build/outputs/apk/debug/app-debug.apk"

.PHONY: android-release
android-release: android-sdk-config android-libs frontend ## Build fresh release APK
	@echo "==> Assembling fresh Android release APK..."
	cd $(ANDROID_DIR) && ./gradlew clean :app:assembleRelease --no-daemon --console=plain
	@echo "==> APK: $(ANDROID_DIR)/app/build/outputs/apk/release/app-release.apk"

# ---------------------------------------------------------------------------
# INSTALL
# ---------------------------------------------------------------------------

.PHONY: install
install: android ## Build debug APK and install on all connected adb devices
	@echo "==> Installing on connected devices..."
	@bash $(REPO_ROOT)/scripts/install_apk_connected_devices.sh

.PHONY: install-only
install-only: ## Install existing APK without rebuilding (fast iteration)
	@bash $(REPO_ROOT)/scripts/install_apk_connected_devices.sh

# ---------------------------------------------------------------------------
# TEST
# ---------------------------------------------------------------------------

.PHONY: test
test: ## Run Rust workspace tests + frontend jest tests
	@echo "==> Running Rust tests..."
	cargo test --workspace --exclude dsm_storage_node -- --nocapture
	cargo test -p dsm_storage_node --no-default-features --features local-dev,strict -- --nocapture
	@echo "==> Running frontend tests..."
	cd $(FRONTEND_DIR) && \
		[ -s $$HOME/.nvm/nvm.sh ] && . $$HOME/.nvm/nvm.sh; \
		nvm use --silent 2>/dev/null || true; \
		npm test -- --passWithNoTests

.PHONY: test-rust
test-rust: ## Run Rust tests only
	# Most of the workspace uses the default (postgres-feature) build.
	# dsm_storage_node integration tests use the local-dev (SQLite) build so
	# they run without a live PostgreSQL instance.
	cargo test --workspace --exclude dsm_storage_node -- --nocapture
	cargo test -p dsm_storage_node --no-default-features --features local-dev,strict -- --nocapture

.PHONY: test-frontend
test-frontend: ## Run frontend jest tests only
	cd $(FRONTEND_DIR) && \
		[ -s $$HOME/.nvm/nvm.sh ] && . $$HOME/.nvm/nvm.sh; \
		nvm use --silent 2>/dev/null || true; \
		npm test -- --passWithNoTests

.PHONY: typecheck
typecheck: ## Run frontend TypeScript type-check
	cd $(FRONTEND_DIR) && \
		[ -s $$HOME/.nvm/nvm.sh ] && . $$HOME/.nvm/nvm.sh; \
		nvm use --silent 2>/dev/null || true; \
		npm run type-check

# ---------------------------------------------------------------------------
# LINT / QUALITY
# ---------------------------------------------------------------------------

.PHONY: lint
lint: ## Run all linters (cargo fmt, clippy, frontend)
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings
	cd $(FRONTEND_DIR) && \
		[ -s $$HOME/.nvm/nvm.sh ] && . $$HOME/.nvm/nvm.sh; \
		nvm use --silent 2>/dev/null || true; \
		npm run lint
	@echo "==> Lint passed."

.PHONY: fmt
fmt: ## Auto-format Rust code
	cargo fmt --all

.PHONY: audit
audit: ## Security audit (cargo-audit + cargo-deny)
	cargo install cargo-audit --quiet || true
	cargo audit
	cargo install cargo-deny --quiet || true
	cargo deny check

.PHONY: deny
deny: ## Run cargo-deny license and advisory checks
	cargo install cargo-deny --quiet || true
	cargo deny check

# ---------------------------------------------------------------------------
# STORAGE NODES (local dev)
# ---------------------------------------------------------------------------

.PHONY: nodes-up
nodes-up: ## Set up the dev database and start the 5 local storage nodes
	@bash $(REPO_ROOT)/scripts/setup_dev_db.sh
	@cd $(STORAGE_NODE_DIR) && ./start_dev_nodes.sh

.PHONY: nodes-down
nodes-down: ## Stop the 5 local storage dev nodes
	@bash $(STORAGE_NODE_DIR)/scripts/stop_dev_nodes.sh

.PHONY: nodes-status
nodes-status: ## Check local storage node health and port status
	@bash $(STORAGE_NODE_DIR)/scripts/check_node_status.sh

.PHONY: nodes-reset
nodes-reset: ## Stop nodes and clean local node logs and pid files
	@bash $(REPO_ROOT)/scripts/dev_nodes_reset.sh

# ---------------------------------------------------------------------------
# PROTO / CODEGEN
# ---------------------------------------------------------------------------

.PHONY: proto-guard
proto-guard: ## Verify protobuf sources are in sync
	@bash scripts/guard_protos.sh

.PHONY: ci-scan
ci-scan: ## Run all CI gate scripts (flow assertions, symbol checks)
	bash scripts/ci_scan.sh
	bash scripts/flow_assertions.sh
	bash scripts/flow_mapping_assertions.sh

.PHONY: flow-assertions
flow-assertions: ## Run flow assertion checks
	bash scripts/flow_assertions.sh
	bash scripts/flow_mapping_assertions.sh

.PHONY: flow-mapping-assertions
flow-mapping-assertions: ## Run flow mapping assertion checks
	bash scripts/flow_mapping_assertions.sh

# ---------------------------------------------------------------------------
# RELEASE PREFLIGHT
# ---------------------------------------------------------------------------

.PHONY: release-preflight
release-preflight: ## Run the full pre-tag release gate (lint, test, audit, CI scan, PII scan, formal verification, frontend, SBOM)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║              DSM Release Preflight                      ║"
	@echo "╚══════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "── [1/8] Lint ──────────────────────────────────────────────"
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings
	@echo ""
	@echo "── [2/8] Rust tests ────────────────────────────────────────"
	cargo test --workspace --exclude dsm_storage_node -- --nocapture
	cargo test -p dsm_storage_node --no-default-features --features local-dev,strict -- --nocapture
	@echo ""
	@echo "── [3/8] Security audit ────────────────────────────────────"
	cargo deny check
	cargo audit
	@echo ""
	@echo "── [4/8] Protocol purity (CI scan) ─────────────────────────"
	bash scripts/ci_scan.sh
	bash scripts/flow_assertions.sh
	bash scripts/flow_mapping_assertions.sh
	bash scripts/check_forbidden_symbols.sh
	@echo ""
	@echo "── [5/8] PII / personal info scan ──────────────────────────"
	@PII_FOUND=0; \
	echo "  Checking for local file paths in source..."; \
	PATH_HITS=$$(git grep -lE '/Users/[a-zA-Z]+/(Desktop|Documents|Downloads)' -- ':(exclude).claude/' ':(exclude)*.lock' 2>/dev/null | head -5); \
	if [ -n "$$PATH_HITS" ]; then \
		echo "FAIL: Local file paths found:"; echo "$$PATH_HITS"; PII_FOUND=1; \
	fi; \
	echo "  Checking for hardcoded credentials..."; \
	CRED_HITS=$$(git grep -lEi '(password|secret|api_key)\s*=\s*"[^"]{4,}"' -- ':(exclude).claude/' ':(exclude)*.lock' ':(exclude)*.md' ':(exclude)*.sh' 2>/dev/null | head -5); \
	if [ -n "$$CRED_HITS" ]; then \
		echo "FAIL: Hardcoded credentials found:"; echo "$$CRED_HITS"; PII_FOUND=1; \
	fi; \
	echo "  Checking for SBOM scatter files..."; \
	SCATTER=$$(find . -name 'dsm-*-beta*.json' -o -name 'dsm-*-preflight*.json' 2>/dev/null | grep -v node_modules | grep -v target | head -5); \
	if [ -n "$$SCATTER" ]; then \
		echo "FAIL: SBOM scatter files with local paths found:"; echo "$$SCATTER"; PII_FOUND=1; \
	fi; \
	if [ $$PII_FOUND -eq 0 ]; then echo "PII scan PASS: no personal info in tracked files"; \
	else echo ""; echo "FAIL: Personal information detected. Clean before release."; exit 1; fi
	@echo ""
	@echo "── [6/8] Frontend (typecheck + test + build) ───────────────"
	cd $(FRONTEND_DIR) && \
		[ -s $$HOME/.nvm/nvm.sh ] && . $$HOME/.nvm/nvm.sh; \
		nvm use --silent 2>/dev/null || true; \
		npm run type-check && npm test -- --passWithNoTests && npm run build
	@echo ""
	@echo "── [7/8] Formal verification (TLA+ vertical validation) ────"
	cargo run -p dsm_vertical_validation -- tla-check
	@echo ""
	@echo "── [8/8] SBOM generation ───────────────────────────────────"
	bash scripts/generate-sbom.sh --run-id preflight-$$(date +%Y%m%d)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║  ✓ All gates passed — ready to tag                      ║"
	@echo "╚══════════════════════════════════════════════════════════╝"

# ---------------------------------------------------------------------------
# CLEAN
# ---------------------------------------------------------------------------

.PHONY: clean
clean: ## Remove all build artifacts
	cargo clean
	rm -rf $(FRONTEND_DIR)/dist $(FRONTEND_DIR)/build
	cd $(ANDROID_DIR) && ./gradlew clean --no-daemon --console=plain
	@echo "==> Clean complete."
