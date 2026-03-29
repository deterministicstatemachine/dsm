
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

SHELL := /bin/bash
REPO_ROOT := $(shell cd "$(dir $(abspath $(lastword $(MAKEFILE_LIST))))" && pwd)
ANDROID_DIR := $(REPO_ROOT)/dsm_client/android
NDK_DIR := $(REPO_ROOT)/dsm_client/deterministic_state_machine
FRONTEND_DIR := $(REPO_ROOT)/dsm_client/new_frontend
STORAGE_NODE_DIR := $(REPO_ROOT)/dsm_storage_node
JNILIBS_DIR := $(ANDROID_DIR)/app/src/main/jniLibs
REPO_JNILIBS_DIR := $(NDK_DIR)/jniLibs
CARGO_CONFIG := $(NDK_DIR)/dsm_sdk/.cargo/config.toml
CARGO_CONFIG_TEMPLATE := $(NDK_DIR)/dsm_sdk/.cargo/config.toml.template
ANDROID_LOCAL_PROPERTIES := $(ANDROID_DIR)/local.properties

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
	@command -v cargo >/dev/null 2>&1 && echo "    cargo: $$(cargo --version)" || echo "    MISSING: cargo (install from https://rustup.rs)"
	@command -v rustfmt >/dev/null 2>&1 && echo "    rustfmt: installed" || echo "    MISSING: rustfmt (run: rustup component add rustfmt)"
	@command -v cargo-clippy >/dev/null 2>&1 && echo "    clippy: installed" || echo "    MISSING: clippy (run: rustup component add clippy)"
	@command -v protoc >/dev/null 2>&1 && echo "    protoc: $$(protoc --version)" || echo "    MISSING: protoc"
	@command -v node >/dev/null 2>&1 && echo "    node: $$(node --version)" || echo "    MISSING: node"
	@command -v npm >/dev/null 2>&1 && echo "    npm: $$(npm --version)" || echo "    MISSING: npm"
	@command -v adb >/dev/null 2>&1 && echo "    adb: available" || echo "    adb: optional (needed only for device install/debug)"
	@command -v psql >/dev/null 2>&1 && echo "    psql: available" || echo "    psql: optional until you run local storage nodes"
	@command -v java >/dev/null 2>&1 && echo "    java: $$(java -version 2>&1 | head -1)" || echo "    java: optional until Android builds"
	@if [ -n "$$ANDROID_NDK_HOME$$ANDROID_NDK_ROOT" ]; then \
		if [ -n "$$ANDROID_NDK_HOME" ]; then \
			echo "    android ndk: configured via ANDROID_NDK_HOME"; \
		else \
			echo "    android ndk: configured via ANDROID_NDK_ROOT"; \
		fi; \
	else \
		echo "    android ndk: not configured (run make setup before Android builds)"; \
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
	@if [ -f "$(CARGO_CONFIG)" ]; then \
		echo "    android cargo config: present"; \
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
	@command -v cargo >/dev/null 2>&1 || { echo "ERROR: Rust/cargo not found. Install from https://rustup.rs"; exit 1; }
	@command -v npm >/dev/null 2>&1 || { echo "ERROR: npm not found. Install Node.js 20+"; exit 1; }
	@command -v protoc >/dev/null 2>&1 || { echo "ERROR: protoc not found. Install protobuf compiler"; exit 1; }
	@command -v adb >/dev/null 2>&1 || echo "WARNING: adb not found — install Android Platform Tools for device installs"
	@$(MAKE) android-sdk-config
	@if [ -z "$$ANDROID_NDK_HOME" ] && [ -z "$$ANDROID_NDK_ROOT" ]; then \
		echo "WARNING: ANDROID_NDK_HOME is not set — skipping Android cargo config generation."; \
		echo "  Set it later and re-run 'make setup' before Android builds."; \
	else \
		command -v cargo-ndk >/dev/null 2>&1 || { echo "Installing cargo-ndk..."; cargo install cargo-ndk; }; \
		NDK="$${ANDROID_NDK_HOME:-$$ANDROID_NDK_ROOT}"; \
		mkdir -p "$$(dirname "$(CARGO_CONFIG)")"; \
		echo "==> Refreshing dsm_client/deterministic_state_machine/dsm_sdk/.cargo/config.toml from template..."; \
		sed \
			-e "s|__NDK_ROOT__|$$NDK|g" \
			-e "s|__NDK_HOST_TAG__|$$(ls $$NDK/toolchains/llvm/prebuilt/ | head -1)|g" \
			$(CARGO_CONFIG_TEMPLATE) > "$(CARGO_CONFIG).tmp"; \
		mv "$(CARGO_CONFIG).tmp" "$(CARGO_CONFIG)"; \
		echo "    Refreshed: dsm_client/deterministic_state_machine/dsm_sdk/.cargo/config.toml"; \
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
release-preflight: ## Run the full pre-tag release gate (lint, test, audit, CI scan, formal verification, frontend, SBOM)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║              DSM Release Preflight                      ║"
	@echo "╚══════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "── [1/7] Lint ──────────────────────────────────────────────"
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings
	@echo ""
	@echo "── [2/7] Rust tests ────────────────────────────────────────"
	cargo test --workspace --exclude dsm_storage_node -- --nocapture
	cargo test -p dsm_storage_node --no-default-features --features local-dev,strict -- --nocapture
	@echo ""
	@echo "── [3/7] Security audit ────────────────────────────────────"
	cargo deny check
	cargo audit
	@echo ""
	@echo "── [4/7] Protocol purity (CI scan) ─────────────────────────"
	bash scripts/ci_scan.sh
	bash scripts/flow_assertions.sh
	bash scripts/flow_mapping_assertions.sh
	bash scripts/check_forbidden_symbols.sh
	@echo ""
	@echo "── [5/7] Frontend (typecheck + test + build) ───────────────"
	cd $(FRONTEND_DIR) && \
		[ -s $$HOME/.nvm/nvm.sh ] && . $$HOME/.nvm/nvm.sh; \
		nvm use --silent 2>/dev/null || true; \
		npm run type-check && npm test -- --passWithNoTests && npm run build
	@echo ""
	@echo "── [6/7] Formal verification (TLA+ vertical validation) ────"
	cargo run -p dsm_vertical_validation -- tla-check
	@echo ""
	@echo "── [7/7] SBOM generation ───────────────────────────────────"
	bash scripts/generate-sbom.sh --run-id preflight-$$(date +%Y%m%d)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║  ✓ All gates passed — ready to tag                      ║"
	@echo "║                                                          ║"
	@echo "║    git tag v0.1.0-beta.1                                 ║"
	@echo "║    git push origin v0.1.0-beta.1                         ║"
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
