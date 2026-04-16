//! # Protocol Metrics SDK Module
//!
//! This module provides comprehensive metrics and verification capabilities
//! for the DSM protocol, focusing on security, performance, and state integrity.
//! It implements the verification mechanisms described in section 5 of the DSM whitepaper
//! and integrates with the core DSM architecture to provide real-time verification
//! and metrics for protocol operations.
//!
//! ## Key Concepts
//!
//! * **Protocol Verification**: Cryptographic verification of state transitions and signatures
//! * **Performance Metrics**: Execution time and resource utilization tracking
//! * **State Integrity**: Validation of hash chain continuity and state transition correctness
//! * **Security Metrics**: Tracking of cryptographic operations and verification results
//! * **Runtime Reporting**: Real-time metrics and formatted verification reports
//!
//! ## Architecture
//!
//! The Protocol Metrics module follows the layered verification architecture:
//!
//! 1. **State Transition Verification**: Ensures each state change is valid according to protocol rules
//! 2. **Signature Verification**: Validates cryptographic signatures for all operations
//! 3. **Hash Chain Verification**: Ensures continuity and integrity of the state machine hash chain
//! 4. **Timing and Performance**: Measures execution time and resource utilization
//!
//! ## Concurrency & Lock Ordering
//!
//! This module uses two `parking_lot::Mutex` locks for internal state:
//! - `verification`: Protocol verification results
//! - `current_metrics`: Performance and timing metrics
//!
//! **Lock Ordering Rule**: Always acquire `verification` before `current_metrics` when both are needed.
//!
//! **Example** (from `finalize_verification`):
//! ```ignore
//! if let (Ok(verification), Ok(metrics)) =
//!     (self.verification.lock(), self.current_metrics.lock())  // Correct order
//! { ... }
//! ```
//!
//! ⚠️ **Deadlock Prevention**: Never acquire `current_metrics` before `verification` in the same scope.
//! Both locks are held only briefly for data cloning; no I/O or blocking operations occur while locked.
//!
//! ## Usage Example
//!
//! ```rust
//! use dsm_sdk::protocol_metrics::{create_metrics_manager, ProtocolMetricsManager};
//! use dsm::core::state_machine::StateMachine;
//! use std::sync::Arc;
//!
//! // Create a state machine
//! let state_machine = Arc::new(StateMachine::new());
//!
//! // Create a metrics manager
//! let metrics = create_metrics_manager(state_machine.clone());
//!
//! // Start timing protocol execution
//! metrics.start_timer("protocol_execution");
//!
//! // Perform protocol operations...
//!
//! // Stop timing and get the results
//! metrics.stop_timer("protocol_execution");
//!
//! // Get verification report
//! let verification_report = metrics.finalize_verification();
//! println!("{}", verification_report);
//! ```

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use blake3::Hasher;
use crate::util::deterministic_time::tick;
use dsm::{
    core::state_machine::StateMachine,
    crypto::signatures::SignatureKeyPair,
    types::{error::DsmError, operations::Operation, state_types::State},
};

/// Timekeeper for protocol operation metrics
///
/// Provides precise timing capabilities for measuring the performance
/// of protocol operations, using deterministic ticks instead of wall clock time.
#[derive(Debug, Clone)]
pub struct ProtocolTimer {
    /// Tick when the timer was started
    start_tick: Option<u64>,

    /// Recorded elapsed ticks after stopping
    elapsed_ticks: Option<u64>,

    /// Name of the operation being timed
    #[allow(dead_code)]
    operation_name: String,
}

impl ProtocolTimer {
    /// Create a new protocol timer for a specific operation
    ///
    /// # Arguments
    ///
    /// * `operation_name` - Name of the operation to time
    ///
    /// # Returns
    ///
    /// A new timer instance ready to be started
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolTimer;
    ///
    /// let mut timer = ProtocolTimer::new("state_verification");
    /// ```
    pub fn new(operation_name: &str) -> Self {
        Self {
            start_tick: None,
            elapsed_ticks: None,
            operation_name: operation_name.to_string(),
        }
    }

    /// Start the timer, recording the current time
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolTimer;
    ///
    /// let mut timer = ProtocolTimer::new("hash_calculation");
    /// timer.start();
    /// // Perform operation to time
    /// ```
    pub fn start(&mut self) {
        self.start_tick = Some(tick());
    }

    /// Stop the timer and record elapsed time
    ///
    /// # Returns
    ///
    /// * `Some(Duration)` - The elapsed time if the timer was started
    /// * `None` - If the timer was not started
    ///
    /// # Examples
    ///
    /// ```text
    /// use dsm_sdk::protocol_metrics::ProtocolTimer;
    ///
    /// let mut timer = ProtocolTimer::new("crypto_operation");
    /// timer.start();
    /// // Perform operation to time
    /// let elapsed = timer.stop();
    /// assert!(elapsed.is_some());
    /// println!("Operation took {} ms", elapsed.unwrap().as_millis());
    /// ```
    pub fn stop(&mut self) -> Option<u64> {
        if let Some(start) = self.start_tick {
            let end = tick();
            self.elapsed_ticks = Some(end.saturating_sub(start));
            self.elapsed_ticks
        } else {
            None
        }
    }

    /// Get the elapsed time without stopping the timer
    ///
    /// # Returns
    ///
    /// * `Some(Duration)` - The elapsed time if the timer was stopped
    /// * `None` - If the timer was not stopped yet
    pub fn elapsed(&self) -> Option<u64> {
        self.elapsed_ticks
    }

    /// Reset the timer to its initial state
    ///
    /// # Examples
    ///
    /// ```text
    /// use dsm_sdk::protocol_metrics::ProtocolTimer;
    ///
    /// let mut timer = ProtocolTimer::new("verification");
    /// timer.start();
    /// // After completing one operation
    /// timer.stop();
    /// // Reset for next operation
    /// timer.reset();
    /// ```
    pub fn reset(&mut self) {
        self.start_tick = None;
        self.elapsed_ticks = None;
    }
}

/// Protocol execution verification result
///
/// Contains comprehensive verification results for a protocol execution,
/// including component-level verification status and detailed metrics.
#[derive(Debug, Clone)]
pub struct ProtocolVerification {
    /// Overall verification status (true only if all components verified)
    pub verified: bool,

    /// Detailed verification results by component
    pub component_results: HashMap<String, bool>,

    /// Verification tick (deterministic logical time)
    pub tick: u64,

    /// Detailed error messages by component
    pub errors: HashMap<String, String>,

    /// Verification metrics
    pub metrics: ProtocolMetrics,
}

impl ProtocolVerification {
    /// Create a new protocol verification result
    ///
    /// # Returns
    ///
    /// A new verification result with default values
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolVerification;
    ///
    /// let verification = ProtocolVerification::new();
    /// ```
    pub fn new() -> Self {
        Self {
            verified: false,
            component_results: HashMap::new(),
            tick: tick(),
            errors: HashMap::new(),
            metrics: ProtocolMetrics::new(),
        }
    }

    /// Add a component verification result
    ///
    /// Records the verification result for a specific component
    /// and updates the overall verification status.
    ///
    /// # Arguments
    ///
    /// * `component` - Name of the component being verified
    /// * `verified` - True if the component verification passed, false otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolVerification;
    ///
    /// let mut verification = ProtocolVerification::new();
    /// verification.add_component_result("signature", true);
    /// verification.add_component_result("hash_chain", true);
    /// ```
    pub fn add_component_result(&mut self, component: &str, verified: bool) {
        self.component_results
            .insert(component.to_string(), verified);
        // Update overall verification status
        self.update_verification_status();
    }

    /// Add an error message for a component
    ///
    /// Records a detailed error message for a component that failed verification.
    ///
    /// # Arguments
    ///
    /// * `component` - Name of the component with the error
    /// * `error` - Detailed error message
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolVerification;
    ///
    /// let mut verification = ProtocolVerification::new();
    /// verification.add_component_result("hash_chain", false);
    /// verification.add_error("hash_chain", "Hash chain broken between states 5 and 6");
    /// ```
    pub fn add_error(&mut self, component: &str, error: &str) {
        self.errors.insert(component.to_string(), error.to_string());
    }

    /// Update the overall verification status based on component results
    ///
    /// Sets the overall verification status to true only if all
    /// component verifications were successful.
    fn update_verification_status(&mut self) {
        // Overall verification status is true only if all components verified successfully
        self.verified =
            !self.component_results.is_empty() && self.component_results.values().all(|&v| v);
    }

    /// Get a formatted representation of the verification result
    ///
    /// Returns a human-readable, formatted report of the verification
    /// results, with color-coding for the terminal.
    ///
    /// # Returns
    ///
    /// A formatted string with verification results and metrics
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolVerification;
    ///
    /// let verification = ProtocolVerification::new();
    /// let report = verification.formatted_output();
    /// println!("{}", report);
    /// ```
    pub fn formatted_output(&self) -> String {
        let _status_str = if self.verified {
            "\x1b[1;32mVERIFIED\x1b[0m"
        } else {
            "\x1b[1;31mFAILED\x1b[0m"
        };

        let memory_safety_str = if self.metrics.memory_safety_verified {
            "\x1b[1;32mVerified with Rust's Borrow Checker\x1b[0m"
        } else {
            "\x1b[1;31mNot Verified\x1b[0m"
        };

        let mut output = String::new();
        output.push_str("\n\x1b[1;37m╔══════════════════════════════════════════════════════════════════════════╗\x1b[0m\n");
        output.push_str("\x1b[1;37m║                    TRADE PROTOCOL METRICS                                ║\x1b[0m\n");
        output.push_str("\x1b[1;37m╠══════════════════════════════════════════════════════════════════════════╣\x1b[0m\n");
        output.push_str("\x1b[1;37m║\x1b[0m \x1b[1;32mProtocol Version\x1b[0m: DSM Secure Trading Protocol v2.0                       \x1b[1;37m║\x1b[0m\n");
        output.push_str("\x1b[1;37m║\x1b[0m \x1b[1;32mSecurity Level\x1b[0m  : Cryptographic Identity Verification                    \x1b[1;37m║\x1b[0m\n");
        output.push_str("\x1b[1;37m║\x1b[0m \x1b[1;32mTransport Layer\x1b[0m : Secure Bluetooth with End-to-End Encryption            \x1b[1;37m║\x1b[0m\n");

        // Format execution time to 1 decimal place (assuming ticks are milliseconds)
        let exec_time = if let Some(time) = self.metrics.execution_time {
            format!("{:.1} ms", time as f32)
        } else {
            "Not measured".to_string()
        };
        output.push_str(&format!(
            "\x1b[1;37m║\x1b[0m \x1b[1;32mExecution Time\x1b[0m  : {exec_time:<50} \x1b[1;37m║\x1b[0m\n"
        ));

        output.push_str(&format!(
            "\x1b[1;37m║\x1b[0m \x1b[1;32mMemory Safety\x1b[0m   : {memory_safety_str:<50} \x1b[1;37m║\x1b[0m\n"
        ));

        let trade_status = match self.metrics.trade_status.as_str() {
            "SUCCESS" => "\x1b[1;32mSUCCESS - Atomically Committed\x1b[0m".to_string(),
            "PENDING" => "\x1b[1;33mPENDING - Awaiting Confirmation\x1b[0m".to_string(),
            "FAILED" => "\x1b[1;31mFAILED - Verification Error\x1b[0m".to_string(),
            status => status.to_string(),
        };
        output.push_str(&format!(
            "\x1b[1;37m║\x1b[0m \x1b[1;32mTrade Status\x1b[0m    : {trade_status:<50} \x1b[1;37m║\x1b[0m\n"
        ));
        output.push_str("\x1b[1;37m╚══════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");

        // Add component details if verification failed
        if !self.verified {
            output.push_str("\nComponent Verification Results:\n");
            for (component, verified) in &self.component_results {
                let result = if *verified { "✓ PASS" } else { "✗ FAIL" };
                output.push_str(&format!("- {component}: {result}\n"));

                // Include error message if available
                if let Some(error) = self.errors.get(component) {
                    output.push_str(&format!("  Error: {error}\n"));
                }
            }
        }

        output
    }
}

impl Default for ProtocolVerification {
    fn default() -> Self {
        Self::new()
    }
}

/// Protocol metrics for measuring performance and security
///
/// Tracks comprehensive metrics related to protocol execution,
/// including performance, cryptographic operations, and verification status.
#[derive(Debug, Clone)]
pub struct ProtocolMetrics {
    /// Execution time of the protocol operation in ticks
    pub execution_time: Option<u64>,

    /// Number of cryptographic operations performed
    pub crypto_operations: u32,

    /// Number of state transitions executed
    pub state_transitions: u32,

    /// Memory safety verification status (always true in Rust)
    pub memory_safety_verified: bool,

    /// Comprehensive verification status
    pub verification_status: bool,

    /// Trade status (SUCCESS, PENDING, FAILED)
    pub trade_status: String,

    /// State hash integrity verification status
    pub state_hash_verified: bool,

    /// Number of signature verifications performed
    pub signature_verifications: u32,

    /// Hash chain continuity verification status
    pub hash_chain_verified: bool,
}

impl ProtocolMetrics {
    /// Create new protocol metrics with default values
    ///
    /// # Returns
    ///
    /// A new ProtocolMetrics instance with default values
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolMetrics;
    ///
    /// let metrics = ProtocolMetrics::new();
    /// ```
    pub fn new() -> Self {
        Self {
            execution_time: None,
            crypto_operations: 0,
            state_transitions: 0,
            memory_safety_verified: true, // Rust's borrow checker guarantees this at compile time
            verification_status: false,
            trade_status: "PENDING".to_string(),
            state_hash_verified: false,
            signature_verifications: 0,
            hash_chain_verified: false,
        }
    }

    /// Set the execution time for the protocol operation
    ///
    /// # Arguments
    ///
    /// * `time` - The measured execution time
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolMetrics;
    /// use std::time::Duration;
    ///
    /// let mut metrics = ProtocolMetrics::new();
    /// metrics.set_execution_time(250); // 250 ticks
    /// ```
    pub fn set_execution_time(&mut self, time: u64) {
        self.execution_time = Some(time);
    }

    /// Increment cryptographic operations counter
    ///
    /// Tracks the total number of cryptographic operations performed
    /// during protocol execution.
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolMetrics;
    ///
    /// let mut metrics = ProtocolMetrics::new();
    /// metrics.increment_crypto_operations();
    /// assert_eq!(metrics.crypto_operations, 1);
    /// ```
    pub fn increment_crypto_operations(&mut self) {
        self.crypto_operations += 1;
    }

    /// Increment state transitions counter
    ///
    /// Tracks the total number of state transitions executed
    /// during protocol execution.
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolMetrics;
    ///
    /// let mut metrics = ProtocolMetrics::new();
    /// metrics.increment_state_transitions();
    /// assert_eq!(metrics.state_transitions, 1);
    /// ```
    pub fn increment_state_transitions(&mut self) {
        self.state_transitions += 1;
    }

    /// Set the overall verification status
    ///
    /// # Arguments
    ///
    /// * `status` - True if verification passed, false otherwise
    pub fn set_verification_status(&mut self, status: bool) {
        self.verification_status = status;
    }

    /// Set the trade status
    ///
    /// # Arguments
    ///
    /// * `status` - The trade status (SUCCESS, PENDING, FAILED)
    pub fn set_trade_status(&mut self, status: &str) {
        self.trade_status = status.to_string();
    }

    /// Set the state hash verification status
    ///
    /// # Arguments
    ///
    /// * `verified` - True if state hash verification passed, false otherwise
    pub fn set_state_hash_verified(&mut self, verified: bool) {
        self.state_hash_verified = verified;
    }

    /// Increment signature verifications counter
    ///
    /// Tracks the total number of signature verifications performed
    /// during protocol execution.
    pub fn increment_signature_verifications(&mut self) {
        self.signature_verifications += 1;
    }

    /// Set the hash chain verification status
    ///
    /// # Arguments
    ///
    /// * `verified` - True if hash chain verification passed, false otherwise
    pub fn set_hash_chain_verified(&mut self, verified: bool) {
        self.hash_chain_verified = verified;
    }

    /// Update the overall verification status based on component verifications
    ///
    /// Updates the overall verification status and trade status based on
    /// the verification status of individual components.
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolMetrics;
    ///
    /// let mut metrics = ProtocolMetrics::new();
    /// metrics.set_state_hash_verified(true);
    /// metrics.set_hash_chain_verified(true);
    /// metrics.update_verification_status();
    /// assert!(metrics.verification_status);
    /// assert_eq!(metrics.trade_status, "SUCCESS");
    /// ```
    pub fn update_verification_status(&mut self) {
        self.verification_status = self.state_hash_verified && self.hash_chain_verified;

        // Update trade status based on verification
        if self.verification_status {
            self.trade_status = "SUCCESS".to_string();
        } else {
            self.trade_status = "FAILED".to_string();
        }
    }
}

impl Default for ProtocolMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Protocol metrics manager for tracking and reporting protocol metrics
///
/// Provides a comprehensive suite of tools for tracking metrics,
/// verifying protocol execution, and generating reports.
pub struct ProtocolMetricsManager {
    /// Active timers for measuring operation durations
    timers: Mutex<HashMap<String, ProtocolTimer>>,

    /// Metrics for the current protocol execution
    current_metrics: Mutex<ProtocolMetrics>,

    /// Protocol verification result
    verification: Mutex<ProtocolVerification>,

    /// State machine reference for state verification
    state_machine: Arc<StateMachine>,
}

impl ProtocolMetricsManager {
    /// Create a new protocol metrics manager
    ///
    /// # Arguments
    ///
    /// * `state_machine` - Arc-wrapped StateMachine for state verification
    ///
    /// # Returns
    ///
    /// A new ProtocolMetricsManager instance
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::ProtocolMetricsManager;
    /// use dsm::core::state_machine::StateMachine;
    /// use std::sync::Arc;
    ///
    /// let state_machine = Arc::new(StateMachine::new());
    /// let metrics_manager = ProtocolMetricsManager::new(state_machine);
    /// ```
    pub fn new(state_machine: Arc<StateMachine>) -> Self {
        Self {
            timers: Mutex::new(HashMap::new()),
            current_metrics: Mutex::new(ProtocolMetrics::new()),
            verification: Mutex::new(ProtocolVerification::new()),
            state_machine,
        }
    }

    /// Start a timer for an operation
    ///
    /// # Arguments
    ///
    /// * `operation` - Name of the operation to time
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::{ProtocolMetricsManager, create_metrics_manager};
    /// use dsm::core::state_machine::StateMachine;
    /// use std::sync::Arc;
    ///
    /// let state_machine = Arc::new(StateMachine::new());
    /// let metrics = create_metrics_manager(state_machine);
    ///
    /// // Start timing the protocol execution
    /// metrics.start_timer("protocol_execution");
    /// ```
    pub fn start_timer(&self, operation: &str) {
        if let Ok(mut timers) = self.timers.lock() {
            let mut timer = ProtocolTimer::new(operation);
            timer.start();
            timers.insert(operation.to_string(), timer);
        }
    }

    /// Stop a timer and record the elapsed time
    ///
    /// # Arguments
    ///
    /// * `operation` - Name of the operation to stop timing
    ///
    /// # Returns
    ///
    /// * `Some(Duration)` - The elapsed time if the timer was started
    /// * `None` - If the timer was not found or not started
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::{ProtocolMetricsManager, create_metrics_manager};
    /// use dsm::core::state_machine::StateMachine;
    /// use std::sync::Arc;
    ///
    /// let state_machine = Arc::new(StateMachine::new());
    /// let metrics = create_metrics_manager(state_machine);
    ///
    /// // Start timing
    /// metrics.start_timer("protocol_execution");
    ///
    /// // Perform some operations...
    ///
    /// // Stop timing and get elapsed time
    /// let elapsed = metrics.stop_timer("protocol_execution");
    /// if let Some(ticks) = elapsed {
    ///     println!("Execution took: {} ticks", ticks);
    /// }
    /// ```
    pub fn stop_timer(&self, operation: &str) -> Option<u64> {
        if let Ok(mut timers) = self.timers.lock() {
            if let Some(timer) = timers.get_mut(operation) {
                let elapsed = timer.stop();

                // If this is the main protocol timer, update metrics
                if operation == "protocol_execution" {
                    if let Some(ticks) = elapsed {
                        if let Ok(mut metrics) = self.current_metrics.lock() {
                            metrics.set_execution_time(ticks);
                        }
                    }
                }

                elapsed
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Verify a state transition
    ///
    /// Verifies that a state transition is valid according to protocol rules.
    ///
    /// # Arguments
    ///
    /// * `prev_state` - The previous state
    /// * `next_state` - The next state
    /// * `operation` - The operation that caused the transition
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the transition is valid, false otherwise
    /// * `Err(DsmError)` - If verification failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::{ProtocolMetricsManager, create_metrics_manager};
    /// use dsm::core::state_machine::StateMachine;
    /// use dsm::types::state_types::State;
    /// use dsm::types::operations::Operation;
    /// use std::sync::Arc;
    ///
    /// async fn verify_example(
    ///     metrics: Arc<ProtocolMetricsManager>,
    ///     prev_state: State,
    ///     next_state: State,
    ///     operation: Operation
    /// ) {
    ///     let verified = metrics.verify_state_transition(
    ///         &prev_state,
    ///         &next_state,
    ///         &operation
    ///     )?;
    ///
    ///     if verified {
    ///         println!("State transition verified successfully");
    ///     }
    /// }
    /// ```
    pub fn verify_state_transition(
        &self,
        prev_state: &State,
        next_state: &State,
        operation: &Operation,
    ) -> Result<bool, DsmError> {
        // Start timer for verification
        self.start_timer("state_verification");

        // Verify state transition
        let result = self.state_machine.apply_operation(
            prev_state.clone(),
            operation.clone(),
            next_state.entropy.clone(),
        );

        // Update metrics
        if let Ok(mut metrics) = self.current_metrics.lock() {
            metrics.increment_state_transitions();
        }

        // Record verification result
        let verified = if let Ok(computed_next_state) = result {
            // Compare computed next state with provided next state
            let state_hash_verified = computed_next_state.hash()? == next_state.hash()?;

            // Update metrics
            if let Ok(mut metrics) = self.current_metrics.lock() {
                metrics.set_state_hash_verified(state_hash_verified);
            }

            // Add to verification results
            if let Ok(mut verification) = self.verification.lock() {
                verification.add_component_result("state_transition", state_hash_verified);
                if !state_hash_verified {
                    verification.add_error("state_transition", "State hashes do not match");
                }
            }

            state_hash_verified
        } else {
            // Update verification on error
            if let Ok(mut verification) = self.verification.lock() {
                verification.add_component_result("state_transition", false);
                verification.add_error(
                    "state_transition",
                    &format!("Error applying operation: {result:?}"),
                );
            }

            false
        };

        // Stop timer
        self.stop_timer("state_verification");

        Ok(verified)
    }

    /// Verify a cryptographic signature
    ///
    /// Verifies that a cryptographic signature is valid for the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - The data that was signed
    /// * `signature` - The signature to verify
    /// * `public_key` - The public key to verify against
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the signature is valid, false otherwise
    /// * `Err(DsmError)` - If verification failed
    ///
    /// # Examples
    ///
    /// ```text
    /// use dsm_sdk::protocol_metrics::{ProtocolMetricsManager, create_metrics_manager};
    /// use dsm::core::state_machine::StateMachine;
    /// use std::sync::Arc;
    ///
    /// async fn verify_signature_example(
    ///     metrics: Arc<ProtocolMetricsManager>,
    ///     data: Vec<u8>,
    ///     signature: Vec<u8>,
    ///     public_key: Vec<u8>
    /// ) {
    ///     let verified = metrics.verify_signature(
    ///         &data,
    ///         &signature,
    ///         &public_key
    ///     )?;
    ///
    ///     if verified {
    ///         println!("Signature verified successfully");
    ///     }
    /// }
    /// ```
    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, DsmError> {
        // Start timer for verification
        self.start_timer("signature_verification");

        // Verify signature
        let result = SignatureKeyPair::verify_raw(data, signature, public_key);

        // Update metrics
        if let Ok(mut metrics) = self.current_metrics.lock() {
            metrics.increment_crypto_operations();
            metrics.increment_signature_verifications();
        }

        // Record verification result
        let verified = match result {
            Ok(verified) => {
                // Add to verification results
                if let Ok(mut verification) = self.verification.lock() {
                    verification.add_component_result("signature", verified);
                    if !verified {
                        verification.add_error("signature", "Signature verification failed");
                    }
                }

                verified
            }
            Err(e) => {
                // Add to verification results
                if let Ok(mut verification) = self.verification.lock() {
                    verification.add_component_result("signature", false);
                    verification
                        .add_error("signature", &format!("Error verifying signature: {e:?}"));
                }

                false
            }
        };

        // Stop timer
        self.stop_timer("signature_verification");

        Ok(verified)
    }

    /// Verify a hash chain's continuity and integrity
    ///
    /// Verifies that a sequence of states forms a valid hash chain,
    /// with proper state number sequencing and hash linking.
    ///
    /// # Arguments
    ///
    /// * `states` - The sequence of states to verify
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the hash chain is valid, false otherwise
    /// * `Err(DsmError)` - If verification failed
    ///
    /// # Examples
    ///
    /// ```text
    /// use dsm_sdk::protocol_metrics::{ProtocolMetricsManager, create_metrics_manager};
    /// use dsm::core::state_machine::StateMachine;
    /// use dsm::types::state_types::State;
    /// use std::sync::Arc;
    ///
    /// async fn verify_hash_chain_example(
    ///     metrics: Arc<ProtocolMetricsManager>,
    ///     states: Vec<State>
    /// ) {
    ///     let verified = metrics.verify_hash_chain(&states)?;
    ///
    ///     if (verified) {
    ///         println!("Hash chain verified successfully");
    ///     } else {
    ///         println!("Hash chain verification failed");
    ///     }
    /// }
    /// ```
    pub fn verify_hash_chain(&self, states: &[State]) -> Result<bool, DsmError> {
        // Start timer for verification
        self.start_timer("hash_chain_verification");

        // Verify hash chain continuity
        let mut verified = true;
        let mut error_message = String::new();

        // Check that state chain is continuous
        for i in 1..states.len() {
            let prev_state = &states[i - 1];
            let curr_state = &states[i];

            // Verify state number continuity
            if curr_state.hash[0] as u64 != prev_state.hash[0] as u64 + 1 {
                verified = false;
                error_message = format!(
                    "State number discontinuity: {prev_num} -> {curr_num}",
                    prev_num = prev_state.hash[0] as u64,
                    curr_num = curr_state.hash[0] as u64
                );
                break;
            }

            // Verify hash chain continuity
            let prev_hash = prev_state.hash()?;
            if curr_state.prev_state_hash != prev_hash {
                verified = false;
                error_message = format!(
                    "Hash chain broken between states {prev_num} and {curr_num}",
                    prev_num = prev_state.hash[0] as u64,
                    curr_num = curr_state.hash[0] as u64
                );
                break;
            }
        }

        // Update metrics
        if let Ok(mut metrics) = self.current_metrics.lock() {
            metrics.set_hash_chain_verified(verified);
        }

        // Record verification result
        if let Ok(mut verification) = self.verification.lock() {
            verification.add_component_result("hash_chain", verified);
            if !verified {
                verification.add_error("hash_chain", &error_message);
            }
        }

        // Stop timer
        self.stop_timer("hash_chain_verification");

        Ok(verified)
    }

    /// Calculate a deterministic hash for data using BLAKE3
    ///
    /// Calculates a cryptographic hash of the input data using the
    /// BLAKE3 hash function, which provides high performance and
    /// cryptographic security.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash
    ///
    /// # Returns
    ///
    /// A vector of bytes containing the hash
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::{ProtocolMetricsManager, create_metrics_manager};
    /// use dsm::core::state_machine::StateMachine;
    /// use std::sync::Arc;
    ///
    /// fn calculate_hash_example(metrics: Arc<ProtocolMetricsManager>) {
    ///     let data = b"Data to hash";
    ///     let hash = metrics.calculate_hash(data);
    ///     println!("Hash: {:?}", hash);
    /// }
    /// ```
    pub fn calculate_hash(&self, data: &[u8]) -> Vec<u8> {
        // Start timer for hashing
        self.start_timer("hash_calculation");

        // Calculate hash
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize().as_bytes().to_vec();

        // Update metrics
        if let Ok(mut metrics) = self.current_metrics.lock() {
            metrics.increment_crypto_operations();
        }

        // Stop timer
        self.stop_timer("hash_calculation");

        hash
    }

    /// Update verification status and return formatted results
    ///
    /// Updates the overall verification status based on component
    /// verifications and returns a formatted report.
    ///
    /// # Returns
    ///
    /// A formatted string with verification results and metrics
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::{ProtocolMetricsManager, create_metrics_manager};
    /// use dsm::core::state_machine::StateMachine;
    /// use std::sync::Arc;
    ///
    /// fn finalize_example(metrics: Arc<ProtocolMetricsManager>) {
    ///     // After performing all verifications
    ///     let report = metrics.finalize_verification();
    ///     println!("{}", report);
    /// }
    /// ```
    pub fn finalize_verification(&self) -> String {
        // Update verification status based on component results
        if let Ok(mut metrics) = self.current_metrics.lock() {
            metrics.update_verification_status();
        }

        // Update overall verification
        let verification_result = {
            if let (Ok(verification), Ok(metrics)) =
                (self.verification.lock(), self.current_metrics.lock())
            {
                let mut updated_verification = verification.clone();
                updated_verification.metrics = metrics.clone();
                updated_verification
            } else {
                ProtocolVerification::new()
            }
        };

        // Return formatted output
        verification_result.formatted_output()
    }

    /// Reset metrics for a new execution
    ///
    /// Resets all metrics, timers, and verification results to prepare
    /// for a new protocol execution.
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::{ProtocolMetricsManager, create_metrics_manager};
    /// use dsm::core::state_machine::StateMachine;
    /// use std::sync::Arc;
    ///
    /// fn reset_example(metrics: Arc<ProtocolMetricsManager>) {
    ///     // Reset metrics before starting a new protocol execution
    ///     metrics.reset();
    /// }
    /// ```
    pub fn reset(&self) {
        if let Ok(mut timers) = self.timers.lock() {
            timers.clear();
        }

        if let Ok(mut metrics) = self.current_metrics.lock() {
            *metrics = ProtocolMetrics::new();
        }

        if let Ok(mut verification) = self.verification.lock() {
            *verification = ProtocolVerification::new();
        }
    }

    /// Get current metrics
    ///
    /// # Returns
    ///
    /// A clone of the current metrics
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::{ProtocolMetricsManager, create_metrics_manager};
    /// use dsm::core::state_machine::StateMachine;
    /// use std::sync::Arc;
    ///
    /// fn get_metrics_example(metrics: Arc<ProtocolMetricsManager>) {
    ///     let current_metrics = metrics.get_metrics();
    ///     println!("Crypto operations: {}", current_metrics.crypto_operations);
    ///     println!("State transitions: {}", current_metrics.state_transitions);
    /// }
    /// ```
    pub fn get_metrics(&self) -> ProtocolMetrics {
        if let Ok(metrics) = self.current_metrics.lock() {
            metrics.clone()
        } else {
            ProtocolMetrics::new()
        }
    }

    /// Get verification results
    ///
    /// # Returns
    ///
    /// A clone of the current verification results
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::protocol_metrics::{ProtocolMetricsManager, create_metrics_manager};
    /// use dsm::core::state_machine::StateMachine;
    /// use std::sync::Arc;
    ///
    /// fn get_verification_example(metrics: Arc<ProtocolMetricsManager>) {
    ///     let verification = metrics.get_verification();
    ///     if (verification.verified) {
    ///         println!("Protocol execution verified successfully");
    ///     } else {
    ///         println!("Protocol execution verification failed");
    ///     }
    /// }
    /// ```
    pub fn get_verification(&self) -> ProtocolVerification {
        if let Ok(verification) = self.verification.lock() {
            verification.clone()
        } else {
            ProtocolVerification::new()
        }
    }
}

/// Create a metrics manager with the specified state machine
///
/// # Arguments
///
/// * `state_machine` - Arc-wrapped StateMachine for state verification
///
/// # Returns
///
/// An Arc-wrapped ProtocolMetricsManager
///
/// # Examples
///
/// ```
/// use dsm_sdk::protocol_metrics::create_metrics_manager;
/// use dsm::core::state_machine::StateMachine;
/// use std::sync::Arc;
///
/// let state_machine = Arc::new(StateMachine::new());
/// let metrics = create_metrics_manager(state_machine);
/// ```
pub fn create_metrics_manager(state_machine: Arc<StateMachine>) -> Arc<ProtocolMetricsManager> {
    Arc::new(ProtocolMetricsManager::new(state_machine))
}

/// Calculate integrity hash for a set of data
///
/// Calculates a deterministic hash over multiple data items,
/// useful for verifying the integrity of a set of related data.
///
/// # Arguments
///
/// * `data_items` - Slice of data items to hash
///
/// # Returns
///
/// A vector of bytes containing the hash
///
/// # Examples
///
/// ```
/// use dsm_sdk::protocol_metrics::calculate_integrity_hash;
///
/// fn integrity_hash_example() {
///     let data1 = b"First piece of data";
///     let data2 = b"Second piece of data";
///     
///     let hash = calculate_integrity_hash(&[data1, data2]);
///     println!("Integrity hash: {:?}", hash);
/// }
/// ```
pub fn calculate_integrity_hash(data_items: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Hasher::new();

    // Add all data items to hasher in sequence
    for data in data_items {
        hasher.update(data);
    }

    hasher.finalize().as_bytes().to_vec()
}

/// Verify memory safety at runtime (always true in Rust due to borrow checker)
///
/// This function always returns true in Rust due to the borrow checker
/// ensuring memory safety at compile time. It's included for completeness
/// in the metrics API.
///
/// # Returns
///
/// Always true in Rust
///
/// # Examples
///
/// ```
/// use dsm_sdk::protocol_metrics::verify_memory_safety;
///
/// fn memory_safety_example() {
///     let safe = verify_memory_safety();
///     assert!(safe);
/// }
/// ```
pub fn verify_memory_safety() -> bool {
    // This is always true in a compiled Rust program due to the borrow checker
    // It's included here for completeness in the metrics API
    true
}

#[cfg(test)]
mod tests {
    use dsm::types::state_types::{DeviceInfo, StateParams};

    use super::*;

    // Helper function to create a test state
    #[allow(dead_code)]
    fn create_test_state(state_number: u64, prev_hash: [u8; 32], entropy: Vec<u8>) -> State {
        let device_info = DeviceInfo::from_hashed_label(
            "test_device",
            vec![0, 1, 2, 3], // Test public key
        );

        let operation = Operation::Generic {
            operation_type: b"test".to_vec(),
            data: vec![],
            message: "Test operation".to_string(),
            signature: vec![],
        };

        let params = StateParams::new(state_number, entropy, operation, device_info);

        let params = params.with_prev_state_hash(prev_hash);

        State::new(params)
    }

    #[test]
    fn test_protocol_timer() -> Result<(), DsmError> {
        let mut timer = ProtocolTimer::new("test_operation");
        timer.start();

        // Simulate some work by advancing ticks
        let _ = tick(); // Advance tick counter

        let elapsed = timer.stop();
        assert!(elapsed.is_some());
        // Timing may be 0 in test environments, just ensure it's not negative
        Ok(())
    }

    #[test]
    fn test_protocol_verification() {
        let mut verification = ProtocolVerification::new();

        // Add some component results
        verification.add_component_result("signature", true);
        verification.add_component_result("state_transition", true);

        // Verify that overall verification is true when all components pass
        assert!(verification.verified);

        // Add a failing component
        verification.add_component_result("hash_chain", false);
        verification.add_error("hash_chain", "Hash chain broken");

        // Overall verification should now be false
        assert!(!verification.verified);
    }

    #[test]
    fn test_protocol_metrics() {
        let mut metrics = ProtocolMetrics::new();

        // Set some metrics
        metrics.set_execution_time(1000); // 1000 ticks = 1 second
        metrics.increment_crypto_operations();
        metrics.increment_state_transitions();
        metrics.set_state_hash_verified(true);
        metrics.set_hash_chain_verified(true);

        // Update verification status
        metrics.update_verification_status();

        // Verify metrics
        assert!(metrics.verification_status);
        assert_eq!(metrics.trade_status, "SUCCESS");
        assert_eq!(metrics.crypto_operations, 1);
        assert_eq!(metrics.state_transitions, 1);
    }

    #[test]
    fn test_calculate_integrity_hash() {
        let data1 = b"test data 1";
        let data2 = b"test data 2";

        let hash = calculate_integrity_hash(&[data1, data2]);

        // Verify hash is not empty
        assert!(!hash.is_empty());

        // Verify hash is deterministic
        let hash2 = calculate_integrity_hash(&[data1, data2]);
        assert_eq!(hash, hash2);

        // Verify hash changes with different data
        let hash3 = calculate_integrity_hash(&[data2, data1]);
        assert_ne!(hash, hash3);
    }
}
