// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Utilities Module
//!
//! General utility functions used throughout the DSM codebase.
//!
//! ## Sub-modules
//!
//! * `file`: File system operations and helpers
//! * `text_id`: Base32 Crockford and dotted-decimal text for display edges

#[cfg(test)]
pub mod file;
pub mod text_id;
