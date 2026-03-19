//! Platform-specific implementations
//!
//! This module provides platform-specific implementations for Android, iOS, and other platforms.

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "ios")]
pub mod ios;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod desktop;
