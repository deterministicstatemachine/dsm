//! UI-facing error types for the DSM Android WebView frontend.
//!
//! [`DsmUiError`] wraps [`DsmCoreError`] with additional context specific to the
//! UI layer: browser user agent, URL context, WebView version, JavaScript bridge
//! function names, and React component identifiers. This enables precise error
//! reporting across the `WebView → MessagePort → Kotlin Bridge` path without
//! leaking internal protocol details to the user interface.

use crate::core::error::DsmCoreError;
use std::{error::Error, fmt::Display};

/// UI-specific error type that extends DsmCoreError with browser/UI fields
#[derive(Debug)]
#[non_exhaustive]
pub enum DsmUiError {
    /// Core DSM error
    Core(DsmCoreError),

    /// Browser-specific error with user agent and URL context
    Browser {
        /// The underlying core error
        core_error: DsmCoreError,
        /// Browser user agent string
        user_agent: Option<String>,
        /// URL where the error occurred
        url: Option<String>,
        /// Browser-specific error details
        browser_details: Option<String>,
    },

    /// WebView-specific error
    WebView {
        /// The underlying core error
        core_error: DsmCoreError,
        /// WebView version
        webview_version: Option<String>,
        /// Platform-specific details
        platform_details: Option<String>,
    },

    /// JavaScript bridge error
    JsBridge {
        /// The underlying core error
        core_error: DsmCoreError,
        /// JavaScript function that failed
        js_function: Option<String>,
        /// JavaScript error message
        js_error: Option<String>,
    },

    /// UI rendering error
    UiRendering {
        /// The underlying core error
        core_error: DsmCoreError,
        /// Component that failed to render
        component: Option<String>,
        /// UI framework details
        framework_details: Option<String>,
    },
}

impl DsmUiError {
    /// Create a new browser error
    pub fn browser(
        core_error: DsmCoreError,
        user_agent: Option<String>,
        url: Option<String>,
        browser_details: Option<String>,
    ) -> Self {
        DsmUiError::Browser {
            core_error,
            user_agent,
            url,
            browser_details,
        }
    }

    /// Create a new WebView error
    pub fn webview(
        core_error: DsmCoreError,
        webview_version: Option<String>,
        platform_details: Option<String>,
    ) -> Self {
        DsmUiError::WebView {
            core_error,
            webview_version,
            platform_details,
        }
    }

    /// Create a new JavaScript bridge error
    pub fn js_bridge(
        core_error: DsmCoreError,
        js_function: Option<String>,
        js_error: Option<String>,
    ) -> Self {
        DsmUiError::JsBridge {
            core_error,
            js_function,
            js_error,
        }
    }

    /// Create a new UI rendering error
    pub fn ui_rendering(
        core_error: DsmCoreError,
        component: Option<String>,
        framework_details: Option<String>,
    ) -> Self {
        DsmUiError::UiRendering {
            core_error,
            component,
            framework_details,
        }
    }

    /// Get the underlying core error
    pub fn core_error(&self) -> &DsmCoreError {
        match self {
            DsmUiError::Core(core) => core,
            DsmUiError::Browser { core_error, .. } => core_error,
            DsmUiError::WebView { core_error, .. } => core_error,
            DsmUiError::JsBridge { core_error, .. } => core_error,
            DsmUiError::UiRendering { core_error, .. } => core_error,
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        self.core_error().is_recoverable()
    }
}

impl Display for DsmUiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsmUiError::Core(core) => write!(f, "{core}"),
            DsmUiError::Browser {
                core_error,
                user_agent,
                url,
                browser_details,
            } => {
                write!(f, "Browser error: {core_error}")?;
                if let Some(ua) = user_agent {
                    write!(f, " (User-Agent: {ua})")?;
                }
                if let Some(u) = url {
                    write!(f, " (URL: {u})")?;
                }
                if let Some(details) = browser_details {
                    write!(f, " (Details: {details})")?;
                }
                Ok(())
            }
            DsmUiError::WebView {
                core_error,
                webview_version,
                platform_details,
            } => {
                write!(f, "WebView error: {core_error}")?;
                if let Some(version) = webview_version {
                    write!(f, " (WebView: {version})")?;
                }
                if let Some(platform) = platform_details {
                    write!(f, " (Platform: {platform})")?;
                }
                Ok(())
            }
            DsmUiError::JsBridge {
                core_error,
                js_function,
                js_error,
            } => {
                write!(f, "JavaScript bridge error: {core_error}")?;
                if let Some(func) = js_function {
                    write!(f, " (Function: {func})")?;
                }
                if let Some(js_err) = js_error {
                    write!(f, " (JS Error: {js_err})")?;
                }
                Ok(())
            }
            DsmUiError::UiRendering {
                core_error,
                component,
                framework_details,
            } => {
                write!(f, "UI rendering error: {core_error}")?;
                if let Some(comp) = component {
                    write!(f, " (Component: {comp})")?;
                }
                if let Some(framework) = framework_details {
                    write!(f, " (Framework: {framework})")?;
                }
                Ok(())
            }
        }
    }
}

impl Error for DsmUiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DsmUiError::Core(core) => core.source(),
            DsmUiError::Browser { core_error, .. } => core_error.source(),
            DsmUiError::WebView { core_error, .. } => core_error.source(),
            DsmUiError::JsBridge { core_error, .. } => core_error.source(),
            DsmUiError::UiRendering { core_error, .. } => core_error.source(),
        }
    }
}

impl From<DsmCoreError> for DsmUiError {
    fn from(core_error: DsmCoreError) -> Self {
        DsmUiError::Core(core_error)
    }
}
