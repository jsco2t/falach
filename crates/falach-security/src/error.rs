//! Single public error type for the `falach-security` crate.
//!
//! Per design §2.2.1 and the project's "no secret material in errors"
//! rule (kb/memory-hygiene.md), every variant of [`SecurityError`]
//! carries only structured, non-secret context — paths, source names,
//! upstream error messages. No variant ever embeds clipboard contents,
//! a master password, or any plaintext from a vault.
//!
//! ## `ClipboardIo` carries a `String` detail, not `arboard::Error`
//!
//! The design (§2.2.1) sketches `ClipboardIo { source: arboard::Error }`
//! but also says "we never expose `arboard::Error` as a public type."
//! We resolve in favour of the latter: this variant holds the
//! formatted upstream message as a `String`, and the clipboard module
//! calls `arboard::Error::to_string()` at the boundary. Consumers get
//! a `Display`-able diagnostic without `arboard` showing up in their
//! `match` arms, and `falach-security`'s public API never names a
//! third-party error type.

/// Errors returned by every fallible operation in `falach-security`.
///
/// `#[non_exhaustive]` so adding new variants (e.g., a future
/// `LockFileContended` for the post-MVP cross-process lock) is
/// non-breaking.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecurityError {
    /// Clipboard backend could not be initialised.
    ///
    /// On Linux this typically means neither `DISPLAY` nor
    /// `WAYLAND_DISPLAY` is set; on macOS it indicates a Pasteboard FFI
    /// failure. Phase 3 maps the relevant `arboard` initialisation
    /// errors here.
    #[error("clipboard backend unavailable: {0}")]
    ClipboardUnavailable(String),

    /// A clipboard read or write failed at the OS layer.
    ///
    /// `detail` is the formatted upstream error (typically
    /// `arboard::Error::to_string()`). Held as a `String` so the
    /// public API never names `arboard::Error` — see the module-level
    /// docs.
    ///
    /// Field name is `detail` (not `source`) because `thiserror`'s
    /// `#[source]`-by-convention picks up any field named `source` and
    /// expects it to implement `std::error::Error`; a plain `String`
    /// does not.
    #[error("clipboard operation failed: {detail}")]
    ClipboardIo {
        /// Formatted upstream error message.
        detail: String,
    },

    /// An OS-event source failed to initialise.
    ///
    /// Examples: `signal-hook` registration failure (Phase 4); future
    /// `zbus` `DBus` connect failure (post-MVP). The `name` field is
    /// the compile-time identifier the source advertises via its
    /// `OsLockEventSource::name` accessor (arrives in Phase 4).
    #[error("OS event source '{name}' failed to start: {detail}")]
    EventSourceStart {
        /// Source identifier (e.g., `"sigstop"`, `"noop"`, `"logind"`).
        name: &'static str,
        /// Human-readable non-secret detail.
        detail: String,
    },

    /// The event channel was closed unexpectedly — the controller was
    /// dropped before the source could exit. Diagnostic; not fatal to
    /// the source itself (it just exits cleanly).
    #[error("OS event source '{name}' lost its channel (controller dropped)")]
    EventChannelClosed {
        /// Source identifier (see [`Self::EventSourceStart`]).
        name: &'static str,
    },

    /// The per-vault `[vault.lock]` TOML section was malformed.
    #[error("invalid per-vault lock config: {detail}")]
    InvalidVaultLockConfig {
        /// Human-readable non-secret detail.
        detail: String,
    },

    /// An `AutoLockConfig` (arrives in Phase 2) failed validation
    /// (e.g., zero idle timeout).
    #[error("invalid auto-lock config: {detail}")]
    InvalidAutoLockConfig {
        /// Human-readable non-secret detail.
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn clipboard_io_carries_supplied_detail_string() {
        // `ClipboardIo`'s `detail` field holds the formatted upstream
        // error message verbatim — Phase 3 will populate it via
        // `arboard::Error::to_string()`. Round-trip the contract here.
        let err = SecurityError::ClipboardIo {
            detail: "x11 connection refused".to_string(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("x11 connection refused"),
            "Display should include the upstream detail: {display:?}"
        );
        // No `Error::source()` chaining today (`String` is not an
        // `Error`). Documented behaviour; when Phase 3 swaps in
        // `arboard::Error`, the variant can rename the field back to
        // `source` and gain chaining via `thiserror`'s
        // `source`-by-convention.
        assert!(err.source().is_none(), "no chaining when detail is String");
    }

    #[test]
    fn invalid_vault_lock_config_debug_carries_no_secret_material() {
        // The variants carry only the strings we supplied. Assert the
        // `Debug` output is *exactly* the structural representation
        // with our `detail` value embedded — any additional content
        // would mean the type accidentally captured process state.
        // `thiserror`'s `#[derive(Error)]` doesn't override `Debug`,
        // so the output is the standard derive shape, which is stable
        // across rustc versions.
        let err = SecurityError::InvalidVaultLockConfig {
            detail: "idle_timeout must be >= 1".to_string(),
        };
        let dbg = format!("{err:?}");
        assert_eq!(
            dbg, "InvalidVaultLockConfig { detail: \"idle_timeout must be >= 1\" }",
            "Debug output should be exactly the derive shape with the supplied detail"
        );
    }

    #[test]
    fn event_source_start_carries_source_name_in_display() {
        // `LogindSource` (post-MVP) re-uses this variant. The name
        // field is how downstream callers distinguish "which source
        // failed". Without `name` in `Display`, diagnostics would be
        // ambiguous between sources.
        let err = SecurityError::EventSourceStart {
            name: "sigstop",
            detail: "signal-hook registration failed".to_string(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("sigstop"),
            "Display should include the source name: {display:?}"
        );
        assert!(
            display.contains("signal-hook registration failed"),
            "Display should include the detail: {display:?}"
        );
    }

    #[test]
    fn event_channel_closed_carries_source_name() {
        let err = SecurityError::EventChannelClosed { name: "noop" };
        let display = format!("{err}");
        assert!(
            display.contains("noop"),
            "Display should include the source name: {display:?}"
        );
    }

    #[test]
    fn invalid_auto_lock_config_carries_detail() {
        let err = SecurityError::InvalidAutoLockConfig {
            detail: "idle_timeout must be >= 1 second".to_string(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("idle_timeout"),
            "Display should include the detail: {display:?}"
        );
    }

    #[test]
    fn clipboard_unavailable_carries_detail_in_display() {
        let err = SecurityError::ClipboardUnavailable("no DISPLAY".to_string());
        let display = format!("{err}");
        assert!(
            display.contains("no DISPLAY"),
            "Display should include the detail: {display:?}"
        );
    }
}
