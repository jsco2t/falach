//! Small crate-wide presentation helpers shared by more than one module.
//!
//! These are deliberately plain functions, not an abstraction (CLAUDE.md
//! "narrow abstractions" / "three similar lines beats a premature
//! abstraction"). They live here only because each previously existed as an
//! identical copy in two modules, and at least one ([`is_otp_field`]) is
//! security-relevant — two copies of a secret-hiding filter can silently
//! drift (PMF-4).

use chrono::{DateTime, Utc};

/// Whether a custom-field name denotes an OTP/TOTP secret seed.
///
/// **Security-relevant:** the detail pane and the edit overlay both use this
/// to keep the `otpauth://` URI (which embeds the `secret=` seed) out of the
/// plainly-rendered/editable custom-field set — the TOTP code is surfaced
/// through the dedicated TOTP path instead. A single definition keeps the two
/// call sites from drifting.
pub(crate) fn is_otp_field(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "otp" || lower.contains("totp")
}

/// Format a UTC timestamp for display as `YYYY-MM-DD HH:MM UTC`.
///
/// Shared by the entry-detail pane and the history overlay so the rendered
/// timestamp format can never diverge between the two.
pub(crate) fn format_ts(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%d %H:%M UTC").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn is_otp_field_matches_otp_and_totp_names_case_insensitively() {
        // Exact "otp" and any name containing "totp" (KeePassXC's TOTP field
        // convention), case-insensitively.
        assert!(is_otp_field("otp"));
        assert!(is_otp_field("OTP"));
        assert!(is_otp_field("TOTP"));
        assert!(is_otp_field("TimeOtp_totp")); // contains "totp"
        assert!(is_otp_field("TOTP Seed"));
    }

    #[test]
    fn is_otp_field_rejects_non_otp_names() {
        assert!(!is_otp_field("API Key"));
        assert!(!is_otp_field("Recovery PIN"));
        assert!(!is_otp_field("password"));
        assert!(!is_otp_field("")); // empty is not an OTP field
    }

    #[test]
    fn format_ts_pins_the_display_format() {
        // 2026-05-06 07:08:09 UTC → seconds are intentionally dropped.
        let ts = Utc.with_ymd_and_hms(2026, 5, 6, 7, 8, 9).unwrap();
        assert_eq!(format_ts(ts), "2026-05-06 07:08 UTC");
    }
}
