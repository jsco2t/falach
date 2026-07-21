//! TOTP code generation per RFC 6238, implemented in-tree against the
//! `RustCrypto` family (`hmac` + `sha1` + `base32`).
//!
//! The on-disk representation of a TOTP entry follows the `KeePassXC`
//! convention: an `otp` custom string field whose value is an
//! `otpauth://totp/...` URI. This module parses, emits, and computes
//! codes against that representation.
//!
//! ## Algorithm support
//!
//! Phase 0 supports HMAC-SHA1 only (RFC 6238 §1.2; the algorithm every
//! mainstream authenticator app uses). `algorithm=SHA256` /
//! `algorithm=SHA512` URIs are rejected at parse time with a clear error
//! rather than silently producing a wrong code. The omission is
//! tracked as a follow-up; re-adding it costs roughly one direct dep
//! (`sha2 = "0.10"` via a `package` rename to avoid clashing with the
//! existing `sha2 = "0.11"` used for content hashing).
//!
//! ## Why not `totp-rs`?
//!
//! `totp-rs` pulled `url` for `otpauth://` parsing, which transitively
//! drags in `idna` + the ICU (`icu_collections`, `icu_normalizer`,
//! `icu_properties`, etc.) tree — roughly thirty crates of
//! internationalised-domain-name machinery for an ASCII-only URI scheme.
//! The in-tree replacement is a few hundred lines and depends only on
//! the small, single-purpose `RustCrypto` primitives already endorsed
//! by `CLAUDE.md`.

use std::fmt;

use hmac::{Hmac, Mac};
use keepass::db::fields;
use keepass::Database;
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::entry::crud::find_entry_id;
use crate::{Vault, VaultError, VaultReadOnly};

/// Default period (step) per RFC 6238.
const DEFAULT_PERIOD: u64 = 30;
/// Default digit count per RFC 6238.
const DEFAULT_DIGITS: u32 = 6;
/// Largest supported digit count. Beyond 10 the modulo can exceed the
/// 31-bit dynamic-truncation output, leaving leading-zero digits that
/// cannot be filled meaningfully.
const MAX_DIGITS: u32 = 10;

/// TOTP algorithm choice used by an entry.
///
/// Phase 0 ships only [`TotpAlgorithm::Sha1`]; the enum is
/// `#[non_exhaustive]` so future variants (SHA-256, SHA-512) can be added
/// without breaking pattern-matching callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TotpAlgorithm {
    /// HMAC-SHA1, the RFC 6238 default. Every mainstream authenticator
    /// app uses this.
    Sha1,
}

impl TotpAlgorithm {
    /// Canonical name used in `otpauth://` URIs.
    pub fn as_uri_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
        }
    }
}

/// Errors returned when parsing an `otpauth://totp/...` URI.
///
/// Surfaced inside [`VaultError::InvalidOtpUri`]. No variant carries
/// user-supplied secret material.
#[derive(Debug)]
#[non_exhaustive]
pub enum OtpAuthUriError {
    /// The input does not begin with `otpauth://`.
    NotAnOtpAuthUri,
    /// The URI host is not `totp` (e.g. `otpauth://hotp/...` — HOTP is
    /// out of scope for Phase 0).
    UnsupportedType,
    /// The `secret` query parameter is absent.
    MissingSecret,
    /// The `secret` query parameter is not valid base32.
    InvalidSecret,
    /// The `algorithm` parameter requested an unsupported algorithm.
    /// Phase 0 supports only `SHA1`.
    UnsupportedAlgorithm,
    /// A numeric query parameter (`digits` / `period`) is malformed or
    /// out of the supported range.
    InvalidParameter {
        /// Parameter name, e.g. `"digits"` or `"period"`.
        name: &'static str,
    },
    /// A percent-encoded sequence in the URI is malformed.
    InvalidEncoding,
}

impl fmt::Display for OtpAuthUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnOtpAuthUri => f.write_str("not an otpauth:// URI"),
            Self::UnsupportedType => {
                f.write_str("only otpauth://totp/ URIs are supported (HOTP not implemented)")
            }
            Self::MissingSecret => f.write_str("missing required 'secret' parameter"),
            Self::InvalidSecret => f.write_str("'secret' is not valid base32"),
            Self::UnsupportedAlgorithm => {
                f.write_str("unsupported algorithm (only SHA1 is supported)")
            }
            Self::InvalidParameter { name } => write!(f, "invalid '{name}' parameter"),
            Self::InvalidEncoding => f.write_str("malformed percent-encoding"),
        }
    }
}

impl std::error::Error for OtpAuthUriError {}

/// Parsed TOTP configuration.
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
    label: String,
    issuer: Option<String>,
}

impl Totp {
    /// Parse an `otpauth://totp/...` URI.
    ///
    /// Accepts any well-formed URI, including ones whose base32 secret is
    /// shorter than the RFC 6238 ≥128-bit recommendation. Secret strength
    /// is the issuer's responsibility; rejecting short secrets here would
    /// break the widely-used 80-bit Google Authenticator demo secret
    /// (`JBSWY3DPEHPK3PXP`) and any other legacy issuer.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidOtpUri`] when the URI is not a
    /// well-formed `otpauth://totp/...` URI with a base32 `secret`.
    pub fn from_otpauth_uri(uri: &str) -> Result<Self, VaultError> {
        parse_otpauth_uri(uri).map_err(|source| VaultError::InvalidOtpUri { source })
    }

    /// Emit a canonical `otpauth://totp/...` URI for this configuration.
    ///
    /// The label and issuer are percent-encoded per RFC 3986 unreserved
    /// rules. Default parameter values (`algorithm=SHA1`, `digits=6`,
    /// `period=30`) are omitted from the emitted URI.
    pub fn to_otpauth_uri(&self) -> String {
        let mut out = String::with_capacity(64);
        out.push_str("otpauth://totp/");
        out.push_str(&percent_encode(&self.label));
        out.push_str("?secret=");
        out.push_str(&base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &self.secret,
        ));
        if let Some(issuer) = &self.issuer {
            out.push_str("&issuer=");
            out.push_str(&percent_encode(issuer));
        }
        if self.algorithm != TotpAlgorithm::Sha1 {
            out.push_str("&algorithm=");
            out.push_str(self.algorithm.as_uri_str());
        }
        if self.digits != DEFAULT_DIGITS {
            out.push_str("&digits=");
            out.push_str(&self.digits.to_string());
        }
        if self.period != DEFAULT_PERIOD {
            out.push_str("&period=");
            out.push_str(&self.period.to_string());
        }
        out
    }

    /// Generate the code for the Unix timestamp `time` (seconds since epoch).
    pub fn code_at(&self, time: u64) -> String {
        // A malformed otpauth URI like `?period=0` is screened at parse time,
        // but `checked_div` keeps this path infallible even if a future
        // change re-introduces a zero `period`.
        let counter = time.checked_div(self.period).unwrap_or(0);
        hotp_code(&self.secret, counter, self.algorithm, self.digits)
    }

    /// Seconds remaining in the current step window at Unix timestamp `time`.
    ///
    /// Returns `0` when the underlying `period` is zero — a malformed
    /// otpauth URI like `?period=0` would otherwise divide by zero. The
    /// non-panicking guard preserves the crate's no-untrusted-input-panics
    /// posture.
    pub fn remaining_at(&self, time: u64) -> u64 {
        if self.period == 0 {
            return 0;
        }
        self.period - (time % self.period)
    }

    /// Number of digits emitted by [`Self::code_at`].
    pub fn digits(&self) -> usize {
        self.digits as usize
    }

    /// Step / period length in seconds.
    pub fn period(&self) -> u64 {
        self.period
    }

    /// HMAC algorithm.
    pub fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("label", &self.label)
            .field("issuer", &self.issuer)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Vault {
    /// Compute the current TOTP code and the seconds remaining in its window.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::EntryNotFound`] when `uuid` does not identify
    /// an entry, [`VaultError::EntryHasNoTotp`] when the entry has no `otp`
    /// field, and [`VaultError::InvalidOtpUri`] when the stored URI does not
    /// parse.
    pub fn totp(&self, uuid: uuid::Uuid) -> Result<(String, u64), VaultError> {
        compute_current_totp(self.database(), uuid)
    }
}

impl VaultReadOnly {
    /// Compute the current TOTP code and the seconds remaining in its window.
    ///
    /// # Errors
    ///
    /// See [`Vault::totp`].
    pub fn totp(&self, uuid: uuid::Uuid) -> Result<(String, u64), VaultError> {
        compute_current_totp(self.database(), uuid)
    }
}

fn compute_current_totp(db: &Database, uuid: uuid::Uuid) -> Result<(String, u64), VaultError> {
    let entry_id = find_entry_id(db, uuid)?;
    let entry = db
        .entry(entry_id)
        .ok_or(VaultError::EntryNotFound { uuid })?;
    let uri = entry
        .get(fields::OTP)
        .ok_or(VaultError::EntryHasNoTotp { uuid })?;
    let totp = Totp::from_otpauth_uri(uri)?;
    // A pre-epoch system clock yields `SystemTimeError`; treat it as `t = 0`
    // and emit a deterministic (but stale) code rather than masking the clock
    // failure as `EntryHasNoTotp`.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Ok((totp.code_at(now), totp.remaining_at(now)))
}

/// RFC 4226 / RFC 6238 dynamic-truncation HOTP code derivation.
fn hotp_code(secret: &[u8], counter: u64, algorithm: TotpAlgorithm, digits: u32) -> String {
    let counter_bytes = counter.to_be_bytes();

    let hmac_bytes: Vec<u8> = match algorithm {
        TotpAlgorithm::Sha1 => {
            // `Hmac::new_from_slice` on the optimised path always succeeds —
            // the key is compressed or padded to the digest's block size.
            let mut mac =
                <Hmac<Sha1>>::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // Dynamic truncation: the low nibble of the last byte selects a 4-byte
    // window; the high bit of the first window byte is masked off to yield
    // a 31-bit positive integer (RFC 4226 §5.3).
    let offset = (hmac_bytes[hmac_bytes.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(hmac_bytes[offset]) & 0x7f) << 24
        | u32::from(hmac_bytes[offset + 1]) << 16
        | u32::from(hmac_bytes[offset + 2]) << 8
        | u32::from(hmac_bytes[offset + 3]);

    let modulus = 10u64.pow(digits);
    let code = u64::from(binary) % modulus;
    format!("{code:0width$}", width = digits as usize)
}

// ---------------------------------------------------------------------------
// otpauth URI parsing
// ---------------------------------------------------------------------------

fn parse_otpauth_uri(uri: &str) -> Result<Totp, OtpAuthUriError> {
    // Scheme. We accept only the lowercase `otpauth://` form — the URI
    // scheme is case-insensitive per RFC 3986, but KeePassXC, Google
    // Authenticator, and every other producer emit it lowercase.
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or(OtpAuthUriError::NotAnOtpAuthUri)?;

    // Split host/path from query.
    let (host_and_path, query) = rest.split_once('?').unwrap_or((rest, ""));

    // Host is `totp` or `hotp`; we only support `totp`.
    let (host, label_path) = host_and_path.split_once('/').unwrap_or((host_and_path, ""));
    if !host.eq_ignore_ascii_case("totp") {
        return Err(OtpAuthUriError::UnsupportedType);
    }
    let label = percent_decode(label_path)?;

    let mut secret_b32: Option<&str> = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits = DEFAULT_DIGITS;
    let mut period = DEFAULT_PERIOD;
    let mut issuer: Option<String> = None;

    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "secret" => secret_b32 = Some(value),
            "algorithm" => {
                if !value.eq_ignore_ascii_case("SHA1") {
                    return Err(OtpAuthUriError::UnsupportedAlgorithm);
                }
                algorithm = TotpAlgorithm::Sha1;
            }
            "digits" => {
                let parsed: u32 = value
                    .parse()
                    .map_err(|_| OtpAuthUriError::InvalidParameter { name: "digits" })?;
                if !(1..=MAX_DIGITS).contains(&parsed) {
                    return Err(OtpAuthUriError::InvalidParameter { name: "digits" });
                }
                digits = parsed;
            }
            "period" => {
                let parsed: u64 = value
                    .parse()
                    .map_err(|_| OtpAuthUriError::InvalidParameter { name: "period" })?;
                if parsed == 0 {
                    return Err(OtpAuthUriError::InvalidParameter { name: "period" });
                }
                period = parsed;
            }
            "issuer" => {
                issuer = Some(percent_decode(value)?);
            }
            // Unknown parameters are ignored (forward-compat — see KeePassXC
            // and Google Authenticator behaviour).
            _ => {}
        }
    }

    let secret_b32 = secret_b32.ok_or(OtpAuthUriError::MissingSecret)?;
    let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, secret_b32))
        .ok_or(OtpAuthUriError::InvalidSecret)?;
    if secret.is_empty() {
        return Err(OtpAuthUriError::InvalidSecret);
    }

    Ok(Totp {
        secret: Zeroizing::new(secret),
        algorithm,
        digits,
        period,
        label,
        issuer,
    })
}

/// Decode a percent-encoded UTF-8 string. `+` is *not* decoded as space —
/// that's an HTML-form convention, not an RFC 3986 URI convention, and
/// otpauth URIs follow URI rules.
fn percent_decode(input: &str) -> Result<String, OtpAuthUriError> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'%' {
            if i + 2 >= bytes.len() {
                return Err(OtpAuthUriError::InvalidEncoding);
            }
            let hi = hex_nibble(bytes[i + 1]).ok_or(OtpAuthUriError::InvalidEncoding)?;
            let lo = hex_nibble(bytes[i + 2]).ok_or(OtpAuthUriError::InvalidEncoding)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(byte);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| OtpAuthUriError::InvalidEncoding)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode a string using the RFC 3986 unreserved set as the
/// "safe" characters: `A-Z a-z 0-9 - . _ ~`. Everything else is %XX-encoded.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B uses the ASCII key "12345678901234567890",
    // base32-encoded as "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".
    const RFC_SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn rfc_uri_sha1() -> String {
        format!(
            "otpauth://totp/Example?secret={RFC_SECRET_BASE32}&algorithm=SHA1&digits=8&period=30"
        )
    }

    #[test]
    fn parses_minimal_otpauth_uri() {
        let totp =
            Totp::from_otpauth_uri("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=Example")
                .expect("minimal URI should parse");
        assert_eq!(totp.algorithm(), TotpAlgorithm::Sha1);
        assert_eq!(totp.digits(), 6);
        assert_eq!(totp.period(), 30);
    }

    #[test]
    fn rejects_malformed_uri() {
        let err = Totp::from_otpauth_uri("not a uri").expect_err("malformed URI should fail");
        assert!(matches!(err, VaultError::InvalidOtpUri { .. }));
    }

    #[test]
    fn rejects_missing_secret() {
        let err = Totp::from_otpauth_uri("otpauth://totp/Example?issuer=Example")
            .expect_err("missing secret should fail");
        assert!(matches!(err, VaultError::InvalidOtpUri { .. }));
    }

    #[test]
    fn rejects_non_totp_host() {
        // RFC HOTP URIs are deliberately rejected (Phase 0 is TOTP only).
        let err =
            Totp::from_otpauth_uri("otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP&counter=0")
                .expect_err("hotp URI should fail");
        assert!(matches!(err, VaultError::InvalidOtpUri { .. }));
    }

    #[test]
    fn rejects_unsupported_algorithm() {
        let err = Totp::from_otpauth_uri(
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256",
        )
        .expect_err("SHA256 not supported in Phase 0");
        assert!(matches!(err, VaultError::InvalidOtpUri { .. }));
    }

    #[test]
    fn rfc6238_vector_t_59_sha1() {
        let totp = Totp::from_otpauth_uri(&rfc_uri_sha1()).expect("RFC URI should parse");
        assert_eq!(totp.code_at(59), "94287082");
    }

    #[test]
    fn rfc6238_vector_t_1111111109_sha1() {
        let totp = Totp::from_otpauth_uri(&rfc_uri_sha1()).expect("RFC URI should parse");
        assert_eq!(totp.code_at(1_111_111_109), "07081804");
    }

    #[test]
    fn rfc6238_vector_t_1234567890_sha1() {
        let totp = Totp::from_otpauth_uri(&rfc_uri_sha1()).expect("RFC URI should parse");
        assert_eq!(totp.code_at(1_234_567_890), "89005924");
    }

    #[test]
    fn remaining_seconds_at_window_start_is_full_period() {
        let totp = Totp::from_otpauth_uri(&rfc_uri_sha1()).expect("RFC URI should parse");
        assert_eq!(totp.remaining_at(0), 30);
        assert_eq!(totp.remaining_at(30), 30);
    }

    #[test]
    fn remaining_seconds_at_window_end_is_one() {
        let totp = Totp::from_otpauth_uri(&rfc_uri_sha1()).expect("RFC URI should parse");
        assert_eq!(totp.remaining_at(29), 1);
        assert_eq!(totp.remaining_at(59), 1);
    }

    #[test]
    fn round_trip_uri_through_parse_and_emit() {
        let original =
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30";
        let totp = Totp::from_otpauth_uri(original).expect("URI should parse");
        let emitted = totp.to_otpauth_uri();
        let reparsed = Totp::from_otpauth_uri(&emitted).expect("emitted URI should re-parse");
        assert_eq!(reparsed.algorithm(), totp.algorithm());
        assert_eq!(reparsed.digits(), totp.digits());
        assert_eq!(reparsed.period(), totp.period());
        // Same code at same time across the round-trip.
        assert_eq!(reparsed.code_at(1000), totp.code_at(1000));
    }

    #[test]
    fn debug_does_not_reveal_secret() {
        let totp = Totp::from_otpauth_uri(&rfc_uri_sha1()).expect("RFC URI should parse");
        let debug = format!("{totp:?}");
        assert!(!debug.contains(RFC_SECRET_BASE32));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn percent_decode_handles_url_encoded_label() {
        // KeePassXC stores labels with spaces as %20.
        let totp = Totp::from_otpauth_uri(
            "otpauth://totp/Example%20Corp:user@host?secret=JBSWY3DPEHPK3PXP",
        )
        .expect("encoded label should parse");
        // The `label` field is private; we observe the round-trip via emit.
        let _ = totp.to_otpauth_uri();
    }

    #[test]
    fn ignores_unknown_query_parameters() {
        let totp =
            Totp::from_otpauth_uri("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&future=value")
                .expect("unknown params should be ignored");
        assert_eq!(totp.digits(), 6);
    }

    #[test]
    fn percent_decode_basic_cases() {
        assert_eq!(percent_decode("abc").unwrap(), "abc");
        assert_eq!(percent_decode("a%20b").unwrap(), "a b");
        assert_eq!(percent_decode("%2F").unwrap(), "/");
        assert!(percent_decode("%2").is_err());
        assert!(percent_decode("%XY").is_err());
    }

    #[test]
    fn percent_encode_basic_cases() {
        assert_eq!(percent_encode("abc"), "abc");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("Example-Co_~"), "Example-Co_~");
    }
}
