//! S3 endpoint URL construction (design.md §2.2.6).
//!
//! Handles the two S3 addressing styles:
//!
//! - **Virtual-hosted** (AWS default): `https://{bucket}.{host}/{key}` —
//!   used for AWS S3 with bucket names that satisfy DNS-name rules.
//! - **Path-style**: `https://{host}/{bucket}/{key}` — required by most
//!   self-hosted backends (MinIO, Garage, SeaweedFS) because they don't
//!   bind bucket names to DNS subdomains; also forced for AWS S3 when the
//!   bucket name contains a `.` (the TLS wildcard cert
//!   `*.s3.<region>.amazonaws.com` doesn't match multi-label subdomains).
//!
//! Also exports [`canonicalize_endpoint`] — used by T5.1's
//! `DuplicateTarget` registry-side uniqueness check (ADR-6). Two endpoints
//! that differ only in case, trailing slash, or `https://` prefix
//! canonicalize to the same string.

/// Errors returned by [`EndpointBuilder::from_config`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointError {
    /// The endpoint URL is missing the scheme (`https://` or `http://`).
    #[error("endpoint URL is missing the scheme (https:// or http://)")]
    MissingScheme,

    /// The endpoint URL's scheme is not HTTP or HTTPS.
    #[error("endpoint URL scheme `{0}` is unsupported (only http/https)")]
    UnsupportedScheme(String),

    /// The endpoint URL has no host component after the scheme.
    #[error("endpoint URL has no host")]
    MissingHost,

    /// URL userinfo is forbidden because endpoint strings are persisted and
    /// may be rendered in diagnostics; accepting it could leak credentials.
    #[error("endpoint URL must not contain userinfo (user:password@host)")]
    UserInfoNotAllowed,

    /// Custom endpoints are origins, not full object URLs. Paths, queries,
    /// and fragments would corrupt the signed host/URL construction and may
    /// carry secret material that must not be persisted or rendered.
    #[error("endpoint URL must contain only a host and optional port")]
    InvalidAuthority,

    /// The region is required (it's part of the SigV4 credential scope).
    #[error("region is required (empty string was supplied)")]
    MissingRegion,
}

/// Which S3 addressing style to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressingStyle {
    /// `https://{bucket}.{host}/{key}` — AWS default; requires bucket name
    /// to be DNS-safe.
    VirtualHosted,
    /// `https://{host}/{bucket}/{key}` — required for MinIO/Garage/etc.,
    /// and forced when the bucket name contains a `.`.
    PathStyle,
}

/// Inputs needed by [`EndpointBuilder::from_config`].
///
/// This struct exists to keep the constructor's argument list readable;
/// the eventual `S3Config` (T5.1) supplies these fields verbatim.
#[derive(Debug, Clone)]
pub struct EndpointConfig<'a> {
    /// S3 endpoint URL with scheme. `None` defaults to
    /// `https://s3.<region>.amazonaws.com`.
    pub endpoint: Option<&'a str>,
    /// AWS region (e.g. `us-east-1`). Required.
    pub region: &'a str,
    /// Bucket name. Used to validate addressing style.
    pub bucket: &'a str,
    /// Force path-style addressing. When `true`, virtual-hosted is never
    /// used regardless of bucket name. When `false`, the builder may STILL
    /// force path-style if the bucket name contains `.`.
    pub force_path_style: bool,
}

/// Builder + cached state for constructing S3 request URLs.
#[derive(Debug, Clone)]
pub struct EndpointBuilder {
    /// Scheme + host (no trailing slash; no path).
    /// Example: `"https://s3.us-east-1.amazonaws.com"`.
    base: String,
    /// Just the host[:port] portion (used for the `Host:` header pre-signing).
    base_host: String,
    /// Resolved addressing style — may differ from the configured value
    /// when the bucket name forced a switch to path-style.
    pub(crate) style: AddressingStyle,
}

impl EndpointBuilder {
    /// Build an `EndpointBuilder` from configuration. Decides the resolved
    /// `AddressingStyle` by combining `force_path_style` with the bucket
    /// name (a `.` in the bucket forces path-style regardless).
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] when the endpoint URL is malformed
    /// (missing scheme/host or non-HTTP scheme) or the region is empty.
    pub fn from_config(cfg: &EndpointConfig<'_>) -> Result<Self, EndpointError> {
        if cfg.region.is_empty() {
            return Err(EndpointError::MissingRegion);
        }
        let endpoint_str = match cfg.endpoint {
            Some(s) => s.to_string(),
            None => format!("https://s3.{}.amazonaws.com", cfg.region),
        };

        let (scheme, rest) = split_scheme(&endpoint_str)?;
        let base_host = strip_trailing_slash(rest).to_string();
        if base_host.is_empty() {
            return Err(EndpointError::MissingHost);
        }
        if base_host.contains('@') {
            return Err(EndpointError::UserInfoNotAllowed);
        }
        if base_host.contains(['/', '?', '#']) {
            return Err(EndpointError::InvalidAuthority);
        }
        validate_authority(&base_host)?;

        let base = format!("{scheme}://{base_host}");

        // Bucket names with `.` force path-style (TLS-cert wildcards don't
        // match multi-label subdomains).
        let style =
            if cfg.force_path_style || cfg.bucket.contains('.') || base_host.starts_with('[') {
                AddressingStyle::PathStyle
            } else {
                AddressingStyle::VirtualHosted
            };

        Ok(Self {
            base,
            base_host,
            style,
        })
    }

    /// The resolved addressing style for this endpoint (may have been
    /// auto-promoted to `PathStyle` from `VirtualHosted` if the bucket
    /// name contains `.`).
    #[must_use]
    pub fn style(&self) -> AddressingStyle {
        self.style
    }

    /// Construct the full URL for an object request.
    ///
    /// The `key` is appended verbatim — the caller is responsible for
    /// percent-encoding any unsafe characters (or relying on the SigV4
    /// signer's canonical-URI encoding, which the s3::Client does today).
    #[must_use]
    pub fn object_url(&self, bucket: &str, key: &str) -> String {
        let path = key.trim_start_matches('/');
        match self.style {
            AddressingStyle::VirtualHosted => {
                format!(
                    "{}://{}.{}/{}",
                    scheme_of(&self.base),
                    bucket,
                    self.base_host,
                    path
                )
            }
            AddressingStyle::PathStyle => {
                format!("{}/{}/{}", self.base, bucket, path)
            }
        }
    }

    /// The host (with port if non-default) to include in the `Host:` header
    /// of HTTP requests.
    ///
    /// For virtual-hosted addressing this is `<bucket>.<endpoint-host>`;
    /// for path-style it's just `<endpoint-host>`.
    #[must_use]
    pub fn host_header(&self, bucket: &str) -> String {
        match self.style {
            AddressingStyle::VirtualHosted => format!("{}.{}", bucket, self.base_host),
            AddressingStyle::PathStyle => self.base_host.clone(),
        }
    }
}

/// Canonicalize an endpoint string for the registry's `DuplicateTarget`
/// uniqueness check (ADR-6). Two endpoints that differ only in case,
/// trailing slash, or `https://` prefix canonicalize to the same string.
///
/// Used by T5.1's `Sync::configure_remote` to detect when two vaults are
/// configured to write to the same S3 target.
#[must_use]
pub fn canonicalize_endpoint(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let no_scheme = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower)
        .to_string();
    no_scheme.trim_end_matches('/').to_string()
}

/// Split `scheme://rest` → `("https", "host[:port][/path]")`.
fn split_scheme(s: &str) -> Result<(&str, &str), EndpointError> {
    let (scheme, rest) = s.split_once("://").ok_or(EndpointError::MissingScheme)?;
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower != "https" && scheme_lower != "http" {
        return Err(EndpointError::UnsupportedScheme(scheme.to_string()));
    }
    // We don't lowercase the scheme in the returned base because the
    // canonical form for HTTP URIs uses the lowercase scheme already;
    // matching that, we always emit lowercase.
    let scheme_canonical = if scheme_lower == "https" {
        "https"
    } else {
        "http"
    };
    Ok((scheme_canonical, rest))
}

/// Strip a single trailing `/` (no recursion).
fn strip_trailing_slash(s: &str) -> &str {
    s.trim_end_matches('/')
}

/// Validate the `host[:port]` authority subset accepted by S3 endpoints.
/// Bracketed IPv6 literals are supported; unbracketed IPv6 is rejected so
/// colons cannot be confused with a port separator.
fn validate_authority(authority: &str) -> Result<(), EndpointError> {
    if authority.chars().any(char::is_whitespace) {
        return Err(EndpointError::InvalidAuthority);
    }

    let port = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, remainder) = bracketed
            .split_once(']')
            .ok_or(EndpointError::InvalidAuthority)?;
        if host.is_empty() || host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(EndpointError::InvalidAuthority);
        }
        if remainder.is_empty() {
            None
        } else {
            Some(
                remainder
                    .strip_prefix(':')
                    .ok_or(EndpointError::InvalidAuthority)?,
            )
        }
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() || host.contains(':') {
            return Err(EndpointError::InvalidAuthority);
        }
        Some(port)
    } else {
        if authority.is_empty() {
            return Err(EndpointError::MissingHost);
        }
        None
    };

    if let Some(port) = port {
        if port.is_empty() || port.parse::<u16>().is_err() {
            return Err(EndpointError::InvalidAuthority);
        }
    }
    Ok(())
}

/// Extract the scheme portion (`"https"` or `"http"`) of a `base` URL.
/// Panics if `base` is malformed — but `base` is only ever produced by
/// `from_config`, which validates the scheme.
fn scheme_of(base: &str) -> &str {
    base.split_once("://").map_or("https", |(s, _)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(bucket: &str, force_path_style: bool) -> EndpointConfig<'_> {
        EndpointConfig {
            endpoint: None,
            region: "us-east-1",
            bucket,
            force_path_style,
        }
    }

    // -- TC-EP-001 ----------------------------------------------------------
    #[test]
    fn virtual_hosted_url_for_dns_safe_bucket() {
        let b = EndpointBuilder::from_config(&cfg("my-bucket", false)).expect("build");
        assert_eq!(b.style(), AddressingStyle::VirtualHosted);
        assert_eq!(
            b.object_url("my-bucket", "vaults/work.kdbx"),
            "https://my-bucket.s3.us-east-1.amazonaws.com/vaults/work.kdbx"
        );
        assert_eq!(
            b.host_header("my-bucket"),
            "my-bucket.s3.us-east-1.amazonaws.com"
        );
    }

    // -- TC-EP-002 ----------------------------------------------------------
    #[test]
    fn path_style_url_when_forced() {
        let b = EndpointBuilder::from_config(&cfg("my-bucket", true)).expect("build");
        assert_eq!(b.style(), AddressingStyle::PathStyle);
        assert_eq!(
            b.object_url("my-bucket", "work.kdbx"),
            "https://s3.us-east-1.amazonaws.com/my-bucket/work.kdbx"
        );
        assert_eq!(b.host_header("my-bucket"), "s3.us-east-1.amazonaws.com");
    }

    // -- TC-EP-003 ----------------------------------------------------------
    #[test]
    fn bucket_with_dot_auto_promotes_to_path_style() {
        // `force_path_style = false`, but the dot in the bucket name
        // forces path-style anyway (TLS-cert wildcard issue).
        let b = EndpointBuilder::from_config(&cfg("my.dotted.bucket", false)).expect("build");
        assert_eq!(b.style(), AddressingStyle::PathStyle);
        assert_eq!(
            b.object_url("my.dotted.bucket", "key"),
            "https://s3.us-east-1.amazonaws.com/my.dotted.bucket/key"
        );
    }

    // -- TC-EP-004 ----------------------------------------------------------
    #[test]
    fn custom_endpoint_overrides_aws_default() {
        let cfg = EndpointConfig {
            endpoint: Some("https://minio.example.com:9000"),
            region: "us-east-1",
            bucket: "my-bucket",
            force_path_style: true,
        };
        let b = EndpointBuilder::from_config(&cfg).expect("build");
        assert_eq!(
            b.object_url("my-bucket", "key"),
            "https://minio.example.com:9000/my-bucket/key"
        );
        assert_eq!(b.host_header("my-bucket"), "minio.example.com:9000");
    }

    // -- TC-EP-005 ----------------------------------------------------------
    #[test]
    fn missing_scheme_is_an_error() {
        let cfg = EndpointConfig {
            endpoint: Some("minio.example.com"),
            region: "us-east-1",
            bucket: "my-bucket",
            force_path_style: true,
        };
        assert!(matches!(
            EndpointBuilder::from_config(&cfg),
            Err(EndpointError::MissingScheme)
        ));
    }

    // -- TC-EP-006 ----------------------------------------------------------
    #[test]
    fn unsupported_scheme_is_an_error() {
        let cfg = EndpointConfig {
            endpoint: Some("ftp://example.com"),
            region: "us-east-1",
            bucket: "my-bucket",
            force_path_style: true,
        };
        let err = EndpointBuilder::from_config(&cfg).expect_err("ftp rejected");
        assert!(matches!(err, EndpointError::UnsupportedScheme(s) if s == "ftp"));
    }

    #[test]
    fn endpoint_userinfo_is_rejected() {
        let cfg = EndpointConfig {
            endpoint: Some("https://user:secret@example.com"),
            region: "us-east-1",
            bucket: "my-bucket",
            force_path_style: true,
        };
        assert!(matches!(
            EndpointBuilder::from_config(&cfg),
            Err(EndpointError::UserInfoNotAllowed)
        ));
    }

    #[test]
    fn endpoint_path_query_and_fragment_are_rejected() {
        for endpoint in [
            "https://example.com/base-path",
            "https://example.com?token=secret",
            "https://example.com#fragment",
        ] {
            let cfg = EndpointConfig {
                endpoint: Some(endpoint),
                region: "us-east-1",
                bucket: "my-bucket",
                force_path_style: true,
            };
            assert!(
                matches!(
                    EndpointBuilder::from_config(&cfg),
                    Err(EndpointError::InvalidAuthority)
                ),
                "accepted invalid endpoint: {endpoint}"
            );
        }
    }

    #[test]
    fn malformed_endpoint_authorities_are_rejected() {
        for endpoint in [
            "https://:9000",
            "https://host:not-a-port",
            "https://host:70000",
            "https://white space.example",
            "https://2001:db8::1",
            "https://[not-ipv6]",
        ] {
            let cfg = EndpointConfig {
                endpoint: Some(endpoint),
                region: "us-east-1",
                bucket: "my-bucket",
                force_path_style: true,
            };
            assert!(
                matches!(
                    EndpointBuilder::from_config(&cfg),
                    Err(EndpointError::InvalidAuthority)
                ),
                "accepted invalid endpoint: {endpoint}"
            );
        }
    }

    #[test]
    fn bracketed_ipv6_authority_with_port_is_accepted() {
        let cfg = EndpointConfig {
            endpoint: Some("http://[2001:db8::1]:9000"),
            region: "us-east-1",
            bucket: "my-bucket",
            force_path_style: false,
        };
        let endpoint = EndpointBuilder::from_config(&cfg).expect("valid IPv6 authority");
        assert_eq!(endpoint.style(), AddressingStyle::PathStyle);
        assert_eq!(endpoint.host_header("my-bucket"), "[2001:db8::1]:9000");
    }

    // -- TC-EP-007 ----------------------------------------------------------
    #[test]
    fn missing_region_is_an_error() {
        let cfg = EndpointConfig {
            endpoint: Some("https://minio.example.com"),
            region: "",
            bucket: "my-bucket",
            force_path_style: true,
        };
        assert!(matches!(
            EndpointBuilder::from_config(&cfg),
            Err(EndpointError::MissingRegion)
        ));
    }

    // -- TC-EP-008 ----------------------------------------------------------
    #[test]
    fn canonicalize_endpoint_normalizes_case_scheme_and_trailing_slash() {
        assert_eq!(canonicalize_endpoint("HTTPS://Example.COM/"), "example.com");
        assert_eq!(canonicalize_endpoint("https://example.com"), "example.com");
        assert_eq!(canonicalize_endpoint("http://example.com/"), "example.com");
        // Already-canonical input is idempotent.
        assert_eq!(canonicalize_endpoint("example.com"), "example.com");
        // Two equivalent forms canonicalize to the same string.
        let a = canonicalize_endpoint("HTTPS://S3.us-east-1.amazonaws.com/");
        let b = canonicalize_endpoint("https://s3.us-east-1.amazonaws.com");
        assert_eq!(a, b);
    }

    // -- TC-EP-009 ----------------------------------------------------------
    #[test]
    fn key_with_leading_slash_is_normalized_to_no_leading_slash() {
        let b = EndpointBuilder::from_config(&cfg("my-bucket", false)).expect("build");
        // A leading slash in the key would produce a double-slash in the
        // URL — strip it.
        assert_eq!(
            b.object_url("my-bucket", "/work.kdbx"),
            "https://my-bucket.s3.us-east-1.amazonaws.com/work.kdbx"
        );
    }
}
