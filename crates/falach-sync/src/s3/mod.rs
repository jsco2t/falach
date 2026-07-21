// The s3 module's doc comments mention many acronyms and product names (S3,
// AWS, ETag, MinIO, KDBX, SigV4, RFC nnnn, etc.). Backticking every one of
// them — as `clippy::doc_markdown` demands — makes the docs harder to read
// rather than easier; the lint is targeted at catching missed intra-doc
// links, which this module has very few of. Allow it at the module
// boundary; intra-doc links are still validated by `rustdoc` itself.
#![allow(clippy::doc_markdown)]

//! S3 wire-protocol layer (FR-040..047; design.md §2.2.3–§2.2.6).
//!
//! This module owns everything between the [`crate::transport`] trait and the
//! network: SigV4 signing, the `ureq`-backed HTTP client, endpoint URL
//! construction (virtual-hosted vs path-style), ETag parsing, and the
//! high-level [`Client`] composing the four primitives PUT / GET / HEAD /
//! DELETE.
//!
//! Per design.md ADR-1 the S3 stack is *hand-rolled SigV4 + `ureq`*: no
//! `aws-sdk-s3`, no `aws-sigv4`. The signer is ~400 LoC of canonical-request
//! building + signing-key derivation, validated against AWS's published
//! test-vector corpus as a CI gate (`tests/sigv4_aws_test_vectors.rs`).
//!
//! Public types are deliberately re-exported at the [`crate`] root only via
//! the orchestrator's surface (T5.2+); callers outside `falach-sync` should
//! never depend on `crate::s3::*` directly.

pub mod client;
pub mod endpoint;
pub mod error;
pub mod etag;
pub mod http;
pub mod signer;

#[cfg(test)]
pub(crate) mod testing;

pub use client::{Client, GetResult, HeadResult, PutResult, S3ClientBackend};
pub use endpoint::{
    canonicalize_endpoint, AddressingStyle, EndpointBuilder, EndpointConfig, EndpointError,
};
pub use error::{IsPreconditionFailed, S3Error};
pub use etag::{Etag, EtagError};
pub use http::{HttpBackend, HttpClient, HttpError, HttpResponse};
pub use signer::{ResolvedCredentials, Signer, SignerError};
