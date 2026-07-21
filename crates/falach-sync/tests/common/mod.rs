//! Shared test helpers for the s3-sync integration tests.
//!
//! Compiled independently into each integration test binary that does
//! `mod common;`. The `dead_code` allow on submodules reflects that any
//! one test file uses only a subset.

#![allow(dead_code, clippy::doc_markdown)]

pub mod minio_env;
pub mod sync_env;
