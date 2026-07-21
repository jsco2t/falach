//! Shared integration-test helpers.
//!
//! Per Test Plan §8.4 (in implementation-plan §8), this module hosts
//! helpers used across every integration test that lands from Phase 4
//! onward. Phase 0 introduces [`TestEnv`] (the principal helper) and the
//! conventions documented in [`CONTRIBUTING.md`].
//!
//! Conventions enforced by these helpers:
//!
//! - **No test touches `$HOME` directly.** Every test that needs a
//!   state dir constructs a [`TestEnv`], which roots a fresh
//!   [`falach_core::FalachPaths`] inside a `tempfile::TempDir`.
//! - **Auto-cleanup on drop.** The `TempDir` owned by [`TestEnv`] is
//!   removed when the test scope ends; no test leaves files behind.

#![allow(dead_code)]

pub mod entry_fixtures;

use falach_core::{FalachPaths, KdfParams, MasterPassword};
use tempfile::TempDir;

/// An isolated test environment.
///
/// Owns a `tempfile::TempDir` and a [`FalachPaths`] rooted in it. On
/// drop, the tempdir disappears.
pub struct TestEnv {
    paths: FalachPaths,
    // Field is held to keep the TempDir alive for the lifetime of the
    // TestEnv; it's accessed via [`Self::tempdir`].
    tempdir: TempDir,
}

impl TestEnv {
    /// Create a fresh isolated environment. The state dir is at
    /// `<tempdir>/state` and is created on demand by the caller via
    /// `paths().ensure_exists()` (matching production behavior).
    pub fn new() -> Self {
        let tempdir = TempDir::new().expect("test env: create tempdir");
        let state = tempdir.path().join("state");
        let paths = FalachPaths::with_state_dir(state);
        Self { paths, tempdir }
    }

    /// The [`FalachPaths`] rooted in this environment's tempdir.
    pub fn paths(&self) -> &FalachPaths {
        &self.paths
    }

    /// The root tempdir path. Tests that need to inspect or create
    /// arbitrary sibling files under the tempdir use this.
    pub fn tempdir(&self) -> &std::path::Path {
        self.tempdir.path()
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}

pub fn master(value: &str) -> MasterPassword {
    MasterPassword::new(value.to_string())
}

pub fn fast_kdf() -> KdfParams {
    KdfParams {
        memory_kib: 1_024,
        iterations: 1,
        parallelism: 1,
    }
}

pub fn assert_no_temp_files(dir: &std::path::Path) {
    let temps: Vec<_> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().extension().is_some_and(|ext| ext == "tmp")
                || entry.file_name().to_string_lossy().starts_with(".tmp")
                || entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".falach-tmp-")
        })
        .collect();
    assert!(
        temps.is_empty(),
        "unexpected temp files: {:?}",
        temps
            .iter()
            .map(std::fs::DirEntry::file_name)
            .collect::<Vec<_>>()
    );
}
