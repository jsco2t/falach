//! Phase 0 smoke test for the shared [`TestEnv`] helper.
//!
//! Phase 4+ integration tests are not yet present; this file exists
//! solely to confirm that `tests/common/mod.rs` compiles and that
//! [`TestEnv::new`] produces a usable isolated environment whose
//! tempdir is cleaned up on drop. When Phase 4 lands its first
//! integration test, this smoke file can either stay (cheap to keep)
//! or be removed.

mod common;

use common::TestEnv;

#[test]
fn test_env_constructs_and_provides_paths_rooted_in_tempdir() {
    let env = TestEnv::new();
    let state_dir = env.paths().state_dir();
    assert!(
        state_dir.starts_with(env.tempdir()),
        "TestEnv state dir should be inside its tempdir"
    );
}

#[test]
fn test_env_ensure_exists_creates_state_dir() {
    let env = TestEnv::new();
    let state_dir = env.paths().state_dir().to_path_buf();
    assert!(!state_dir.exists(), "state dir should not exist initially");

    env.paths().ensure_exists().expect("ensure_exists succeeds");
    assert!(
        state_dir.is_dir(),
        "state dir should exist after ensure_exists"
    );
}

#[test]
fn test_env_tempdir_is_removed_on_drop() {
    let path = {
        let env = TestEnv::new();
        env.paths().ensure_exists().expect("ensure_exists");
        env.tempdir().to_path_buf()
    };
    // After the TestEnv is dropped, the tempdir should be gone.
    assert!(
        !path.exists(),
        "tempdir should be removed when TestEnv is dropped: {}",
        path.display()
    );
}
