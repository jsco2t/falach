//! Phase 4 (T4.2) integration tests for the `falach completions
//! <shell>` subcommand and the `make completions` build-time helper.
//!
//! The `make_completions_writes_files` test that touches the
//! `shell-completions/` directory on disk is `#[ignore]`d so the
//! default `cargo test` run never mutates files outside the workspace
//! build tree. Run it via `make test-ignored`.

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::{falach_bin, run_args};

#[test]
fn completions_bash_nonempty_and_contains_falach() {
    let (code, stdout, stderr) = run_args(&["completions", "bash"]);
    assert_eq!(code, 0, "stderr was:\n{stderr}");
    assert!(
        stdout.contains("falach"),
        "bash completion output should reference the bin name; got:\n{}",
        truncate(&stdout)
    );
    assert!(
        !stdout.trim().is_empty(),
        "bash completion output should be non-empty"
    );
}

#[test]
fn completions_zsh_starts_with_compdef_directive() {
    let (code, stdout, stderr) = run_args(&["completions", "zsh"]);
    assert_eq!(code, 0, "stderr was:\n{stderr}");
    assert!(
        stdout.contains("#compdef falach"),
        "zsh completion should start with #compdef directive; got first 200 chars:\n{}",
        truncate(&stdout)
    );
}

#[test]
fn completions_fish_emits_complete_directive() {
    let (code, stdout, stderr) = run_args(&["completions", "fish"]);
    assert_eq!(code, 0, "stderr was:\n{stderr}");
    assert!(
        stdout.contains("complete -c falach"),
        "fish completion should emit `complete -c falach`; got first 200 chars:\n{}",
        truncate(&stdout)
    );
}

#[test]
fn completions_unknown_shell_fails_clap_parse() {
    // `clap_complete::Shell` is a `ValueEnum` accepting `bash`, `zsh`,
    // `fish`, `powershell`, and `elvish`. Anything else is a clap
    // parse error, which exits with clap's documented code 2.
    let (code, _stdout, stderr) = run_args(&["completions", "definitely-not-a-shell-name-xyzzy"]);
    assert_eq!(
        code, 2,
        "clap parse failure should exit 2; stderr was:\n{stderr}"
    );
    // The exact wording is clap's, but every variant of clap's
    // "invalid value" line includes the word "invalid".
    assert!(
        stderr.to_lowercase().contains("invalid"),
        "stderr should explain the invalid value:\n{stderr}"
    );
}

#[test]
fn completions_missing_shell_arg_is_user_error() {
    // clap accepts the bare invocation because `shell` is
    // `Option<Shell>` (so `falach completions --help` works). The
    // dispatcher then surfaces a UserError explaining what's missing.
    let (code, _stdout, stderr) = run_args(&["completions"]);
    assert_eq!(code, 1, "stderr was:\n{stderr}");
    assert!(
        stderr.contains("missing shell argument"),
        "stderr should explain the missing positional:\n{stderr}"
    );
}

#[test]
fn completions_powershell_value_is_accepted() {
    // `powershell` is one of the five `clap_complete::Shell` variants;
    // we accept it even though the Phase-0 support matrix only
    // documents bash/zsh/fish.
    let (code, stdout, stderr) = run_args(&["completions", "powershell"]);
    assert_eq!(code, 0, "stderr was:\n{stderr}");
    assert!(
        !stdout.trim().is_empty(),
        "powershell output should be non-empty"
    );
}

/// `#[ignore]`d — runs `make completions` and verifies the output files
/// land in `shell-completions/`. Touches the actual workspace directory
/// so we serialize via `make test-ignored`.
#[test]
#[ignore = "spawns `make completions` which writes to shell-completions/; run via `make test-ignored`"]
fn make_completions_writes_shell_completions_files() {
    let workspace = workspace_root();
    let output = Command::new("make")
        .arg("completions")
        .current_dir(&workspace)
        .output()
        .expect("spawn make completions");
    assert!(
        output.status.success(),
        "make completions failed: stderr={}\nstdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );

    let out_dir = workspace.join("shell-completions");
    for filename in ["falach.bash", "_falach", "falach.fish"] {
        let path = out_dir.join(filename);
        let meta =
            std::fs::metadata(&path).unwrap_or_else(|e| panic!("missing {}: {e}", path.display()));
        assert!(
            meta.len() > 0,
            "{} should be non-empty (got {} bytes)",
            path.display(),
            meta.len()
        );
    }
}

/// Locate the workspace root (two levels up from `Cargo.toml` of this
/// crate, mirroring the build-time helper).
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(std::path::Path::parent)
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf)
}

fn truncate(s: &str) -> &str {
    s.get(..200).unwrap_or(s)
}

#[test]
fn binary_path_is_set_for_test_harness() {
    // Sanity-check the test environment: `CARGO_BIN_EXE_falach`
    // resolves to a path Cargo built for us. If this fails the rest
    // of the file produces confusing errors.
    let path = falach_bin();
    assert!(!path.is_empty(), "CARGO_BIN_EXE_falach was not set");
}
