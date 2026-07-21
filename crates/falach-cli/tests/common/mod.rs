//! Shared helpers for `falach-cli` integration tests.
//!
//! Uses `std::process::Command` directly with the `CARGO_BIN_EXE_falach`
//! env var Cargo sets for tests, avoiding the `assert_cmd` +
//! `predicates` dependency tree (~15 transitives).

#![allow(dead_code)] // helpers, not all tests use every one

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use tempfile::TempDir;

/// Path to the `falach` test binary Cargo built for us.
///
/// `CARGO_BIN_EXE_falach` is set by Cargo's test harness; it does not
/// require the binary to be on `PATH`.
pub fn falach_bin() -> &'static str {
    env!("CARGO_BIN_EXE_falach")
}

/// Build a `Command` for the `falach` binary with an isolated env so
/// host `FALACH_*` settings cannot leak into the test.
pub fn falach_cmd() -> Command {
    let mut cmd = Command::new(falach_bin());
    // `env_clear` would lose `PATH` which clap doesn't need but
    // libraries occasionally do — instead, strip only the falach-
    // specific vars and leave everything else alone.
    cmd.env_remove("FALACH_MASTER_PASSWORD");
    cmd.env_remove("FALACH_STATE_DIR");
    cmd
}

/// Create and register a vault directly via `falach-core` with
/// test-grade (fast) Argon2id parameters, bypassing the spawned binary.
///
/// For tests whose subject is NOT `vault create`: the binary's create
/// path hard-codes production KDF parameters (64 MiB × 3 iterations),
/// and every later unlock re-pays that cost — ~1s of pure Argon2id per
/// spawned invocation, dominating the CLI suite's runtime. Subsequent
/// unlocks read the KDF from the KDBX header, so a vault seeded here
/// makes every downstream binary invocation fast. KDF correctness
/// itself is vault-core's concern; `cli_vault.rs` keeps real
/// production-KDF `vault create` coverage.
pub fn seed_vault(reg: &VaultsToml, id: &str, password: &str) -> PathBuf {
    use falach_core::{
        FalachPaths, KdfParams, MasterPassword, NoRecoveryConfirmed, RegisteredVault, Vault,
        VaultRegistry,
    };

    let path = reg.tempdir.path().join(format!("{id}.kdbx"));
    let kdf = KdfParams {
        memory_kib: 1_024,
        iterations: 1,
        parallelism: 1,
    };
    drop(
        Vault::create(
            &path,
            &MasterPassword::new(password.to_string()),
            None,
            kdf,
            NoRecoveryConfirmed::yes(),
        )
        .expect("seed vault"),
    );

    let paths = FalachPaths::with_registry_file(reg.vaults_toml.clone());
    let mut registry = VaultRegistry::load(paths).expect("load registry");
    registry
        .register(RegisteredVault {
            name: id.to_string(),
            path: path.clone(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            keyfile_path: None,
            extra: toml::Table::new(),
        })
        .expect("register vault");
    registry.save().expect("save registry");
    path
}

/// Run a `falach` invocation with the given args and return
/// `(exit_code, stdout, stderr)`.
pub fn run_args(args: &[&str]) -> (i32, String, String) {
    let output = falach_cmd()
        .args(args)
        .output()
        .expect("failed to spawn falach binary");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(-1);
    (code, stdout, stderr)
}

/// A tempdir holding a `vaults.toml` path Falach can be pointed at via
/// the global `--registry` flag.
///
/// `_tempdir` is held to keep the directory alive for the lifetime of
/// the test. `vaults_toml` is the path to pass with `--registry`.
pub struct VaultsToml {
    pub tempdir: TempDir,
    pub vaults_toml: PathBuf,
}

impl VaultsToml {
    /// Create a fresh tempdir + plan the `vaults.toml` path inside it.
    /// The file itself is not created; the CLI will create it lazily
    /// on first registry save.
    pub fn new() -> Self {
        let tempdir = TempDir::new().expect("create tempdir");
        let vaults_toml = tempdir.path().join("vaults.toml");
        Self {
            tempdir,
            vaults_toml,
        }
    }

    /// `--registry <path>` argument as a `String` (so it can be
    /// borrowed by `Command::arg`).
    pub fn registry_arg(&self) -> String {
        self.vaults_toml.display().to_string()
    }
}

/// Assert that the raw bytes of the file at `path` do NOT contain
/// `needle`. Used by the `set-sync` security test to prove a plaintext
/// secret never lands on disk in `vaults.toml` — a byte scan (not a
/// string search) so a secret split across a lossy UTF-8 boundary can't
/// hide from the assertion.
pub fn assert_file_lacks_bytes(path: &std::path::Path, needle: &str) {
    let contents = std::fs::read(path).expect("read file for secret scan");
    let needle = needle.as_bytes();
    let found = !needle.is_empty()
        && contents
            .windows(needle.len())
            .any(|window| window == needle);
    assert!(
        !found,
        "file {} unexpectedly contains the secret bytes {needle:?}",
        path.display(),
    );
}

/// Run `falach` with `--registry <path>` pointed at `reg`, feeding
/// `stdin_input` on stdin. Returns `(exit_code, stdout, stderr)`.
pub fn run_with_stdin(reg: &VaultsToml, args: &[&str], stdin_input: &str) -> (i32, String, String) {
    let mut cmd = falach_cmd();
    cmd.args(["--registry", &reg.registry_arg()]).args(args);
    run_cmd_with_stdin(&mut cmd, stdin_input)
}

/// Run an already-configured `Command`, feeding `stdin_input` on stdin.
/// Returns `(exit_code, stdout, stderr)`. Used directly by tests that
/// need a non-standard `--registry` argument.
pub fn run_cmd_with_stdin(cmd: &mut Command, stdin_input: &str) -> (i32, String, String) {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn falach binary");
    if !stdin_input.is_empty() {
        let stdin = child.stdin.as_mut().expect("captured stdin");
        stdin
            .write_all(stdin_input.as_bytes())
            .expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait for falach");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(-1);
    (code, stdout, stderr)
}
