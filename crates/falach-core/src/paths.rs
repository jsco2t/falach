//! Resolve the canonical Falach state directory and the `vaults.toml`
//! location.
//!
//! Per design §2.2.1 and PRD Decision #16, the state directory is
//! `$HOME/.local/state/falach/` on both macOS and Linux — deliberately
//! consistent across platforms, deliberately NOT following macOS
//! `Application Support/`. We resolve `$HOME` directly instead of using
//! the `dirs` crate because `dirs::state_dir()` returns
//! `~/Library/Application Support/...` on macOS, which would contradict
//! the project's "same path everywhere" promise and could silently
//! diverge from registries users created on Linux.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::error::VaultError;

/// Resolved paths for a Falach installation.
///
/// All filesystem operations in `falach-core` route their path
/// resolution through this type. Construct via [`Self::from_env`] in
/// production code, or [`Self::with_state_dir`] in tests.
#[derive(Debug, Clone)]
pub struct FalachPaths {
    state_dir: PathBuf,
    /// The user-configuration directory (`$XDG_CONFIG_HOME/falach`, else
    /// `$HOME/.config/falach`). Distinct from [`Self::state_dir`] per the
    /// config-vs-state split (TUI enhancements design §2.2.5): user-edited
    /// preferences live here, machine-managed state stays in `state_dir`.
    config_dir: PathBuf,
    /// Explicit registry-file override (e.g. the CLI's `--registry`
    /// flag). `None` means the conventional `<state_dir>/vaults.toml`.
    registry_file: Option<PathBuf>,
}

impl FalachPaths {
    /// Resolve the state directory from `$HOME`.
    ///
    /// Returns [`VaultError::HomeUnresolvable`] if the `HOME` environment
    /// variable is absent or empty. The library must not panic in
    /// CI / containers / headless services where `$HOME` is missing.
    pub fn from_env() -> Result<Self, VaultError> {
        // Read once and delegate to the env-free helper so the body's
        // logic (empty-string filtering, path composition) is unit-
        // testable without mutating process env vars — env mutation is
        // `unsafe` in Rust 1.85+ and races concurrent `getenv` calls
        // anywhere else in the process.
        let home = std::env::var_os("HOME");
        let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");
        Self::from_env_values(home.as_deref(), xdg_config_home.as_deref())
    }

    /// Resolve from pre-fetched optional `HOME` and `XDG_CONFIG_HOME`
    /// values.
    ///
    /// `HOME` is required (`None`/`Some("")` → [`VaultError::HomeUnresolvable`])
    /// — it anchors the state directory and the config-dir fallback.
    /// `XDG_CONFIG_HOME`, when present and non-empty, roots the config
    /// directory at `$XDG_CONFIG_HOME/falach`; otherwise it falls back to
    /// `$HOME/.config/falach`. Crate-private so tests exercise the
    /// resolution without mutating process env.
    pub(crate) fn from_env_values(
        home: Option<&OsStr>,
        xdg_config_home: Option<&OsStr>,
    ) -> Result<Self, VaultError> {
        let home = home
            .filter(|v| !v.is_empty())
            .ok_or(VaultError::HomeUnresolvable)?;
        Ok(Self::from_home(
            home,
            xdg_config_home.filter(|v| !v.is_empty()),
        ))
    }

    /// Compose the state and config directory paths from a known-good
    /// `HOME` value plus an optional (already-non-empty-filtered)
    /// `XDG_CONFIG_HOME`.
    ///
    /// `home` must be non-empty; callers (`from_env`, `from_env_values`)
    /// enforce this. Crate-private — production callers go through
    /// `from_env`; tests use `from_env_values` or `with_state_dir`.
    fn from_home(home: &OsStr, xdg_config_home: Option<&OsStr>) -> Self {
        let mut state_dir = PathBuf::from(home);
        state_dir.push(".local");
        state_dir.push("state");
        state_dir.push("falach");

        let config_dir = xdg_config_home.map_or_else(
            || PathBuf::from(home).join(".config").join("falach"),
            |xdg| PathBuf::from(xdg).join("falach"),
        );

        Self {
            state_dir,
            config_dir,
            registry_file: None,
        }
    }

    /// Construct from an explicit state directory.
    ///
    /// Used by tests to root the state dir inside a `tempfile::TempDir`.
    /// The config directory defaults to the same path; tests that also
    /// exercise `config.toml` I/O should chain [`Self::with_config_dir`]
    /// to isolate it. Not for production use.
    pub fn with_state_dir(state_dir: PathBuf) -> Self {
        Self {
            config_dir: state_dir.clone(),
            state_dir,
            registry_file: None,
        }
    }

    /// Override the config directory (builder-style, for tests). Lets a
    /// test root `config.toml` inside a `tempfile::TempDir` independently
    /// of the state directory. Not for production use.
    #[must_use]
    pub fn with_config_dir(mut self, config_dir: PathBuf) -> Self {
        self.config_dir = config_dir;
        self
    }

    /// Construct from an explicit registry-file path (e.g. the CLI's
    /// `--registry` flag). The file's parent directory becomes the state
    /// directory, and [`Self::vaults_toml`] returns exactly the given
    /// path — the file name the caller chose is honored, not replaced
    /// with the conventional `vaults.toml`.
    pub fn with_registry_file(registry_file: PathBuf) -> Self {
        // `Path::parent()` yields `Some("")` for a bare file name; both
        // that and `None` mean "the current directory".
        let state_dir = match registry_file.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        Self {
            config_dir: state_dir.clone(),
            state_dir,
            registry_file: Some(registry_file),
        }
    }

    /// The resolved state directory (`$HOME/.local/state/falach`).
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// The resolved user-config directory (`$XDG_CONFIG_HOME/falach`, else
    /// `$HOME/.config/falach`). Holds `config.toml` and `themes/`.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// The user-config file path: `<config_dir>/config.toml`.
    pub fn config_toml(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// The vault-registry file path: the explicit override when one was
    /// given ([`Self::with_registry_file`]), else `<state_dir>/vaults.toml`.
    pub fn vaults_toml(&self) -> PathBuf {
        self.registry_file
            .clone()
            .unwrap_or_else(|| self.state_dir.join("vaults.toml"))
    }

    /// Ensure the state directory exists with mode `0700` (POSIX).
    ///
    /// Idempotent — safe to call from multiple call sites (registry
    /// load, vault create). If the directory already exists, its
    /// permissions are not modified (re-tightening on every load would
    /// surprise users who deliberately loosened it for, e.g., a backup
    /// process; loosened state dirs are flagged elsewhere, not silently
    /// reset).
    pub fn ensure_exists(&self) -> Result<(), VaultError> {
        if self.state_dir.exists() {
            return Ok(());
        }

        std::fs::create_dir_all(&self.state_dir).map_err(|source| VaultError::Io {
            source,
            path: self.state_dir.clone(),
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&self.state_dir, perms).map_err(|source| VaultError::Io {
                source,
                path: self.state_dir.clone(),
            })?;
        }

        Ok(())
    }

    /// Ensure the config directory exists with mode `0700` (POSIX).
    ///
    /// Idempotent, mirroring [`Self::ensure_exists`]. Created lazily on
    /// first-run config generation. Uses `0700` because, while `config.toml`
    /// holds no secrets, it can encode the user's keymap/theme choices and
    /// there is no reason to make the directory world-readable.
    pub fn ensure_config_dir_exists(&self) -> Result<(), VaultError> {
        if self.config_dir.exists() {
            return Ok(());
        }

        std::fs::create_dir_all(&self.config_dir).map_err(|source| VaultError::Io {
            source,
            path: self.config_dir.clone(),
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&self.config_dir, perms).map_err(|source| VaultError::Io {
                source,
                path: self.config_dir.clone(),
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use tempfile::TempDir;

    // -------------------------------------------------------------------
    // Pure resolution-logic tests — no env mutation, no `unsafe`.
    //
    // These exercise `from_home_value` directly. Together they cover the
    // three branches of `from_env`'s body (HOME set, HOME absent, HOME
    // empty) without touching process env state, which is `unsafe` in
    // Rust 1.85+ and would race concurrent `getenv` calls elsewhere in
    // the test process (notably `tempfile::TempDir::new` reading
    // `TMPDIR`).
    // -------------------------------------------------------------------

    #[test]
    fn from_env_values_returns_state_dir_under_home_when_present() {
        let paths = FalachPaths::from_env_values(Some(OsStr::new("/tmp/jasontest")), None)
            .expect("HOME set");
        assert_eq!(
            paths.state_dir(),
            Path::new("/tmp/jasontest/.local/state/falach"),
        );
    }

    #[test]
    fn from_env_values_returns_err_when_none() {
        let err = FalachPaths::from_env_values(None, None).expect_err("HOME absent");
        assert!(matches!(err, VaultError::HomeUnresolvable));
    }

    #[test]
    fn from_env_values_returns_err_when_empty() {
        let err = FalachPaths::from_env_values(Some(OsStr::new("")), None).expect_err("HOME empty");
        assert!(matches!(err, VaultError::HomeUnresolvable));
    }

    #[test]
    fn config_dir_falls_back_to_home_dot_config_when_xdg_absent() {
        let paths = FalachPaths::from_env_values(Some(OsStr::new("/home/jt")), None)
            .expect("HOME set, XDG absent");
        assert_eq!(
            paths.config_dir(),
            Path::new("/home/jt/.config/falach"),
            "config dir falls back to $HOME/.config/falach"
        );
        assert_eq!(
            paths.config_toml(),
            PathBuf::from("/home/jt/.config/falach/config.toml")
        );
    }

    #[test]
    fn config_dir_honors_xdg_config_home_when_present() {
        let paths = FalachPaths::from_env_values(
            Some(OsStr::new("/home/jt")),
            Some(OsStr::new("/custom/xdg")),
        )
        .expect("HOME + XDG set");
        assert_eq!(
            paths.config_dir(),
            Path::new("/custom/xdg/falach"),
            "a non-empty XDG_CONFIG_HOME roots the config dir"
        );
        // The state dir stays anchored on HOME regardless of XDG.
        assert_eq!(paths.state_dir(), Path::new("/home/jt/.local/state/falach"));
    }

    #[test]
    fn config_dir_ignores_empty_xdg_config_home() {
        let paths =
            FalachPaths::from_env_values(Some(OsStr::new("/home/jt")), Some(OsStr::new("")))
                .expect("HOME set, XDG empty");
        assert_eq!(
            paths.config_dir(),
            Path::new("/home/jt/.config/falach"),
            "an empty XDG_CONFIG_HOME is treated as absent"
        );
    }

    #[test]
    fn with_config_dir_overrides_only_the_config_dir() {
        let paths = FalachPaths::with_state_dir(PathBuf::from("/s/state"))
            .with_config_dir(PathBuf::from("/c/config"));
        assert_eq!(paths.state_dir(), Path::new("/s/state"));
        assert_eq!(paths.config_dir(), Path::new("/c/config"));
        assert_eq!(paths.config_toml(), PathBuf::from("/c/config/config.toml"));
    }

    #[test]
    fn vaults_toml_is_state_dir_slash_vaults_toml() {
        let paths = FalachPaths::with_state_dir(PathBuf::from("/some/state/dir"));
        assert_eq!(
            paths.vaults_toml(),
            PathBuf::from("/some/state/dir/vaults.toml")
        );
    }

    #[test]
    fn with_registry_file_honors_the_exact_path() {
        let paths = FalachPaths::with_registry_file(PathBuf::from("/backups/registry-2026.toml"));
        assert_eq!(
            paths.vaults_toml(),
            PathBuf::from("/backups/registry-2026.toml"),
            "the caller-supplied file name must be used, not vaults.toml"
        );
        assert_eq!(paths.state_dir(), Path::new("/backups"));
    }

    #[test]
    fn with_registry_file_bare_filename_uses_current_dir() {
        let paths = FalachPaths::with_registry_file(PathBuf::from("registry.toml"));
        assert_eq!(paths.vaults_toml(), PathBuf::from("registry.toml"));
        assert_eq!(paths.state_dir(), Path::new("."));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_exists_creates_with_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().expect("create tempdir");
        let state = tmp.path().join("state-dir-fresh");
        let paths = FalachPaths::with_state_dir(state.clone());

        paths.ensure_exists().expect("ensure_exists succeeds");
        assert!(state.is_dir(), "state dir should exist");

        let mode = std::fs::metadata(&state)
            .expect("stat state dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "state dir must be created with mode 0700");
    }

    #[test]
    fn ensure_exists_is_idempotent() {
        let tmp = TempDir::new().expect("create tempdir");
        let state = tmp.path().join("state-dir-idempotent");
        let paths = FalachPaths::with_state_dir(state.clone());

        paths.ensure_exists().expect("first call");
        paths.ensure_exists().expect("second call is a no-op");
        assert!(state.is_dir(), "state dir still exists after two calls");
    }

    // -------------------------------------------------------------------
    // Single env-mutating smoke test for `from_env` itself.
    //
    // The unit tests above prove the resolution logic; this one confirms
    // that `from_env` correctly reads `HOME` and passes the value
    // through. It is marked `#[ignore]` because env mutation in `cargo
    // test`'s default parallel mode is racy against any other test in
    // the process that reads env vars (e.g., `TempDir::new` reading
    // `TMPDIR`). Run it explicitly when needed:
    //
    //     cargo test -- --ignored --test-threads=1
    //
    // The `EnvGuard` helper below restores `HOME` on drop so this test
    // is safe to run repeatedly and does not leak state.
    // -------------------------------------------------------------------

    /// RAII guard that saves the current value of `HOME`, replaces it,
    /// and restores the original on drop.
    ///
    /// SAFETY note for future maintainers: `std::env::set_var` is
    /// `unsafe` in Rust 1.85+ because it races concurrent `getenv` calls
    /// anywhere in the process. There is no in-process synchronization
    /// that can fully eliminate this race — `getenv` callers in other
    /// crates (notably libc-level callers and `tempfile`'s `TMPDIR`
    /// resolution) do not consult any application-level mutex. Marking
    /// the single test that uses this helper `#[ignore]` keeps it out
    /// of the default-parallel test run; explicit serial runs
    /// (`--test-threads=1`) provide the safety guarantee.
    #[allow(unsafe_code)] // documented above; only used by an #[ignore]d test
    struct EnvGuard {
        var: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        #[allow(unsafe_code)]
        fn set(var: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(var);
            // SAFETY: see struct-level note. Caller is responsible for
            // ensuring the test is run with `--test-threads=1`.
            unsafe {
                std::env::set_var(var, value);
            }
            Self { var, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            // SAFETY: see struct-level note.
            unsafe {
                match self.previous.take() {
                    Some(v) => std::env::set_var(self.var, v),
                    None => std::env::remove_var(self.var),
                }
            }
        }
    }

    #[test]
    #[ignore = "mutates HOME; run with `cargo test -- --ignored --test-threads=1`"]
    fn from_env_smoke_reads_home_from_process_environment() {
        let _guard = EnvGuard::set("HOME", "/tmp/jasontest-smoke");
        let paths = FalachPaths::from_env().expect("HOME set by guard");
        assert_eq!(
            paths.state_dir(),
            Path::new("/tmp/jasontest-smoke/.local/state/falach"),
        );
    }
}
