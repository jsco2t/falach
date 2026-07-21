//! Build-time helper invoked by `make completions` (Phase 4 T4.2).
//!
//! Writes pre-generated `bash`, `zsh`, and `fish` completion scripts
//! into the tracked `shell-completions/` directory at the workspace
//! root, using the same code path the runtime `falach completions
//! <shell>` subcommand uses (so the build-time and runtime outputs
//! cannot drift).
//!
//! The CI drift gate runs `make completions-check`, which re-runs
//! `make completions` and then fails the build if
//! `git status --porcelain -- shell-completions/` reports any change —
//! catching both edits to tracked completion scripts and additions of
//! new ones.
//!
//! Output filenames follow the `clap_complete` / shell-tooling
//! conventions:
//!   * bash → `falach.bash`
//!   * zsh  → `_falach`
//!   * fish → `falach.fish`

use std::fs;
use std::path::PathBuf;

use clap_complete::aot::Shell;

const OUT_DIR_NAME: &str = "shell-completions";

fn main() {
    let out_dir = workspace_root().join(OUT_DIR_NAME);
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!(
            "gen_completions: failed to create {}: {e}",
            out_dir.display()
        );
        std::process::exit(1);
    }

    for (shell, filename) in [
        (Shell::Bash, "falach.bash"),
        (Shell::Zsh, "_falach"),
        (Shell::Fish, "falach.fish"),
    ] {
        let path = out_dir.join(filename);
        let file = match fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("gen_completions: failed to open {}: {e}", path.display());
                std::process::exit(1);
            }
        };
        let mut writer = std::io::BufWriter::new(file);
        falach_cli::commands::completions::write_completions(shell, &mut writer);
        if let Err(e) = std::io::Write::flush(&mut writer) {
            eprintln!("gen_completions: failed to flush {}: {e}", path.display());
            std::process::exit(1);
        }
        println!("wrote {}", path.display());
    }
}

/// Resolve the workspace root from this crate's `CARGO_MANIFEST_DIR`.
///
/// `cargo run --example` sets `CARGO_MANIFEST_DIR` to the crate root
/// (`crates/falach-cli`); the workspace root is two `..` up.
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(std::path::Path::parent)
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf)
}
