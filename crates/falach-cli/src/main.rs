//! `falach` binary — thin shim over [`falach_cli::run`].

fn main() -> std::process::ExitCode {
    falach_cli::run()
}
