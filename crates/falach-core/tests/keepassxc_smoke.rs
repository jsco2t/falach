mod common;

use std::io::Write as _;
use std::process::{Command, Stdio};

use falach_core::{fields, NoRecoveryConfirmed, Vault};

use common::{fast_kdf, master, TestEnv};

#[test]
#[ignore = "requires keepassxc-cli >= 2.7 on PATH"]
fn falach_created_vault_opens_with_keepassxc_cli() {
    let env = TestEnv::new();
    let path = env.tempdir().join("kpxc-smoke.kdbx");
    let password = "interop-smoke-password";

    let mut vault = Vault::create(
        &path,
        &master(password),
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create Falach vault");

    vault.database_mut().root_mut().add_entry().edit(|entry| {
        entry.set_unprotected(fields::TITLE, "Example Site");
        entry.set_unprotected(fields::USERNAME, "me@example.com");
        entry.set_protected(fields::PASSWORD, "manual-test-value-2026");
    });
    vault.save().expect("save populated vault");
    drop(vault);

    let listing = keepassxc_cli(password, &["ls", "-q", "-R", path.to_str().unwrap()]);
    assert!(
        listing.status.success(),
        "keepassxc-cli ls failed\nstdout:\n{}\nstderr:\n{}",
        listing.stdout,
        listing.stderr
    );
    assert!(
        listing.stdout.contains("Example Site"),
        "listing did not include Example Site\nstdout:\n{}",
        listing.stdout
    );

    let shown = keepassxc_cli(
        password,
        &[
            "show",
            "-q",
            "-s",
            "-a",
            "UserName",
            "-a",
            "Password",
            path.to_str().unwrap(),
            "Example Site",
        ],
    );
    assert!(
        shown.status.success(),
        "keepassxc-cli show failed\nstdout:\n{}\nstderr:\n{}",
        shown.stdout,
        shown.stderr
    );
    assert!(shown.stdout.contains("me@example.com"));
    assert!(shown.stdout.contains("manual-test-value-2026"));
}

struct CliOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn keepassxc_cli(password: &str, args: &[&str]) -> CliOutput {
    let mut child = Command::new("keepassxc-cli")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keepassxc-cli");

    {
        let stdin = child.stdin.as_mut().expect("stdin pipe");
        writeln!(stdin, "{password}").expect("write password");
    }

    let output = child.wait_with_output().expect("wait for keepassxc-cli");
    CliOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}
