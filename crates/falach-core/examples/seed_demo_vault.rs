//! One-off generator for the committed demo test vault.
//!
//! Builds a KDBX4 vault populated with a broad spread of secret types so
//! the TUI and CLI have something realistic to exercise: credentials,
//! secure notes, TOTP entries, attachments, custom fields, nested groups,
//! tags, and an entry carrying history snapshots.
//!
//! Master password: `Password123` (this is a throwaway fixture — never a
//! real secret).
//!
//! Run:
//!
//! ```text
//! cargo run --example seed_demo_vault -p falach-core --offline --locked -- test-vaults/demo.kdbx
//! ```

use falach_core::{fields, Database, KdfParams, MasterPassword, NoRecoveryConfirmed, Vault};
use keepass::db::{EntryMut, Value};
use std::path::PathBuf;

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: seed_demo_vault <output.kdbx>");
    let path = PathBuf::from(out);
    // Regenerate cleanly: `Vault::create` refuses to overwrite.
    let _ = std::fs::remove_file(&path);

    let master = MasterPassword::new("Password123".to_string());
    let mut vault = Vault::create(
        &path,
        &master,
        None,
        KdfParams::default(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create demo vault");

    {
        let db = vault.database_mut();
        db.root_mut().edit(|root| root.name = "Falach Demo".into());
        build_root_entries(db);
        build_personal(db);
        build_work(db);
        build_secure_notes(db);
        build_archive(db);
    }

    vault.save().expect("save demo vault");
    println!("wrote demo vault to {}", path.display());
}

/// Root-level entries: a TOTP account, an entry with attachments, and one
/// carrying custom (extra) string fields.
fn build_root_entries(db: &mut Database) {
    db.root_mut().add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "GitHub");
        e.set_unprotected(fields::USERNAME, "octocat");
        e.set_unprotected(fields::URL, "https://github.com");
        e.set_protected(
            fields::OTP,
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        );
        e.set_unprotected(fields::NOTES, "TOTP-protected account.");
        e.tags.extend(["totp", "dev"].map(String::from));
    });

    db.root_mut().add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "Signing Certificate");
        e.set_unprotected(fields::USERNAME, "release-bot");
        e.set_protected(fields::PASSWORD, "cert-export-passphrase");
        e.set_unprotected(fields::NOTES, "Bundle plus its passphrase.");
        e.add_attachment("codesign.pfx", Value::unprotected(fake_pfx()));
        e.add_attachment(
            "README.txt",
            Value::unprotected(
                b"Import codesign.pfx into the keychain before a release build.".to_vec(),
            ),
        );
        e.tags.push("attachment".to_string());
    });

    db.root_mut().add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "Payments API");
        e.set_unprotected(fields::USERNAME, "acct_9f2a");
        e.set_unprotected(fields::URL, "https://api.payments.example");
        e.set_protected(fields::PASSWORD, "sk_live_51H8xQ2eZvKYlo2C");
        // Custom fields — one visible, one protected.
        e.set_unprotected("Environment", "production");
        e.set_protected("Webhook Secret", "whsec_7d4Ff0aB19cD");
        e.tags.extend(["api", "finance"].map(String::from));
    });
}

/// `Personal/` with a `Social/` subgroup.
fn build_personal(db: &mut Database) {
    let mut root = db.root_mut();
    let mut personal = root.add_group();
    personal.edit(|g| g.name = "Personal".into());

    personal.add_entry().edit(|e| {
        credential(
            e,
            "Gmail",
            "jane.doe@gmail.com",
            "hunter2-but-longer",
            "https://mail.google.com",
            "Primary personal mailbox.",
            &["email"],
        );
    });
    personal.add_entry().edit(|e| {
        credential(
            e,
            "Bank of Falach",
            "jdoe",
            "Tr0ub4dour&3",
            "https://bankoffalach.example",
            "Checking + savings.",
            &["finance", "banking"],
        );
    });

    let mut social = personal.add_group();
    social.edit(|g| g.name = "Social".into());
    social.add_entry().edit(|e| {
        credential(
            e,
            "Mastodon",
            "@jane@fosstodon.org",
            "elephant-parade-88",
            "https://fosstodon.org",
            "",
            &["social"],
        );
    });
    social.add_entry().edit(|e| {
        credential(
            e,
            "Reddit",
            "u_jdoe",
            "sn00-sn00",
            "https://reddit.com",
            "",
            &["social"],
        );
    });
}

/// `Work/` with an `Infrastructure/` subgroup (incl. a second TOTP account).
fn build_work(db: &mut Database) {
    let mut root = db.root_mut();
    let mut work = root.add_group();
    work.edit(|g| g.name = "Work".into());

    work.add_entry().edit(|e| {
        credential(
            e,
            "Jira",
            "jane.doe",
            "corp-sso-fallback-pw",
            "https://falach.atlassian.net",
            "SSO usually; this is the break-glass local password.",
            &["work"],
        );
    });

    let mut infra = work.add_group();
    infra.edit(|g| g.name = "Infrastructure".into());
    infra.add_entry().edit(|e| {
        credential(
            e,
            "Prod SSH — web-01",
            "deploy",
            "not-the-real-key-obviously",
            "ssh://web-01.prod.falach.example",
            "Jump host: bastion.prod.falach.example\nUse the deploy key, not password auth.",
            &["work", "ssh", "prod"],
        );
    });
    infra.add_entry().edit(|e| {
        credential(
            e,
            "Postgres — analytics",
            "admin",
            "pg-4dm1n-rotate-me",
            "postgres://db-analytics.prod.falach.example:5432",
            "Read/write superuser. Rotate quarterly.",
            &["work", "database", "prod"],
        );
    });
    infra.add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "AWS Root");
        e.set_unprotected(fields::USERNAME, "root@falach.example");
        e.set_unprotected(fields::URL, "https://console.aws.amazon.com");
        e.set_protected(
            fields::OTP,
            "otpauth://totp/AWS:root?secret=NB2W45DFOIZA&issuer=AWS",
        );
        e.set_unprotected(fields::NOTES, "Break-glass only. MFA required.");
        e.tags.extend(["work", "totp", "prod"].map(String::from));
    });
}

/// `Secure Notes/` — entries with notes-only payloads (no password/URL).
fn build_secure_notes(db: &mut Database) {
    let mut root = db.root_mut();
    let mut notes = root.add_group();
    notes.edit(|g| g.name = "Secure Notes".into());

    notes.add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "GitHub Recovery Codes");
        e.set_unprotected(
            fields::NOTES,
            "3f9a-11b2\n8c7d-44e0\n0a1b-92ff\nd3e4-5678\n7788-aabb",
        );
        e.tags.push("note".to_string());
    });
    notes.add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "Home WiFi");
        e.set_unprotected(
            fields::NOTES,
            "SSID: falach-home\nPSK: correct-horse-battery-staple\n\
             Guest SSID: falach-guest\nGuest PSK: welcome-friend",
        );
        e.tags.extend(["note", "home"].map(String::from));
    });
    notes.add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "Passport / ID");
        e.set_protected(
            fields::NOTES,
            "Passport: X1234567 (exp 2031-04)\nDriver license: D9988776",
        );
        e.tags.extend(["note", "personal"].map(String::from));
    });
}

/// `Archive/` — one entry with three tracked edits, leaving three history
/// snapshots (v1..v3) behind the current version (v4).
fn build_archive(db: &mut Database) {
    let old_id = {
        let mut root = db.root_mut();
        let mut archive = root.add_group();
        archive.edit(|g| g.name = "Archive".into());
        archive
            .add_entry()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Legacy Webmail");
                e.set_unprotected(fields::USERNAME, "jdoe");
                e.set_protected(fields::PASSWORD, "password-v1");
                e.set_unprotected(fields::URL, "https://webmail.legacy.example");
                e.set_unprotected(fields::NOTES, "Deprecated account; kept for archive.");
                e.tags.push("archive".to_string());
            })
            .id()
    };

    for version in 2..=4 {
        db.entry_mut(old_id)
            .expect("archive history entry should exist")
            .edit_tracking(|e| {
                e.set_protected(fields::PASSWORD, format!("password-v{version}"));
                e.set_unprotected(
                    fields::NOTES,
                    format!("Deprecated account; rotated to v{version}."),
                );
            });
    }
}

/// Populate the standard credential fields on an entry.
fn credential(
    e: &mut EntryMut<'_>,
    title: &str,
    username: &str,
    password: &str,
    url: &str,
    notes: &str,
    tags: &[&str],
) {
    e.set_unprotected(fields::TITLE, title);
    e.set_unprotected(fields::USERNAME, username);
    e.set_protected(fields::PASSWORD, password);
    if !url.is_empty() {
        e.set_unprotected(fields::URL, url);
    }
    if !notes.is_empty() {
        e.set_unprotected(fields::NOTES, notes);
    }
    e.tags.extend(tags.iter().map(|t| (*t).to_string()));
}

/// A small blob that starts with a plausible PKCS#12 header shape so a
/// viewer shows a non-empty binary attachment. Not a real certificate.
fn fake_pfx() -> Vec<u8> {
    let mut bytes = vec![0x30, 0x82, 0x04, 0x00]; // DER SEQUENCE header shape
    bytes.extend(std::iter::repeat_n(0xAB, 2044));
    bytes
}
