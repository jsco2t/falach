//! Shared entry-management fixtures.

use falach_core::{fields, Database};
use keepass::db::Value;

/// Build a deterministic in-memory database for entry-management tests.
///
/// The fixture contains eight entries total:
///
/// - Five credentials named `Example 1` through `Example 5`.
/// - A secure note named `Recovery Codes`.
/// - A TOTP entry named `GitHub TOTP` with an `otp` custom field.
/// - A credential named `With Attachment` with a 1 KiB `doc.pdf` attachment.
///
/// It also contains two root child groups: `Banking` with `Example 4`, and
/// `Email` with `Example 5`.
pub fn sample_database_with_entries() -> Database {
    let mut db = Database::new();
    db.root_mut()
        .edit(|root| root.name = "Falach Entry Fixture".into());

    for n in 1..=3 {
        add_credential(
            &mut db,
            &format!("Example {n}"),
            &format!("user{n}"),
            &format!("https://example{n}.test"),
            &[if n % 2 == 0 { "even" } else { "odd" }, "root"],
        );
    }

    db.root_mut().add_entry().edit(|entry| {
        entry.set_unprotected(fields::TITLE, "Recovery Codes");
        entry.set_unprotected(fields::NOTES, "alpha\nbravo\ncharlie");
        entry.tags.push("note".to_string());
    });

    db.root_mut().add_entry().edit(|entry| {
        entry.set_unprotected(fields::TITLE, "GitHub TOTP");
        entry.set_unprotected(fields::USERNAME, "octocat");
        entry.set_protected(
            fields::OTP,
            "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        );
        entry.tags.push("totp".to_string());
    });

    db.root_mut().add_entry().edit(|entry| {
        entry.set_unprotected(fields::TITLE, "With Attachment");
        entry.set_unprotected(fields::USERNAME, "attached");
        entry.set_protected(fields::PASSWORD, "attachment-password");
        entry.add_attachment("doc.pdf", Value::unprotected(vec![b'A'; 1024]));
        entry.tags.push("attachment".to_string());
    });

    db.root_mut()
        .add_group()
        .edit(|group| group.name = "Banking".into())
        .add_entry()
        .edit(|entry| {
            set_credential_fields(
                entry,
                "Example 4",
                "bank-user",
                "bank-password",
                "https://bank.example",
                "Banking credential",
                &["finance", "banking"],
            );
        });

    db.root_mut()
        .add_group()
        .edit(|group| group.name = "Email".into())
        .add_entry()
        .edit(|entry| {
            set_credential_fields(
                entry,
                "Example 5",
                "mail-user",
                "mail-password",
                "https://mail.example",
                "Email credential",
                &["email"],
            );
        });

    db
}

/// Build a database with one entry and three history snapshots.
///
/// The current entry title is `v4`. Its history contains three entries in
/// `keepass-rs` public API order: `v3`, `v2`, `v1` (newest first).
pub fn kdbx_with_history() -> Database {
    let mut db = Database::new();
    let entry_id = db
        .root_mut()
        .add_entry()
        .edit(|entry| {
            entry.set_unprotected(fields::TITLE, "v1");
            entry.set_unprotected(fields::USERNAME, "history-user");
            entry.set_protected(fields::PASSWORD, "password-v1");
        })
        .id();

    for version in 2..=4 {
        db.entry_mut(entry_id)
            .expect("history fixture entry should exist")
            .edit_tracking(|entry| {
                entry.set_unprotected(fields::TITLE, format!("v{version}"));
                entry.set_protected(fields::PASSWORD, format!("password-v{version}"));
            });
    }

    db
}

/// Populate a database with `n` deterministic credential entries.
///
/// Entries are added directly under the root group with titles `Entry-1`,
/// `Entry-2`, and so on. This fixture is intended for search benchmarks and
/// high-volume smoke tests.
pub fn populate_with_n_entries(db: &mut Database, n: usize) {
    for index in 1..=n {
        db.root_mut().add_entry().edit(|entry| {
            set_credential_fields(
                entry,
                &format!("Entry-{index}"),
                &format!("user{index}"),
                &format!("password-{index}"),
                &format!("https://entry-{index}.example"),
                &format!("Generated entry {index}"),
                &["generated"],
            );
        });
    }
}

fn add_credential(db: &mut Database, title: &str, username: &str, url: &str, tags: &[&str]) {
    db.root_mut().add_entry().edit(|entry| {
        set_credential_fields(
            entry,
            title,
            username,
            &format!("{title}-password"),
            url,
            &format!("Notes for {title}"),
            tags,
        );
    });
}

fn set_credential_fields(
    entry: &mut keepass::db::EntryMut<'_>,
    title: &str,
    username: &str,
    password: &str,
    url: &str,
    notes: &str,
    tags: &[&str],
) {
    entry.set_unprotected(fields::TITLE, title);
    entry.set_unprotected(fields::USERNAME, username);
    entry.set_protected(fields::PASSWORD, password);
    entry.set_unprotected(fields::URL, url);
    entry.set_unprotected(fields::NOTES, notes);
    entry.tags.extend(tags.iter().map(|tag| (*tag).to_string()));
}
