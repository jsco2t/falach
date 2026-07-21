mod common;

use std::time::Instant;

use common::entry_fixtures::{
    kdbx_with_history, populate_with_n_entries, sample_database_with_entries,
};
use falach_core::fields;

#[test]
fn sample_database_with_entries_has_documented_shape() {
    let db = sample_database_with_entries();
    let root = db.root();

    assert_eq!(count_entries(&root), 8);
    assert!(root.group_by_name("Banking").is_some());
    assert!(root.group_by_name("Email").is_some());

    let example_1 = root
        .entry_by_name("Example 1")
        .expect("Example 1 should exist");
    assert_eq!(example_1.get(fields::USERNAME), Some("user1"));
    assert_eq!(example_1.tags, vec!["odd".to_string(), "root".to_string()]);

    let totp = root
        .entry_by_name("GitHub TOTP")
        .expect("GitHub TOTP should exist");
    assert_eq!(
        totp.get(fields::OTP),
        Some("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
    );

    let attached = root
        .entry_by_name("With Attachment")
        .expect("attachment entry should exist");
    let attachment = attached
        .attachment_by_name("doc.pdf")
        .expect("doc.pdf should exist");
    assert_eq!(attachment.data.as_slice().len(), 1024);
}

#[test]
fn kdbx_with_history_has_three_newest_first_history_entries() {
    let db = kdbx_with_history();
    let root = db.root();
    let entries: Vec<_> = root.entries().collect();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].get(fields::TITLE), Some("v4"));

    let history = entries[0].history.as_ref().expect("history should exist");
    let titles: Vec<_> = history
        .get_entries()
        .iter()
        .map(|entry| entry.get(fields::TITLE).expect("history title"))
        .collect();
    assert_eq!(titles, vec!["v3", "v2", "v1"]);
}

#[test]
fn populate_with_n_entries_adds_deterministic_entries_quickly() {
    let mut db = falach_core::Database::new();
    let started = Instant::now();

    populate_with_n_entries(&mut db, 5_000);

    assert!(
        started.elapsed().as_secs() < 1,
        "fixture construction should stay comfortably below one second"
    );
    assert_eq!(count_entries(&db.root()), 5_000);
    assert!(db.root().entry_by_name("Entry-5000").is_some());
}

fn count_entries(group: &falach_core::GroupRef<'_>) -> usize {
    group.entries().count()
        + group
            .groups()
            .map(|child| count_entries(&child))
            .sum::<usize>()
}
