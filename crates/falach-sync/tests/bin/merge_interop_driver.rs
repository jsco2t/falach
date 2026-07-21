//! `merge-interop-driver` — emit a *merged* KDBX vault for the KeePassXC
//! interop test (`tools/interop-tests/sync_us-044.sh`, s3-sync T6.3/§8.4.4).
//!
//! Produces the US-044 collision outcome on disk: a single entry whose
//! current title is `winner` and whose history contains the collision loser
//! `loser`. The shell harness then opens the vault with `keepassxc-cli`,
//! exports it to XML, and asserts KeePassXC ≥ 2.7 reads both the current
//! value and the preserved-loser history entry — the NFR-009 round-trip
//! promise applied to a merged vault.
//!
//! Test-only: gated behind the `test-helpers` feature so it is never built
//! into a production binary. The master password is read from stdin (first
//! line) — never the command line — matching the project's secure-input rule.

#![allow(clippy::doc_markdown)]

use std::io::BufRead;

use chrono::NaiveDateTime;
use falach_core::{fields, Database, KdfParams, MasterPassword, NoRecoveryConfirmed, Uuid, Vault};
use falach_sync::merge::reconcile;

/// A deterministic modification timestamp `secs` past a fixed base instant.
fn ts(secs: i64) -> NaiveDateTime {
    chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0)
        .expect("valid timestamp")
        .naive_utc()
}

/// Edit the entry with `uuid`, tracking the prior value into history (as a
/// real edit does), then pin its `last_modification` so merge ordering is
/// deterministic.
fn edit(db: &mut Database, uuid: Uuid, title: &str, at: NaiveDateTime) {
    let id = db
        .root()
        .entries()
        .find(|e| e.id().uuid() == uuid)
        .map(|e| e.id())
        .expect("entry exists");
    db.entry_mut(id)
        .expect("entry exists")
        .edit_tracking(|e| e.set_unprotected(fields::TITLE, title));
    db.entry_mut(id)
        .expect("entry exists")
        .times
        .last_modification = Some(at);
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: merge-interop-driver <output.kdbx>  (password on stdin)");

    let mut pw_line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut pw_line)
        .expect("read password from stdin");
    let password = MasterPassword::new(pw_line.trim_end_matches(['\n', '\r']).to_string());

    // Interop wants a KeePassXC-readable vault; keep the KDF modest so the
    // script is quick but the file is a genuine KDBX4.
    let kdf = KdfParams {
        memory_kib: 16_384,
        iterations: 2,
        parallelism: 1,
    };

    // 1. Base vault with one shared entry.
    Vault::create(
        out.as_ref(),
        &password,
        None,
        kdf,
        NoRecoveryConfirmed::yes(),
    )
    .expect("create base vault");
    let uuid: Uuid = {
        let mut v = Vault::open(out.as_ref(), &password, None).expect("open base");
        let u = {
            let db = v.database_mut();
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "collision");
            e.set_unprotected(fields::USERNAME, "shared@example.com");
            e.times.last_modification = Some(ts(0));
            e.id().uuid()
        };
        v.save().expect("save base");
        u
    };

    // 2. The "remote" device: an in-memory clone of the base that edits the
    //    shared entry to the (older) loser value. `open_from_bytes` yields a
    //    `Database` directly (the decrypted contents), not a `Vault`.
    let base_bytes = std::fs::read(&out).expect("read base bytes");
    let mut remote: Database =
        Vault::open_from_bytes(&base_bytes, &password, None).expect("open_from_bytes remote");
    edit(&mut remote, uuid, "loser", ts(10));

    // 3. The "local" device edits the same entry to the (newer) winner value.
    let mut local = Vault::open(out.as_ref(), &password, None).expect("open local");
    edit(local.database_mut(), uuid, "winner", ts(20));

    // 4. Merge: winner (newer) wins the current value; loser is preserved as
    //    a history entry under the same UUID. Save the merged vault.
    reconcile(local.database_mut(), &remote).expect("merge");
    local.save().expect("save merged vault");

    // The shell harness reads this to confirm the entry UUID round-tripped.
    println!("{uuid}");
}
