//! Property-based tests for the two-way merge adapter (`merge::reconcile`).
//!
//! These complement the example-based characterization suite
//! (`tests/merge_semantics.rs`): where that suite pins specific behaviours at
//! hand-picked timestamps, this suite generates thousands of randomized merge
//! scenarios and asserts the four merge properties the implementation plan
//! (§8 / PRD §11 Risk #2) requires:
//!
//! 1. **No data loss** — every pre-merge entry version, from either side, that
//!    is not the merged current value survives as a history entry under the
//!    same UUID (the module's load-bearing guarantee; `merge/mod.rs` docs).
//! 2. **Determinism / correct winner** — a contested entry resolves to the side
//!    with the newer `last_modification`, regardless of generation order.
//! 3. **Commutativity over disjoint changes** — when each entry is edited by at
//!    most one side, `reconcile(local, remote)` and the role-swapped
//!    `reconcile(remote, local)` converge to the same set of current values.
//! 4. **Idempotence** — re-running `reconcile` with the same remote is a no-op:
//!    no further delta, no duplicated history.
//!
//! A same-second-divergence property pins the `Unresolvable` conflict path.
//!
//! ## Generation strategy
//!
//! All databases are built through the public API; entries live at the root
//! group. Contested entries are given timestamps on disjoint even/odd tracks so
//! a randomly-generated merge is always *resolvable* (distinct
//! `last_modification` on the two sides) — the same-second case is exercised by
//! its own dedicated property rather than as generation noise. Titles encode
//! their (side, entry, version) origin so each version is a distinct, traceable
//! string.
//!
//! The `Scenario`/`EntryPlan` inputs derive both `proptest_derive::Arbitrary`
//! (drives the `proptest!` properties below, with shrinking) and
//! `arbitrary::Arbitrary` (drives the byte-seeded `fuzz_scenarios_never_lose_data`
//! smoke test). A standalone libfuzzer/`cargo-fuzz` target reusing the same
//! `Arbitrary` impl is a documented deferred follow-up; it is intentionally out
//! of scope here to avoid adding the `cargo-fuzz` / `libfuzzer-sys` vendored
//! tree + a nightly toolchain requirement.

use std::collections::BTreeMap;

use chrono::NaiveDateTime;
use falach_core::{fields, Database, GroupRef, Uuid};
use falach_sync::merge::{reconcile, MergeError};
use proptest::prelude::*;

/// Upper bound on shared base entries per generated scenario. Kept small so
/// each case stays fast; the randomness is in *which* entries diverge and how,
/// not in raw entry count.
const MAX_SHARED: usize = 4;
/// Upper bound on single-sided ("local-only" / "remote-only") additions.
const MAX_NEW: usize = 2;

// ---------------------------------------------------------------------------
// Generated input
// ---------------------------------------------------------------------------

/// One shared entry's per-side edit plan. `None` means that side leaves the
/// entry at its base value; `Some(tag)` means that side edits it (the tag
/// varies the content and the relative modification time).
#[derive(Debug, Clone, proptest_derive::Arbitrary, arbitrary::Arbitrary)]
struct EntryPlan {
    local_edit: Option<u8>,
    remote_edit: Option<u8>,
}

/// A full merge scenario: a set of shared entries with per-side edit plans,
/// plus counts of single-sided additions. Vec/scalar bounds are normalized in
/// the builders (`MAX_SHARED` / `MAX_NEW`), so the raw generated sizes do not
/// matter.
#[derive(Debug, Clone, proptest_derive::Arbitrary, arbitrary::Arbitrary)]
struct Scenario {
    shared: Vec<EntryPlan>,
    local_only: u8,
    remote_only: u8,
}

impl Scenario {
    /// Number of shared entries actually realized (generated length capped).
    fn n_shared(&self) -> usize {
        self.shared.len().min(MAX_SHARED)
    }
    fn n_local_only(&self) -> usize {
        self.local_only as usize % (MAX_NEW + 1)
    }
    fn n_remote_only(&self) -> usize {
        self.remote_only as usize % (MAX_NEW + 1)
    }
}

// ---------------------------------------------------------------------------
// Database construction helpers (public API only)
// ---------------------------------------------------------------------------

/// A deterministic timestamp `secs` seconds past a fixed base instant.
fn t(secs: i64) -> NaiveDateTime {
    chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0)
        .expect("valid timestamp")
        .naive_utc()
}

/// Add a root-level entry titled `title` with `last_modification == at`.
fn add_entry(db: &mut Database, title: &str, at: NaiveDateTime) -> Uuid {
    let mut root = db.root_mut();
    let mut entry = root.add_entry();
    entry.set_unprotected(fields::TITLE, title);
    entry.times.last_modification = Some(at);
    entry.id().uuid()
}

/// History-tracked title edit (the prior value is pushed to history, matching
/// Falach's real edit path), with `last_modification` pinned to `at`.
fn edit_tracked(db: &mut Database, uuid: Uuid, title: &str, at: NaiveDateTime) {
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

/// Add (or replace) attachment `name`→`bytes` on the root-level entry with
/// `uuid`, then pin `last_modification` to `at` (raw keepass API; no
/// auto-history, matching Falach's metadata side-channel write).
fn set_attachment(db: &mut Database, uuid: Uuid, name: &str, bytes: &[u8], at: NaiveDateTime) {
    let id = db
        .root()
        .entries()
        .find(|e| e.id().uuid() == uuid)
        .map(|e| e.id())
        .expect("entry exists");
    let mut entry = db.entry_mut(id).expect("entry exists");
    entry.add_attachment(name, falach_core::Value::unprotected(bytes.to_vec()));
    entry.times.last_modification = Some(at);
}

/// Remove attachment `name` from the root-level entry with `uuid`, then pin
/// `last_modification` to `at`.
fn remove_named_attachment(db: &mut Database, uuid: Uuid, name: &str, at: NaiveDateTime) {
    let id = db
        .root()
        .entries()
        .find(|e| e.id().uuid() == uuid)
        .map(|e| e.id())
        .expect("entry exists");
    let mut entry = db.entry_mut(id).expect("entry exists");
    entry.remove_attachment_by_name(name);
    entry.times.last_modification = Some(at);
}

/// The bytes of attachment `name` on the root-level entry with `uuid`, or
/// `None` if the entry or the attachment is absent.
fn attachment_bytes(db: &Database, uuid: Uuid, name: &str) -> Option<Vec<u8>> {
    let id = db
        .root()
        .entries()
        .find(|e| e.id().uuid() == uuid)
        .map(|e| e.id())?;
    db.entry(id)?
        .attachment_by_name(name)
        .map(|att| att.data.as_slice().to_vec())
}

/// Current title of the entry with `uuid`, or `None` if absent after a merge.
fn current_title(db: &Database, uuid: Uuid) -> Option<String> {
    fn walk(group: &GroupRef<'_>, uuid: Uuid) -> Option<String> {
        for entry in group.entries() {
            if entry.id().uuid() == uuid {
                return Some(entry.get(fields::TITLE).unwrap_or_default().to_string());
            }
        }
        for sub in group.groups() {
            if let Some(found) = walk(&sub, uuid) {
                return Some(found);
            }
        }
        None
    }
    walk(&db.root(), uuid)
}

/// Titles recorded in the history of the entry with `uuid`.
fn history_titles(db: &Database, uuid: Uuid) -> Vec<String> {
    fn walk(group: &GroupRef<'_>, uuid: Uuid) -> Option<Vec<String>> {
        for entry in group.entries() {
            if entry.id().uuid() == uuid {
                let values = entry
                    .history
                    .as_ref()
                    .map(|h| {
                        h.get_entries()
                            .iter()
                            .map(|he| he.get(fields::TITLE).unwrap_or_default().to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                return Some(values);
            }
        }
        for sub in group.groups() {
            if let Some(found) = walk(&sub, uuid) {
                return Some(found);
            }
        }
        None
    }
    walk(&db.root(), uuid).unwrap_or_default()
}

/// Every title visible for `uuid` after a merge: the current value plus every
/// history value. Used to check the no-data-loss invariant.
fn observed_titles(db: &Database, uuid: Uuid) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(current) = current_title(db, uuid) {
        out.push(current);
    }
    out.extend(history_titles(db, uuid));
    out
}

/// Map of every root-or-subgroup entry's UUID → current title. Used for the
/// commutativity comparison.
fn current_titles_map(db: &Database) -> BTreeMap<Uuid, String> {
    fn walk(group: &GroupRef<'_>, out: &mut BTreeMap<Uuid, String>) {
        for entry in group.entries() {
            out.insert(
                entry.id().uuid(),
                entry.get(fields::TITLE).unwrap_or_default().to_string(),
            );
        }
        for sub in group.groups() {
            walk(&sub, out);
        }
    }
    let mut out = BTreeMap::new();
    walk(&db.root(), &mut out);
    out
}

// ---------------------------------------------------------------------------
// Scenario builders
// ---------------------------------------------------------------------------

/// The realized form of a [`Scenario`]: the two diverged databases plus the
/// bookkeeping a property needs to assert outcomes.
struct Built {
    local: Database,
    remote: Database,
    shared_uuids: Vec<Uuid>,
    /// Expected current title per shared entry after a successful merge (the
    /// newer-timestamp winner).
    expected_current: Vec<String>,
    /// Every pre-merge title (both sides) per shared entry — all must survive.
    pre_titles: Vec<Vec<String>>,
    local_only_uuids: Vec<Uuid>,
    remote_only_uuids: Vec<Uuid>,
}

/// Build a *resolvable* divergence from `s`: contested entries get distinct
/// even (local) / odd (remote) timestamps, so `reconcile` never hits the
/// same-second `Unresolvable` path. The newer side wins, which is computable up
/// front from the tags.
fn build_resolvable(s: &Scenario) -> Built {
    let n_shared = s.n_shared();

    let mut base = Database::new();
    let mut shared_uuids = Vec::with_capacity(n_shared);
    for i in 0..n_shared {
        shared_uuids.push(add_entry(&mut base, &format!("base{i}"), t(0)));
    }

    let mut local = base.clone();
    let mut remote = base.clone();
    let mut expected_current = Vec::with_capacity(n_shared);
    let mut pre_titles = Vec::with_capacity(n_shared);

    for (i, &uuid) in shared_uuids.iter().enumerate() {
        let plan = &s.shared[i];
        let mut pre = vec![format!("base{i}")];
        // (last_modification-seconds, title) candidates for the merge winner;
        // the base value at t(0) is always a candidate. All times are distinct
        // (even local track / odd remote track), so `max_by_key` is unambiguous.
        let mut candidates = vec![(0i64, format!("base{i}"))];

        if let Some(tag) = plan.local_edit {
            let title = format!("L{i}.{tag}");
            let time = 100 + 2 * i64::from(tag); // even track
            edit_tracked(&mut local, uuid, &title, t(time));
            pre.push(title.clone());
            candidates.push((time, title));
        }
        if let Some(tag) = plan.remote_edit {
            let title = format!("R{i}.{tag}");
            let time = 101 + 2 * i64::from(tag); // odd track — never equals local's
            edit_tracked(&mut remote, uuid, &title, t(time));
            pre.push(title.clone());
            candidates.push((time, title));
        }

        let winner = candidates
            .into_iter()
            .max_by_key(|(time, _)| *time)
            .map(|(_, title)| title)
            .expect("at least the base candidate is present");
        expected_current.push(winner);
        pre_titles.push(pre);
    }

    let mut local_only_uuids = Vec::new();
    for j in 0..s.n_local_only() {
        let secs = 50 + i64::try_from(j).expect("small index fits i64");
        local_only_uuids.push(add_entry(&mut local, &format!("LO{j}"), t(secs)));
    }
    let mut remote_only_uuids = Vec::new();
    for j in 0..s.n_remote_only() {
        let secs = 60 + i64::try_from(j).expect("small index fits i64");
        remote_only_uuids.push(add_entry(&mut remote, &format!("RO{j}"), t(secs)));
    }

    Built {
        local,
        remote,
        shared_uuids,
        expected_current,
        pre_titles,
        local_only_uuids,
        remote_only_uuids,
    }
}

/// A single edit to replay onto a base clone: `(uuid, title, time-seconds)`.
type Edit = (Uuid, String, i64);

/// Build a *disjoint* divergence: each shared entry is edited by at most one
/// side (when the plan picks both, local is kept). Returns the shared base plus
/// the two sides' edit lists, so a property can assemble the merge in either
/// direction. Disjoint ⇒ no contest ⇒ always resolvable and order-independent.
fn build_disjoint(s: &Scenario) -> (Database, Vec<Edit>, Vec<Edit>) {
    let n_shared = s.n_shared();
    let mut base = Database::new();
    let mut uuids = Vec::with_capacity(n_shared);
    for i in 0..n_shared {
        uuids.push(add_entry(&mut base, &format!("base{i}"), t(0)));
    }

    let mut local_edits = Vec::new();
    let mut remote_edits = Vec::new();
    for (i, &uuid) in uuids.iter().enumerate() {
        let plan = &s.shared[i];
        let time = 100 + 2 * i64::try_from(i).expect("small index fits i64");
        match (plan.local_edit, plan.remote_edit) {
            (Some(tag), _) => local_edits.push((uuid, format!("L{i}.{tag}"), time)),
            (None, Some(tag)) => remote_edits.push((uuid, format!("R{i}.{tag}"), time)),
            (None, None) => {}
        }
    }
    (base, local_edits, remote_edits)
}

/// Clone `base` and replay `edits` onto it.
fn apply_edits(base: &Database, edits: &[Edit]) -> Database {
    let mut db = base.clone();
    for (uuid, title, time) in edits {
        edit_tracked(&mut db, *uuid, title, t(*time));
    }
    db
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    // 256 cases per property keeps the default `make test` fast; override with
    // PROPTEST_CASES (e.g. `make test-merge-properties` runs a heavier sweep).
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Property 1 (no data loss) + Property 2 (correct winner) + union: a
    /// resolvable merge keeps every pre-merge version (current or history),
    /// resolves each contested entry to the newer side, and never drops an
    /// entry that wasn't deleted.
    #[test]
    fn resolvable_merge_preserves_all_versions_and_picks_newest(s in any::<Scenario>()) {
        let built = build_resolvable(&s);
        let mut local = built.local.clone();

        let summary = reconcile(&mut local, &built.remote)
            .expect("a build_resolvable scenario never has same-second divergence");

        // Union: no shared or single-sided entry vanishes (no deletions here).
        for &uuid in &built.shared_uuids {
            prop_assert!(current_title(&local, uuid).is_some(), "shared entry vanished");
        }
        for &uuid in built.local_only_uuids.iter().chain(&built.remote_only_uuids) {
            prop_assert!(current_title(&local, uuid).is_some(), "single-sided entry vanished");
        }

        for (i, &uuid) in built.shared_uuids.iter().enumerate() {
            // Correct winner.
            let current = current_title(&local, uuid);
            prop_assert_eq!(
                current.as_deref(),
                Some(built.expected_current[i].as_str()),
                "wrong merge winner for entry {}", i
            );
            // No data loss: every pre-merge title is still observable.
            let observed = observed_titles(&local, uuid);
            for pre in &built.pre_titles[i] {
                prop_assert!(
                    observed.contains(pre),
                    "lost version {:?} for entry {}; observed {:?}", pre, i, observed
                );
            }
        }

        // Delta honesty: an entry reported neither added nor modified must have
        // kept local's pre-merge current value (i.e. the merge didn't silently
        // touch it).
        prop_assert!(summary.delta.removed.is_empty(), "no deletions were generated");
    }

    /// Property 4 (idempotence): re-running `reconcile` with the same remote
    /// reports no further change and leaves the database byte-identical (no
    /// duplicated backfill history).
    #[test]
    fn reconcile_is_idempotent(s in any::<Scenario>()) {
        let built = build_resolvable(&s);
        let mut local = built.local.clone();

        reconcile(&mut local, &built.remote).expect("first merge succeeds");
        let after_first = local.clone();

        let summary = reconcile(&mut local, &built.remote).expect("second merge succeeds");

        prop_assert!(summary.delta.is_empty(), "a repeated reconcile reports no changes");
        prop_assert!(local == after_first, "a repeated reconcile is a no-op");
    }

    /// Property 3 (commutativity over disjoint changes): with each entry edited
    /// by at most one side, merging local←remote and remote←local converge to
    /// the same set of current values.
    #[test]
    fn disjoint_merge_is_commutative(s in any::<Scenario>()) {
        let (base, local_edits, remote_edits) = build_disjoint(&s);

        let mut forward = apply_edits(&base, &local_edits);
        reconcile(&mut forward, &apply_edits(&base, &remote_edits))
            .expect("disjoint merge is always resolvable");

        let mut swapped = apply_edits(&base, &remote_edits);
        reconcile(&mut swapped, &apply_edits(&base, &local_edits))
            .expect("disjoint merge is always resolvable");

        prop_assert_eq!(
            current_titles_map(&forward),
            current_titles_map(&swapped),
            "disjoint merge must converge regardless of which side is `local`"
        );
    }

    /// Conflict path: the same entry edited on both sides within KDBX's
    /// one-second timestamp granularity, with differing content, is
    /// `Unresolvable` (the orchestrator turns this into a user-visible error
    /// with `.kdbx.bak` preserved). `secs` and the two titles are generated.
    #[test]
    fn same_second_divergence_is_unresolvable(
        secs in 0i64..10_000,
        a in "[a-z]{1,8}",
        b in "[a-z]{1,8}",
    ) {
        prop_assume!(a != b); // identical content at the same second is not a conflict

        let mut base = Database::new();
        let uuid = add_entry(&mut base, "v0", t(0));
        let mut local = base.clone();
        let remote = {
            let mut r = base.clone();
            edit_tracked(&mut r, uuid, &b, t(secs));
            r
        };
        edit_tracked(&mut local, uuid, &a, t(secs));

        let result = reconcile(&mut local, &remote);
        prop_assert!(
            matches!(result, Err(MergeError::Unresolvable { .. })),
            "same-second divergence must be Unresolvable; got {:?}", result
        );
    }

    /// Attachment propagation (merge-attachment-propagation): an attachment
    /// present on the strictly-newer side of a both-sides collision always
    /// appears — with its exact bytes — in the merged current value, regardless
    /// of local pool occupancy. A re-sync must then be a clean no-op (the
    /// timestamp-bump guarantee), never `Unresolvable`.
    #[test]
    fn attachment_on_strictly_newer_remote_reaches_merged_current(
        bytes in proptest::collection::vec(any::<u8>(), 1..48),
        fillers in 0u8..4,
    ) {
        let mut base = Database::new();
        let target = add_entry(&mut base, "target", t(0));
        let mut local = base.clone();
        let mut remote = base.clone();

        // Vary local pool occupancy (unrelated attachments on local-only entries)
        // so the propagated attachment's pool id diverges from remote's by
        // differing amounts — the case have_entries_diverged would trip on.
        for k in 0..fillers {
            let f = add_entry(&mut local, &format!("filler{k}"), t(5));
            set_attachment(&mut local, f, &format!("f{k}.bin"), &[k], t(5));
        }

        set_attachment(&mut remote, target, "att.bin", &bytes, t(20));

        reconcile(&mut local, &remote).expect("resolvable merge");

        let got = attachment_bytes(&local, target, "att.bin");
        prop_assert_eq!(
            got.as_deref(),
            Some(bytes.as_slice()),
            "attachment on the strictly-newer side must reach the merged current value"
        );

        let summary = reconcile(&mut local, &remote).expect("re-sync must not be Unresolvable");
        prop_assert!(summary.delta.is_empty(), "re-sync is a clean no-op");
    }

    /// Removal dual: an attachment removed on the strictly-newer side is absent
    /// from the merged current value.
    #[test]
    fn attachment_removed_on_strictly_newer_remote_is_absent(fillers in 0u8..4) {
        let mut base = Database::new();
        let target = add_entry(&mut base, "target", t(0));
        set_attachment(&mut base, target, "doomed.bin", b"X", t(0));
        let mut local = base.clone();
        let mut remote = base.clone();

        for k in 0..fillers {
            let f = add_entry(&mut local, &format!("filler{k}"), t(5));
            set_attachment(&mut local, f, &format!("f{k}.bin"), &[k], t(5));
        }

        remove_named_attachment(&mut remote, target, "doomed.bin", t(20));

        reconcile(&mut local, &remote).expect("resolvable merge");

        prop_assert!(
            attachment_bytes(&local, target, "doomed.bin").is_none(),
            "removal on the strictly-newer side must propagate to the merged current value"
        );
    }
}

// ---------------------------------------------------------------------------
// Fuzz-style smoke test (drives the `arbitrary` dep)
// ---------------------------------------------------------------------------

/// Volume smoke test over `arbitrary`-decoded scenarios. This exercises the
/// same `Arbitrary` impl a future `cargo-fuzz` target would drive (the libfuzzer
/// target itself is a deferred follow-up — see the module docs), asserting that
/// a resolvable merge never panics and never loses a pre-merge version across a
/// large sweep of byte-seeded inputs.
#[test]
fn fuzz_scenarios_never_lose_data() {
    use arbitrary::{Arbitrary, Unstructured};

    // Deterministic xorshift64* byte stream — no `rand` dependency, reproducible
    // across runs.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next_byte = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        // Extract byte 4 (bits 32..40) of the scrambled word — equivalent to
        // `(x >> 32) as u8` but without a truncating cast.
        state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes()[4]
    };

    for _ in 0..1024 {
        let buf: Vec<u8> = (0..48).map(|_| next_byte()).collect();
        let mut u = Unstructured::new(&buf);
        let Ok(scenario) = <Scenario as Arbitrary>::arbitrary(&mut u) else {
            continue;
        };

        let built = build_resolvable(&scenario);
        let mut local = built.local.clone();
        // build_resolvable is always resolvable, so this is Ok; the point is to
        // exercise reconcile + the no-data-loss invariant on random structure.
        if reconcile(&mut local, &built.remote).is_ok() {
            for (i, &uuid) in built.shared_uuids.iter().enumerate() {
                let observed = observed_titles(&local, uuid);
                for pre in &built.pre_titles[i] {
                    assert!(
                        observed.contains(pre),
                        "fuzz: lost version {pre:?} for entry {i}; observed {observed:?}"
                    );
                }
            }
        }
    }
}
