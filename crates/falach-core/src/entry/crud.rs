//! Entry CRUD operations on unlocked vaults.

use keepass::db::{fields, Entry, EntryId, GroupId, History, Times};
use keepass::Database;

use crate::{EntryDraft, EntryView, EntryViewMut, Tag, Vault, VaultError};

const DEFAULT_MAX_HISTORY_PER_ENTRY: usize = 10;
const RECYCLE_BIN_NAME: &str = "Recycle Bin";

/// History policy decoded from the KDBX `Meta/HistoryMaxItems` value.
///
/// `KeePass` and `KeePassXC` use `-1` for "unlimited history" (written when
/// "limit history items" is unchecked) and `0` for "history disabled".
/// Coercing either to a numeric cap would silently prune history a user
/// configured to keep forever, or keep history a user turned off — both
/// interop violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryCap {
    /// Negative `HistoryMaxItems`: keep every snapshot, never prune.
    Unlimited,
    /// `HistoryMaxItems = 0`: do not record history snapshots.
    Disabled,
    /// Positive `HistoryMaxItems` (or absent → default 10): keep at most
    /// this many snapshots.
    Max(usize),
}

impl Vault {
    /// Add `draft` to `group` and return the freshly allocated entry UUID.
    ///
    /// The entry exists only in the in-memory vault until [`Self::save`] is
    /// called.
    pub fn add_entry(
        &mut self,
        group: uuid::Uuid,
        draft: EntryDraft,
    ) -> Result<uuid::Uuid, VaultError> {
        let group_id = find_group_id(self.database(), group)?;
        let mut group = self
            .database_mut()
            .group_mut(group_id)
            .ok_or(VaultError::GroupNotFound { uuid: group })?;
        let mut entry = group.add_entry();
        populate_entry_from_draft(&mut entry, draft);
        Ok(entry.id().uuid())
    }

    /// Return a read-only view of an entry.
    pub fn get_entry(&self, uuid: uuid::Uuid) -> Result<EntryView<'_>, VaultError> {
        let entry_id = find_entry_id(self.database(), uuid)?;
        self.database()
            .entry(entry_id)
            .map(EntryView::new)
            .ok_or(VaultError::EntryNotFound { uuid })
    }

    /// Return a mutable view of an entry.
    ///
    /// Prefer [`Self::update_entry`] for normal edits so KDBX history is
    /// appended exactly once for the logical update.
    pub fn get_entry_mut(&mut self, uuid: uuid::Uuid) -> Result<EntryViewMut<'_>, VaultError> {
        let entry_id = find_entry_id(self.database(), uuid)?;
        self.database_mut()
            .entry_mut(entry_id)
            .map(EntryViewMut::new)
            .ok_or(VaultError::EntryNotFound { uuid })
    }

    /// Update an entry, appending one history snapshot for the committed edit.
    ///
    /// If `f` returns an error, the entry is restored to its pre-call state and
    /// no history snapshot remains.
    pub fn update_entry<F>(&mut self, uuid: uuid::Uuid, f: F) -> Result<(), VaultError>
    where
        F: FnOnce(&mut EntryViewMut<'_>) -> Result<(), VaultError>,
    {
        let entry_id = find_entry_id(self.database(), uuid)?;
        let cap = self.history_cap();
        let snapshot = {
            let mut entry = self
                .database_mut()
                .entry_mut(entry_id)
                .ok_or(VaultError::EntryNotFound { uuid })?;
            let snapshot = entry.clone();
            match cap {
                HistoryCap::Disabled => {}
                HistoryCap::Unlimited | HistoryCap::Max(_) => {
                    let mut historical = snapshot.clone();
                    historical.history = None;
                    entry.history.get_or_insert_default().add_entry(historical);
                    if let HistoryCap::Max(max) = cap {
                        prune_history(&mut entry, max);
                    }
                }
            }
            snapshot
        };

        let result = {
            let entry = self
                .database_mut()
                .entry_mut(entry_id)
                .ok_or(VaultError::EntryNotFound { uuid })?;
            let mut view = EntryViewMut::new(entry);
            f(&mut view)
        };

        match result {
            Ok(()) => {
                let mut entry = self
                    .database_mut()
                    .entry_mut(entry_id)
                    .ok_or(VaultError::EntryNotFound { uuid })?;
                entry.times.last_modification = Some(Times::now());
                Ok(())
            }
            Err(err) => {
                let mut entry = self
                    .database_mut()
                    .entry_mut(entry_id)
                    .ok_or(VaultError::EntryNotFound { uuid })?;
                *entry = snapshot;
                Err(err)
            }
        }
    }

    /// Delete an entry using the vault's recycle-bin setting.
    ///
    /// When the recycle bin is enabled, the entry is moved there with its UUID
    /// preserved. When disabled, this permanently removes the entry.
    pub fn delete_entry(&mut self, uuid: uuid::Uuid) -> Result<(), VaultError> {
        if !self.database().meta.recyclebin_enabled.unwrap_or(true) {
            return self.purge_entry(uuid);
        }

        let entry_id = find_entry_id(self.database(), uuid)?;
        let bin_id = recycle_bin_group_id_or_create(self.database_mut());
        let parent_id = self
            .database()
            .entry(entry_id)
            .ok_or(VaultError::EntryNotFound { uuid })?
            .parent()
            .id();

        if parent_id == bin_id {
            return Ok(());
        }

        // Tracked move: stamps `times.location_changed`, which the sync
        // merge requires on both sides to propagate a relocation — an
        // untracked move (no timestamp) silently fails to sync, letting
        // recycle-binned entries pop back out on other devices.
        self.database_mut()
            .entry_mut(entry_id)
            .ok_or(VaultError::EntryNotFound { uuid })?
            .track_changes()
            .move_to(bin_id)
            .map_err(|_| VaultError::GroupNotFound {
                uuid: bin_id.uuid(),
            })?;
        Ok(())
    }

    /// Permanently remove an entry regardless of recycle-bin settings.
    ///
    /// Uses the *tracked* removal so a `DeletedObjects` tombstone is
    /// recorded in the KDBX file — without it, the sync merge (which
    /// keys deletion handling entirely off `DeletedObjects`) would
    /// resurrect the purged entry from any replica that still holds it.
    pub fn purge_entry(&mut self, uuid: uuid::Uuid) -> Result<(), VaultError> {
        let entry_id = find_entry_id(self.database(), uuid)?;
        self.database_mut()
            .entry_mut(entry_id)
            .ok_or(VaultError::EntryNotFound { uuid })?
            .track_changes()
            .remove();
        Ok(())
    }

    /// Move an entry to another group while preserving the entry UUID.
    ///
    /// Tracked move: stamps `times.location_changed` so the relocation
    /// propagates through the sync merge (which requires the timestamp
    /// on both sides to order competing moves).
    pub fn move_entry(
        &mut self,
        uuid: uuid::Uuid,
        new_group: uuid::Uuid,
    ) -> Result<(), VaultError> {
        let entry_id = find_entry_id(self.database(), uuid)?;
        let group_id = find_group_id(self.database(), new_group)?;
        self.database_mut()
            .entry_mut(entry_id)
            .ok_or(VaultError::EntryNotFound { uuid })?
            .track_changes()
            .move_to(group_id)
            .map_err(|_| VaultError::GroupNotFound { uuid: new_group })?;
        Ok(())
    }

    /// Return the vault's history policy, decoded from the KDBX
    /// `Meta/HistoryMaxItems` value using the `KeePass`/`KeePassXC`
    /// convention: negative = unlimited history, `0` = history disabled,
    /// positive = cap, absent = the `KeePassXC`-matching default of 10.
    pub fn history_cap(&self) -> HistoryCap {
        match self.database().meta.history_max_items {
            None => HistoryCap::Max(DEFAULT_MAX_HISTORY_PER_ENTRY),
            Some(value) if value < 0 => HistoryCap::Unlimited,
            Some(0) => HistoryCap::Disabled,
            // `value` is positive and fits: isize -> usize on the same
            // platform cannot fail for non-negative values.
            Some(value) => HistoryCap::Max(usize::try_from(value).unwrap_or(usize::MAX)),
        }
    }

    /// Set the max history snapshots kept per entry.
    ///
    /// `0` writes the KDBX "history disabled" convention (no snapshots
    /// are appended on update); positive values cap the history list.
    pub fn set_max_history_per_entry(&mut self, n: usize) -> Result<(), VaultError> {
        self.database_mut().meta.history_max_items =
            Some(
                isize::try_from(n).map_err(|_| VaultError::InvalidGroupTarget {
                    reason: "history cap exceeds supported range",
                })?,
            );
        Ok(())
    }
}

pub(crate) fn find_entry_id(db: &Database, uuid: uuid::Uuid) -> Result<EntryId, VaultError> {
    db.iter_all_entries()
        .find(|entry| entry.id().uuid() == uuid)
        .map(|entry| entry.id())
        .ok_or(VaultError::EntryNotFound { uuid })
}

pub(crate) fn find_group_id(db: &Database, uuid: uuid::Uuid) -> Result<GroupId, VaultError> {
    db.iter_all_groups()
        .find(|group| group.id().uuid() == uuid)
        .map(|group| group.id())
        .ok_or(VaultError::GroupNotFound { uuid })
}

pub(crate) fn recycle_bin_group_id_or_create(db: &mut Database) -> GroupId {
    if let Some(bin) = db.recycle_bin() {
        return bin.id();
    }

    let bin_id = db
        .root_mut()
        .add_group()
        .edit(|group| {
            group.name = RECYCLE_BIN_NAME.to_string();
            group.times.creation = Some(Times::now());
            group.times.last_modification = Some(Times::now());
        })
        .id();
    db.meta.recyclebin_uuid = Some(bin_id.uuid());
    db.meta.recyclebin_enabled = Some(true);
    db.meta.recyclebin_changed = Some(Times::now());
    bin_id
}

pub(crate) fn is_entry_in_recycle_bin(db: &Database, entry_id: EntryId) -> bool {
    db.recycle_bin()
        .is_some_and(|bin| group_contains_entry(&bin, entry_id))
}

fn group_contains_entry(group: &keepass::db::GroupRef<'_>, entry_id: EntryId) -> bool {
    group.entry(entry_id).is_some()
        || group
            .groups()
            .any(|child| group_contains_entry(&child, entry_id))
}

fn populate_entry_from_draft(entry: &mut keepass::db::EntryMut<'_>, draft: EntryDraft) {
    entry.set_unprotected(fields::TITLE, draft.title);
    if let Some(username) = draft.username {
        entry.set_unprotected(fields::USERNAME, username);
    }
    if let Some(password) = draft.password {
        entry.set_protected(fields::PASSWORD, password.to_string());
    }
    if let Some(url) = draft.url {
        entry.set_unprotected(fields::URL, url);
    }
    if let Some(notes) = draft.notes {
        entry.set_unprotected(fields::NOTES, notes);
    }
    if let Some(expires_at) = draft.expires_at {
        entry.times.expires = Some(true);
        entry.times.expiry = Some(expires_at.naive_utc());
    }
    entry.tags = draft.tags.into_iter().map(Tag::into_inner).collect();
    for mut field in draft.custom_fields {
        // Move the inner buffer out of the `Zeroizing` wrapper without
        // copying: ownership transfers into the entry's field store (the
        // intended destination); the wrapper then zeroizes only the empty
        // leftover on drop.
        let value = std::mem::take(&mut *field.value);
        if field.protected {
            entry.set_protected(field.name, value);
        } else {
            entry.set_unprotected(field.name, value);
        }
    }
    entry.times.creation = Some(Times::now());
    entry.times.last_modification = Some(Times::now());
}

fn prune_history(entry: &mut Entry, max: usize) {
    if let Some(history) = &mut entry.history {
        if history.get_entries().len() > max {
            let retained: Vec<_> = history.get_entries().iter().take(max).cloned().collect();
            let mut pruned = History::default();
            for historical in retained.into_iter().rev() {
                pruned.add_entry(historical);
            }
            entry.history = Some(pruned);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryBuilder, KdfParams, MasterPassword, NoRecoveryConfirmed};

    fn fast_kdf() -> KdfParams {
        KdfParams {
            memory_kib: 1_024,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn vault_with_entry() -> (tempfile::TempDir, Vault, uuid::Uuid) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("history-cap.kdbx");
        let password = MasterPassword::new("history-cap".to_string());
        let mut vault = Vault::create(
            &path,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create vault");
        let root = vault.root_group_uuid();
        let uuid = vault
            .add_entry(root, EntryBuilder::credential("History Cap").build())
            .expect("add entry");
        (dir, vault, uuid)
    }

    fn history_len(vault: &Vault, uuid: uuid::Uuid) -> usize {
        vault.get_entry(uuid).expect("entry exists").history().len()
    }

    // KeePass/KeePassXC conventions for `Meta/HistoryMaxItems`: absent →
    // default cap, negative → unlimited, 0 → disabled, positive → cap.
    #[test]
    fn history_cap_decodes_meta_conventions() {
        let (_dir, mut vault, _uuid) = vault_with_entry();

        vault.database_mut().meta.history_max_items = None;
        assert_eq!(
            vault.history_cap(),
            HistoryCap::Max(DEFAULT_MAX_HISTORY_PER_ENTRY)
        );

        vault.database_mut().meta.history_max_items = Some(-1);
        assert_eq!(vault.history_cap(), HistoryCap::Unlimited);

        vault.database_mut().meta.history_max_items = Some(0);
        assert_eq!(vault.history_cap(), HistoryCap::Disabled);

        vault.database_mut().meta.history_max_items = Some(5);
        assert_eq!(vault.history_cap(), HistoryCap::Max(5));
    }

    #[test]
    fn unlimited_history_is_never_pruned() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault.database_mut().meta.history_max_items = Some(-1);

        let updates = DEFAULT_MAX_HISTORY_PER_ENTRY + 5;
        for i in 0..updates {
            vault
                .update_entry(uuid, |view| {
                    view.set_username(format!("user-{i}"));
                    Ok(())
                })
                .expect("update entry");
        }
        assert_eq!(
            history_len(&vault, uuid),
            updates,
            "unlimited history must keep every snapshot"
        );
    }

    #[test]
    fn disabled_history_appends_no_snapshots() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault
            .set_max_history_per_entry(0)
            .expect("set history cap to 0");
        assert_eq!(vault.history_cap(), HistoryCap::Disabled);

        vault
            .update_entry(uuid, |view| {
                view.set_username("user".to_string());
                Ok(())
            })
            .expect("update entry");
        assert_eq!(
            history_len(&vault, uuid),
            0,
            "disabled history must not record snapshots"
        );
    }

    // The next three tests tie the CRUD API to the sync merge's needs:
    // keepass-rs's `Database::merge` keys deletion handling off the KDBX
    // `DeletedObjects` tombstone list and relocation handling off
    // `times.location_changed`. If these regress to the untracked APIs,
    // purged entries resurrect on sync and moves silently fail to
    // propagate.

    #[test]
    fn purge_entry_tombstone_survives_save_and_reopen() {
        let (dir, mut vault, uuid) = vault_with_entry();
        vault.purge_entry(uuid).expect("purge entry");
        assert!(
            vault.database().deleted_objects.contains_key(&uuid),
            "purge must record a DeletedObjects tombstone"
        );

        vault.save().expect("save vault");
        drop(vault);

        let reopened = Vault::open(
            &dir.path().join("history-cap.kdbx"),
            &MasterPassword::new("history-cap".to_string()),
            None,
        )
        .expect("reopen vault");
        assert!(
            reopened.database().deleted_objects.contains_key(&uuid),
            "the tombstone must round-trip through the KDBX file"
        );
        assert!(
            reopened.get_entry(uuid).is_err(),
            "the purged entry itself must stay gone"
        );
    }

    #[test]
    fn move_entry_stamps_location_changed() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        let root = vault.root_group_uuid();
        let group = vault.create_group(root, "Target").expect("create group");

        // Simulate an entry without the stamp (e.g. parsed from a file
        // that omitted LocationChanged) so the assertion below proves the
        // move itself writes it.
        let entry_id = find_entry_id(vault.database(), uuid).expect("entry id");
        vault
            .database_mut()
            .entry_mut(entry_id)
            .expect("entry exists")
            .times
            .location_changed = None;

        vault.move_entry(uuid, group).expect("move entry");
        let stamped = vault
            .database()
            .entry(entry_id)
            .expect("entry exists")
            .times
            .location_changed;
        assert!(
            stamped.is_some(),
            "move_entry must stamp times.location_changed for the sync merge"
        );
    }

    #[test]
    fn delete_entry_recycle_bin_move_stamps_location_changed() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        let entry_id = find_entry_id(vault.database(), uuid).expect("entry id");
        vault
            .database_mut()
            .entry_mut(entry_id)
            .expect("entry exists")
            .times
            .location_changed = None;

        vault.delete_entry(uuid).expect("delete to recycle bin");
        let stamped = vault
            .database()
            .entry(entry_id)
            .expect("entry still exists in the bin")
            .times
            .location_changed;
        assert!(
            stamped.is_some(),
            "the recycle-bin move must stamp times.location_changed"
        );
    }

    #[test]
    fn positive_cap_prunes_to_cap_keeping_newest_snapshots() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault.set_max_history_per_entry(2).expect("set history cap");

        for i in 0..4 {
            vault
                .update_entry(uuid, |view| {
                    view.set_username(format!("user-{i}"));
                    Ok(())
                })
                .expect("update entry");
        }
        // Each update snapshots the PRIOR state, so the four updates record
        // ["", user-0, user-1, user-2]; pruning to 2 must keep the two most
        // recent prior states, newest first. A prune that dropped the wrong
        // end (destroying the newest snapshots) would still pass a bare
        // length check.
        let entry = vault.get_entry(uuid).expect("entry exists");
        let usernames: Vec<String> = entry
            .history()
            .iter()
            .map(|h| h.username().to_string())
            .collect();
        assert_eq!(
            usernames,
            vec!["user-2".to_string(), "user-1".to_string()],
            "pruning must retain the newest snapshots, newest first"
        );
    }
}
