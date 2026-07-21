//! Entry expiration metadata and the inclusive `is_expired(now)` view.
//!
//! KDBX stores expiration in two `Times` fields: `expires: bool` (the
//! enabled flag) and `expiry: NaiveDateTime` (the cutoff). The public API
//! surfaces `chrono::DateTime<Utc>` and converts on the way in/out.
//!
//! Per design §2.2.8, `is_expired(uuid, now)` is *inclusive* of the exact
//! `expiry` moment: at `now == expiry`, the entry is considered expired.

use chrono::{DateTime, Utc};
use keepass::db::Times;

use crate::entry::crud::find_entry_id;
use crate::{Vault, VaultError, VaultReadOnly};

impl Vault {
    /// Mark `uuid` as expiring at `when` (UTC). Replaces any prior expiration.
    pub fn set_expiration(
        &mut self,
        uuid: uuid::Uuid,
        when: DateTime<Utc>,
    ) -> Result<(), VaultError> {
        let entry_id = find_entry_id(self.database(), uuid)?;
        let mut entry = self
            .database_mut()
            .entry_mut(entry_id)
            .ok_or(VaultError::EntryNotFound { uuid })?;
        entry.times.expires = Some(true);
        entry.times.expiry = Some(when.naive_utc());
        // Sync merge tie-breaks on last_modification (see crud.rs:90 convention);
        // metadata mutations must refresh it even though they skip history.
        entry.times.last_modification = Some(Times::now());
        Ok(())
    }

    /// Clear the expiration flag on `uuid`. The KDBX-stored `expiry` field
    /// is preserved verbatim (`KeePassXC` ignores it when `expires == false`)
    /// so that re-enabling expiration with the same value is lossless.
    pub fn clear_expiration(&mut self, uuid: uuid::Uuid) -> Result<(), VaultError> {
        let entry_id = find_entry_id(self.database(), uuid)?;
        let mut entry = self
            .database_mut()
            .entry_mut(entry_id)
            .ok_or(VaultError::EntryNotFound { uuid })?;
        entry.times.expires = Some(false);
        entry.times.last_modification = Some(Times::now());
        Ok(())
    }

    /// Return `true` when `uuid` expires and `now >= expiry`.
    pub fn is_expired(&self, uuid: uuid::Uuid, now: DateTime<Utc>) -> Result<bool, VaultError> {
        is_expired(self.database(), uuid, now)
    }
}

impl VaultReadOnly {
    /// Return `true` when `uuid` expires and `now >= expiry`.
    pub fn is_expired(&self, uuid: uuid::Uuid, now: DateTime<Utc>) -> Result<bool, VaultError> {
        is_expired(self.database(), uuid, now)
    }
}

fn is_expired(
    db: &keepass::Database,
    uuid: uuid::Uuid,
    now: DateTime<Utc>,
) -> Result<bool, VaultError> {
    let entry_id = find_entry_id(db, uuid)?;
    let entry = db
        .entry(entry_id)
        .ok_or(VaultError::EntryNotFound { uuid })?;
    let expires = entry.times.expires.unwrap_or(false);
    if !expires {
        return Ok(false);
    }
    let Some(expiry) = entry.times.expiry else {
        // `expires == true` without an `expiry` timestamp is malformed KDBX
        // produced by some legacy tools; treat it as "never expires" rather
        // than panic.
        return Ok(false);
    };
    let expiry_utc = DateTime::<Utc>::from_naive_utc_and_offset(expiry, Utc);
    Ok(now >= expiry_utc)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::{EntryBuilder, KdfParams, MasterPassword, NoRecoveryConfirmed};

    fn fast_kdf() -> KdfParams {
        KdfParams {
            memory_kib: 1_024,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn fixed_time(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0)
            .single()
            .expect("valid timestamp")
    }

    fn vault_with_entry() -> (tempfile::TempDir, Vault, uuid::Uuid) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("expiration.kdbx");
        let password = MasterPassword::new("expiration".to_string());
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
            .add_entry(root, EntryBuilder::credential("Exp").build())
            .expect("add entry");
        (dir, vault, uuid)
    }

    #[test]
    fn set_expiration_marks_expires_true_and_stores_time() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        let when = fixed_time(1_000_000);

        vault.set_expiration(uuid, when).expect("set expiration");

        assert!(vault.is_expired(uuid, when).expect("at boundary"));
        assert!(vault
            .is_expired(uuid, fixed_time(1_000_001))
            .expect("after"));
    }

    #[test]
    fn clear_expiration_disables_flag_but_preserves_timestamp() {
        use crate::entry::crud::find_entry_id;

        let (_dir, mut vault, uuid) = vault_with_entry();
        let when = fixed_time(1_000_000);
        vault.set_expiration(uuid, when).expect("set expiration");
        vault.clear_expiration(uuid).expect("clear expiration");

        // Behavior: is_expired returns false after clear.
        assert!(!vault.is_expired(uuid, when).expect("query"));
        assert!(!vault
            .is_expired(uuid, fixed_time(2_000_000))
            .expect("future"));

        // Storage: the KDBX `expiry` NaiveDateTime is preserved verbatim
        // alongside `expires = false`. A regression that cleared `expiry`
        // on `clear_expiration` would still pass `is_expired` checks but
        // lose the timestamp, breaking the "lossless clear+set" promise
        // documented on the method.
        let entry_id = find_entry_id(vault.database(), uuid).expect("entry exists after clear");
        let entry = vault.database().entry(entry_id).expect("entry handle");
        assert_eq!(entry.times.expires, Some(false));
        assert_eq!(
            entry.times.expiry,
            Some(when.naive_utc()),
            "expiry timestamp must survive clear_expiration"
        );
    }

    #[test]
    fn is_expired_one_second_before_returns_false() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault
            .set_expiration(uuid, fixed_time(1_000_000))
            .expect("set");
        assert!(!vault
            .is_expired(uuid, fixed_time(999_999))
            .expect("one second before"));
    }

    #[test]
    fn is_expired_one_second_after_returns_true() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault
            .set_expiration(uuid, fixed_time(1_000_000))
            .expect("set");
        assert!(vault
            .is_expired(uuid, fixed_time(1_000_001))
            .expect("one second after"));
    }

    #[test]
    fn is_expired_inclusive_at_exact_boundary() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        let when = fixed_time(1_000_000);
        vault.set_expiration(uuid, when).expect("set");
        assert!(
            vault.is_expired(uuid, when).expect("boundary"),
            "is_expired is inclusive at the exact expiry"
        );
    }

    #[test]
    fn is_expired_never_expires_returns_false_for_any_time() {
        let (_dir, vault, uuid) = vault_with_entry();
        // Brand-new entry has no expiration set.
        assert!(!vault.is_expired(uuid, fixed_time(0)).expect("epoch"));
        // Far future, but within chrono's representable range (~year 262143).
        assert!(!vault
            .is_expired(uuid, fixed_time(4_102_444_800))
            .expect("far future"));
    }

    #[test]
    fn is_expired_unknown_uuid_yields_entry_not_found() {
        let (_dir, vault, _) = vault_with_entry();
        let bogus = uuid::Uuid::new_v4();
        let err = vault
            .is_expired(bogus, fixed_time(0))
            .expect_err("missing uuid");
        assert!(matches!(err, VaultError::EntryNotFound { uuid } if uuid == bogus));
    }

    #[test]
    fn set_expiration_does_not_append_history() {
        // Design §2.2.8: expiration is a metadata side-channel; no history.
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault
            .set_expiration(uuid, fixed_time(1_000_000))
            .expect("set");

        let entry = vault.get_entry(uuid).expect("entry");
        assert!(
            entry.history().is_empty(),
            "set_expiration must not push to history"
        );
    }
}
