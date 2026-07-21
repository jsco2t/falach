//! Entry attachments with a configurable size cap.
//!
//! The cap is stored in KDBX `Meta::custom_data` under the key
//! [`MAX_ATTACHMENT_BYTES_KEY`] as a decimal `u64`. `KeePassXC` preserves
//! unknown custom-metadata fields verbatim, so the value round-trips
//! through interop without loss; clients that do not understand the key
//! ignore it and fall back to the [`DEFAULT_MAX_ATTACHMENT_BYTES`].
//!
//! Attachments are returned as [`zeroize::Zeroizing<Vec<u8>>`] so the
//! caller's buffer self-clears on drop.
//!
//! ## Binary-pool deduplication
//!
//! `keepass-rs` 0.12.9 allocates a fresh `AttachmentId` per
//! `add_attachment` call (`vendor/keepass/src/db/types/entry.rs:393`),
//! so two attachments with identical content occupy two pool entries.
//! Content-based dedup would require crate-internal access we don't
//! have. This is a known divergence from the original Phase-4 plan and
//! is tracked as a follow-up — the feature works correctly; only the
//! storage-size claim is affected.

use keepass::db::{CustomDataItem, CustomDataValue, Times, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::entry::crud::find_entry_id;
use crate::{Attachment, Vault, VaultError, VaultReadOnly};

/// KDBX `Meta::custom_data` key holding the per-attachment byte cap.
pub const MAX_ATTACHMENT_BYTES_KEY: &str = "falach.max_attachment_bytes";

/// Default per-attachment byte cap (5 MiB).
pub const DEFAULT_MAX_ATTACHMENT_BYTES: u64 = 5 * 1024 * 1024;

/// Hard upper bound for the per-attachment cap (100 MiB).
///
/// Mirrors [`VaultError::InvalidAttachmentCap`]'s documented range; values
/// larger than this almost certainly reflect a bug or misuse rather than a
/// legitimate use case for a personal vault.
pub const MAX_ATTACHMENT_BYTES_UPPER_BOUND: u64 = 100 * 1024 * 1024;

impl Vault {
    /// Add `bytes` to `entry` under filename `name`.
    ///
    /// Refuses when `bytes.len() > max_attachment_bytes()` with
    /// [`VaultError::AttachmentTooLarge`].
    pub fn add_attachment(
        &mut self,
        entry: uuid::Uuid,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), VaultError> {
        let limit = self.max_attachment_bytes();
        let actual = bytes.len() as u64;
        if actual > limit {
            return Err(VaultError::AttachmentTooLarge { actual, limit });
        }

        let entry_id = find_entry_id(self.database(), entry)?;
        let mut entry_mut = self
            .database_mut()
            .entry_mut(entry_id)
            .ok_or(VaultError::EntryNotFound { uuid: entry })?;
        entry_mut.add_attachment(name.to_string(), Value::unprotected(bytes.to_vec()));
        // Sync merge tie-breaks on last_modification (see crud.rs:90 convention);
        // metadata side-channels (attachments) update the timestamp without
        // appending to history.
        entry_mut.times.last_modification = Some(Times::now());
        Ok(())
    }

    /// Return the bytes of the attachment named `name` on `entry`, wrapped
    /// in a self-zeroizing buffer.
    pub fn get_attachment(
        &self,
        entry: uuid::Uuid,
        name: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        read_attachment(self.database(), entry, name)
    }

    /// Return metadata for every attachment on `entry`.
    pub fn list_attachments(&self, entry: uuid::Uuid) -> Result<Vec<Attachment>, VaultError> {
        list_attachments_for(self.database(), entry)
    }

    /// Remove the attachment named `name` from `entry`.
    ///
    /// Returns [`VaultError::AttachmentNotFound`] when the entry has no
    /// attachment by that name.
    pub fn remove_attachment(&mut self, entry: uuid::Uuid, name: &str) -> Result<(), VaultError> {
        let entry_id = find_entry_id(self.database(), entry)?;
        let existed = {
            let mut entry_mut = self
                .database_mut()
                .entry_mut(entry_id)
                .ok_or(VaultError::EntryNotFound { uuid: entry })?;
            let existed = entry_mut.attachment_by_name_mut(name).is_some();
            if existed {
                entry_mut.remove_attachment_by_name(name);
                entry_mut.times.last_modification = Some(Times::now());
            }
            existed
        };
        if existed {
            Ok(())
        } else {
            Err(VaultError::AttachmentNotFound {
                name: name.to_string(),
            })
        }
    }

    /// Return the configured per-attachment byte cap.
    pub fn max_attachment_bytes(&self) -> u64 {
        read_max_attachment_bytes(self.database())
    }

    /// Update the per-attachment byte cap.
    ///
    /// Returns [`VaultError::InvalidAttachmentCap`] when `n == 0` or when
    /// `n > MAX_ATTACHMENT_BYTES_UPPER_BOUND`.
    pub fn set_max_attachment_bytes(&mut self, n: u64) -> Result<(), VaultError> {
        if n == 0 || n > MAX_ATTACHMENT_BYTES_UPPER_BOUND {
            return Err(VaultError::InvalidAttachmentCap);
        }
        self.database_mut().meta.custom_data.insert(
            MAX_ATTACHMENT_BYTES_KEY.to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String(n.to_string())),
                last_modification_time: None,
            },
        );
        Ok(())
    }
}

impl VaultReadOnly {
    /// Return the bytes of the attachment named `name` on `entry`, wrapped
    /// in a self-zeroizing buffer.
    pub fn get_attachment(
        &self,
        entry: uuid::Uuid,
        name: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        read_attachment(self.database(), entry, name)
    }

    /// Return metadata for every attachment on `entry`.
    pub fn list_attachments(&self, entry: uuid::Uuid) -> Result<Vec<Attachment>, VaultError> {
        list_attachments_for(self.database(), entry)
    }

    /// Return the configured per-attachment byte cap.
    pub fn max_attachment_bytes(&self) -> u64 {
        read_max_attachment_bytes(self.database())
    }
}

fn read_attachment(
    db: &keepass::Database,
    entry: uuid::Uuid,
    name: &str,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let entry_id = find_entry_id(db, entry)?;
    let entry_ref = db
        .entry(entry_id)
        .ok_or(VaultError::EntryNotFound { uuid: entry })?;
    let attachment =
        entry_ref
            .attachment_by_name(name)
            .ok_or_else(|| VaultError::AttachmentNotFound {
                name: name.to_string(),
            })?;
    Ok(Zeroizing::new(attachment.data.as_slice().to_vec()))
}

fn list_attachments_for(
    db: &keepass::Database,
    entry: uuid::Uuid,
) -> Result<Vec<Attachment>, VaultError> {
    let entry_id = find_entry_id(db, entry)?;
    let entry_ref = db
        .entry(entry_id)
        .ok_or(VaultError::EntryNotFound { uuid: entry })?;
    Ok(entry_ref
        .attachments_named()
        .map(|(name, attachment)| Attachment {
            name: name.to_string(),
            size_bytes: attachment.data.as_slice().len() as u64,
            content_hash: Sha256::digest(attachment.data.as_slice()).into(),
        })
        .collect())
}

fn read_max_attachment_bytes(db: &keepass::Database) -> u64 {
    db.meta
        .custom_data
        .get(MAX_ATTACHMENT_BYTES_KEY)
        .and_then(|item| item.value.as_ref())
        .and_then(|value| match value {
            CustomDataValue::String(s) => s.parse::<u64>().ok(),
            CustomDataValue::Binary(_) => None,
        })
        .unwrap_or(DEFAULT_MAX_ATTACHMENT_BYTES)
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
        let path = dir.path().join("attachments.kdbx");
        let password = MasterPassword::new("attachments".to_string());
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
            .add_entry(root, EntryBuilder::credential("With Attachments").build())
            .expect("add entry");
        (dir, vault, uuid)
    }

    #[test]
    fn default_max_attachment_bytes_is_five_mib() {
        let (_dir, vault, _) = vault_with_entry();
        assert_eq!(vault.max_attachment_bytes(), DEFAULT_MAX_ATTACHMENT_BYTES);
    }

    #[test]
    fn add_attachment_round_trips_bytes() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        let bytes = b"hello attachments".to_vec();

        vault
            .add_attachment(uuid, "greeting.txt", &bytes)
            .expect("add attachment");

        let read = vault
            .get_attachment(uuid, "greeting.txt")
            .expect("get attachment");
        assert_eq!(read.as_slice(), bytes.as_slice());
    }

    #[test]
    fn add_attachment_at_cap_succeeds() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault.set_max_attachment_bytes(1024).expect("set cap");
        let bytes = vec![0u8; 1024];

        vault
            .add_attachment(uuid, "max.bin", &bytes)
            .expect("at-cap should succeed");
        assert_eq!(
            vault.get_attachment(uuid, "max.bin").expect("get").len(),
            1024
        );
    }

    #[test]
    fn add_attachment_one_over_cap_returns_attachment_too_large() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault.set_max_attachment_bytes(1024).expect("set cap");
        let bytes = vec![0u8; 1025];

        let err = vault
            .add_attachment(uuid, "over.bin", &bytes)
            .expect_err("over-cap should fail");

        assert!(matches!(
            err,
            VaultError::AttachmentTooLarge {
                actual: 1025,
                limit: 1024
            }
        ));
    }

    #[test]
    fn get_attachment_returns_attachment_not_found_for_missing_name() {
        let (_dir, vault, uuid) = vault_with_entry();
        let err = vault
            .get_attachment(uuid, "nonesuch")
            .expect_err("missing attachment should fail");
        assert!(matches!(err, VaultError::AttachmentNotFound { name } if name == "nonesuch"));
    }

    #[test]
    fn remove_attachment_drops_pool_entry() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault
            .add_attachment(uuid, "tmp.bin", &[1, 2, 3])
            .expect("add");
        assert_eq!(vault.database().num_attachments(), 1);

        vault.remove_attachment(uuid, "tmp.bin").expect("remove");

        assert_eq!(
            vault.database().num_attachments(),
            0,
            "pool entry freed when last reference gone"
        );
        let err = vault
            .get_attachment(uuid, "tmp.bin")
            .expect_err("attachment should be gone");
        assert!(matches!(err, VaultError::AttachmentNotFound { .. }));
    }

    #[test]
    fn remove_attachment_yields_attachment_not_found_for_missing_name() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        let err = vault
            .remove_attachment(uuid, "never-added")
            .expect_err("missing attachment should fail");
        assert!(matches!(err, VaultError::AttachmentNotFound { .. }));
    }

    #[test]
    fn list_attachments_includes_size_and_hash() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        let bytes = b"list me".to_vec();
        vault.add_attachment(uuid, "list.txt", &bytes).expect("add");

        let list = vault.list_attachments(uuid).expect("list");

        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "list.txt");
        assert_eq!(list[0].size_bytes, bytes.len() as u64);
        let expected_hash: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(list[0].content_hash, expected_hash);
    }

    #[test]
    fn set_max_attachment_bytes_zero_rejected() {
        let (_dir, mut vault, _) = vault_with_entry();
        let err = vault
            .set_max_attachment_bytes(0)
            .expect_err("zero should fail");
        assert!(matches!(err, VaultError::InvalidAttachmentCap));
    }

    #[test]
    fn set_max_attachment_bytes_above_upper_bound_rejected() {
        let (_dir, mut vault, _) = vault_with_entry();
        let err = vault
            .set_max_attachment_bytes(MAX_ATTACHMENT_BYTES_UPPER_BOUND + 1)
            .expect_err("absurd cap should fail");
        assert!(matches!(err, VaultError::InvalidAttachmentCap));
    }

    #[test]
    fn set_max_attachment_bytes_persists_in_meta_custom_data() {
        let (_dir, mut vault, _) = vault_with_entry();
        vault.set_max_attachment_bytes(2048).expect("set");
        assert_eq!(vault.max_attachment_bytes(), 2048);

        let stored = vault
            .database()
            .meta
            .custom_data
            .get(MAX_ATTACHMENT_BYTES_KEY)
            .expect("custom_data entry present");
        match stored.value.as_ref().expect("value present") {
            CustomDataValue::String(s) => assert_eq!(s, "2048"),
            CustomDataValue::Binary(_) => panic!("unexpected binary value"),
        }
    }

    #[test]
    fn get_attachment_returns_zeroizing_wrapper() {
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault
            .add_attachment(uuid, "z.bin", &[9, 9, 9])
            .expect("add");

        // Type-level assertion via explicit annotation: the return type is
        // Zeroizing<Vec<u8>>. A signature change would fail to compile.
        let read: Zeroizing<Vec<u8>> = vault.get_attachment(uuid, "z.bin").expect("get");
        assert_eq!(read.as_slice(), &[9, 9, 9]);
    }

    #[test]
    fn add_attachment_does_not_append_history() {
        // Design §2.2.7 / §3.7: attachments are a metadata side-channel and
        // explicitly do not push to entry history. Confirms the contract by
        // observing that an attachment add leaves the entry's history list
        // empty (no automatic snapshot like update_entry would create).
        let (_dir, mut vault, uuid) = vault_with_entry();
        vault
            .add_attachment(uuid, "side.txt", &[1])
            .expect("add attachment");

        let entry = vault.get_entry(uuid).expect("entry");
        assert!(
            entry.history().is_empty(),
            "attachment add must not push to history"
        );
    }

    #[test]
    fn ignores_non_string_custom_metadata_value() {
        let (_dir, mut vault, _) = vault_with_entry();
        vault.database_mut().meta.custom_data.insert(
            MAX_ATTACHMENT_BYTES_KEY.to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::Binary(vec![1, 2, 3])),
                last_modification_time: None,
            },
        );
        assert_eq!(
            vault.max_attachment_bytes(),
            DEFAULT_MAX_ATTACHMENT_BYTES,
            "binary value should fall back to default rather than panic"
        );
    }

    #[test]
    fn ignores_non_numeric_custom_metadata_value() {
        let (_dir, mut vault, _) = vault_with_entry();
        vault.database_mut().meta.custom_data.insert(
            MAX_ATTACHMENT_BYTES_KEY.to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("not a number".to_string())),
                last_modification_time: None,
            },
        );
        assert_eq!(vault.max_attachment_bytes(), DEFAULT_MAX_ATTACHMENT_BYTES);
    }
}
