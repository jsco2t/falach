//! Group operations and vault-level tag aggregation.

use std::collections::BTreeSet;

use keepass::db::{MoveGroupError, Times};

use crate::entry::crud::{find_group_id, is_entry_in_recycle_bin, recycle_bin_group_id_or_create};
use crate::{Tag, Vault, VaultError};

/// Behavior to use when deleting a group.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GroupDeleteBehavior {
    /// Refuse to delete a group that contains entries or child groups.
    #[default]
    Refuse,
    /// Move the group subtree to the Recycle Bin.
    Recurse,
}

/// Read-only view of a KDBX group.
pub struct GroupView<'a> {
    group: keepass::db::GroupRef<'a>,
}

impl<'a> GroupView<'a> {
    /// Wrap a `keepass-rs` group reference.
    pub fn new(group: keepass::db::GroupRef<'a>) -> Self {
        Self { group }
    }

    /// Return the group UUID.
    pub fn uuid(&self) -> uuid::Uuid {
        self.group.id().uuid()
    }

    /// Return the group name.
    pub fn name(&self) -> &str {
        &self.group.name
    }

    /// Return direct child group UUIDs.
    pub fn child_group_uuids(&self) -> Vec<uuid::Uuid> {
        let mut uuids: Vec<_> = self.group.groups().map(|group| group.id().uuid()).collect();
        uuids.sort_unstable();
        uuids
    }

    /// Return direct child entry UUIDs.
    pub fn entry_uuids(&self) -> Vec<uuid::Uuid> {
        let mut uuids: Vec<_> = self
            .group
            .entries()
            .map(|entry| entry.id().uuid())
            .collect();
        uuids.sort_unstable();
        uuids
    }

    /// Return whether the group has no child groups or entries.
    pub fn is_empty(&self) -> bool {
        self.group.group_ids().next().is_none() && self.group.entry_ids().next().is_none()
    }
}

impl Vault {
    /// Return the root group UUID.
    pub fn root_group_uuid(&self) -> uuid::Uuid {
        self.database().root().id().uuid()
    }

    /// Return a read-only view of a group.
    pub fn group_view(&self, uuid: uuid::Uuid) -> Result<GroupView<'_>, VaultError> {
        let group_id = find_group_id(self.database(), uuid)?;
        self.database()
            .group(group_id)
            .map(GroupView::new)
            .ok_or(VaultError::GroupNotFound { uuid })
    }

    /// Create a child group under `parent`.
    pub fn create_group(
        &mut self,
        parent: uuid::Uuid,
        name: &str,
    ) -> Result<uuid::Uuid, VaultError> {
        let parent_id = find_group_id(self.database(), parent)?;
        let group_id = self
            .database_mut()
            .group_mut(parent_id)
            .ok_or(VaultError::GroupNotFound { uuid: parent })?
            .add_group()
            .edit(|group| {
                group.name = name.to_string();
                group.times.creation = Some(Times::now());
                group.times.last_modification = Some(Times::now());
            })
            .id();
        Ok(group_id.uuid())
    }

    /// Rename a group while preserving its UUID.
    pub fn rename_group(&mut self, uuid: uuid::Uuid, new_name: &str) -> Result<(), VaultError> {
        let group_id = find_group_id(self.database(), uuid)?;
        self.database_mut()
            .group_mut(group_id)
            .ok_or(VaultError::GroupNotFound { uuid })?
            .edit(|group| {
                group.name = new_name.to_string();
                group.times.last_modification = Some(Times::now());
            });
        Ok(())
    }

    /// Move a group to a new parent while preserving all UUIDs.
    pub fn move_group(
        &mut self,
        uuid: uuid::Uuid,
        new_parent: uuid::Uuid,
    ) -> Result<(), VaultError> {
        let group_id = find_group_id(self.database(), uuid)?;
        let new_parent_id = find_group_id(self.database(), new_parent)?;
        if group_id.uuid() == self.root_group_uuid() {
            return Err(VaultError::CannotModifyRoot);
        }
        if self
            .database()
            .recycle_bin()
            .is_some_and(|bin| new_parent_id == bin.id())
        {
            return Err(VaultError::InvalidGroupTarget {
                reason: "cannot move a group directly into the recycle bin",
            });
        }

        // Tracked move: stamps `times.location_changed`, which the sync
        // merge requires on both sides to propagate group relocations.
        self.database_mut()
            .group_mut(group_id)
            .ok_or(VaultError::GroupNotFound { uuid })?
            .track_changes()
            .move_to(new_parent_id)
            .map_err(|err| map_move_group_error(&err))?;
        Ok(())
    }

    /// Delete a group according to `behavior`.
    pub fn delete_group(
        &mut self,
        uuid: uuid::Uuid,
        behavior: GroupDeleteBehavior,
    ) -> Result<(), VaultError> {
        let group_id = find_group_id(self.database(), uuid)?;
        if uuid == self.root_group_uuid() {
            return Err(VaultError::CannotModifyRoot);
        }

        match behavior {
            GroupDeleteBehavior::Refuse => {
                let group = self
                    .database()
                    .group(group_id)
                    .ok_or(VaultError::GroupNotFound { uuid })?;
                if group.group_ids().next().is_some() || group.entry_ids().next().is_some() {
                    return Err(VaultError::GroupNotEmpty { uuid });
                }
                let bin_id = recycle_bin_group_id_or_create(self.database_mut());
                if group_id == bin_id {
                    return Ok(());
                }
                // Tracked move into the bin — see `move_group`.
                self.database_mut()
                    .group_mut(group_id)
                    .ok_or(VaultError::GroupNotFound { uuid })?
                    .track_changes()
                    .move_to(bin_id)
                    .map_err(|err| map_move_group_error(&err))?;
                Ok(())
            }
            GroupDeleteBehavior::Recurse => {
                let bin_id = recycle_bin_group_id_or_create(self.database_mut());
                if group_id == bin_id {
                    return Ok(());
                }
                // Tracked move into the bin — see `move_group`.
                self.database_mut()
                    .group_mut(group_id)
                    .ok_or(VaultError::GroupNotFound { uuid })?
                    .track_changes()
                    .move_to(bin_id)
                    .map_err(|err| map_move_group_error(&err))?;
                Ok(())
            }
        }
    }

    /// Return distinct tags across all non-recycled entries.
    pub fn list_tags(&self) -> Vec<Tag> {
        let mut tags = BTreeSet::new();
        for entry in self.database().iter_all_entries() {
            if is_entry_in_recycle_bin(self.database(), entry.id()) {
                continue;
            }
            for tag in &entry.tags {
                if let Ok(tag) = Tag::from(tag.clone()) {
                    tags.insert(tag);
                }
            }
        }
        tags.into_iter().collect()
    }

    /// Add a tag to an entry.
    pub fn add_tag(&mut self, uuid: uuid::Uuid, tag: Tag) -> Result<(), VaultError> {
        self.get_entry_mut(uuid)?.add_tag(tag);
        Ok(())
    }

    /// Remove a tag from an entry.
    pub fn remove_tag(&mut self, uuid: uuid::Uuid, tag: &Tag) -> Result<(), VaultError> {
        self.get_entry_mut(uuid)?.remove_tag(tag);
        Ok(())
    }

    /// Replace all tags on an entry.
    pub fn set_tags(
        &mut self,
        uuid: uuid::Uuid,
        tags: impl IntoIterator<Item = Tag>,
    ) -> Result<(), VaultError> {
        self.get_entry_mut(uuid)?.set_tags(tags);
        Ok(())
    }
}

fn map_move_group_error(err: &MoveGroupError) -> VaultError {
    match err {
        MoveGroupError::CannotMoveRoot => VaultError::CannotModifyRoot,
        MoveGroupError::NotFound(group_id) => VaultError::GroupNotFound {
            uuid: group_id.uuid(),
        },
        MoveGroupError::WouldCreateCycle => VaultError::InvalidGroupTarget {
            reason: "cannot move a group into itself or one of its descendants",
        },
        _ => VaultError::InvalidGroupTarget {
            reason: "unsupported group move failure",
        },
    }
}
