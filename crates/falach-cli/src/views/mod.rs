//! Per-subcommand serializable view structs — JSON schema contract.
//!
//! Phase 1 lands the module shape only. Phases 2–4 fill in:
//!
//! - [`vault`]: `VaultCreateView`, `VaultListView`, `VaultOpenView`, `VaultSetLockView`, `VaultSetSyncView`.
//! - [`entry`]: `EntryGetView`, `EntryListView`, `EntrySearchView`, `EntryAddView`, `EntryEditView`, `EntryRmView`.
//! - [`gen`]: `PasswordGenView`, `PassphraseGenView`.
//! - [`sync`]: the `falach sync` outcome view `SyncView`.

pub mod entry;
pub mod gen;
pub mod sync;
pub mod vault;
