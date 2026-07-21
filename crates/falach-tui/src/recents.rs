//! `Recents` — the per-vault most-recently-used entry list (T4.2 / ADR-T5).
//!
//! A bounded, most-recent-first list of entry UUIDs. The TUI owns this signal
//! because `falach-core` exposes no last-access timestamp and a read-only open
//! records nothing — so "recently used" can only come from a UI-side list. An
//! entry is [`bump`](Recents::bump)ed to the front when the user **opens its
//! detail or copies a field** (D-6); the `RecentlyUsed` tree sort orders by
//! [`rank`](Recents::rank) (in-list entries first, ascending; the rest fall
//! back to title order — see `entry_tree::sort_entries`).
//!
//! The list holds only UUIDs (non-secret), so it is persisted verbatim in
//! `tui.toml` (ADR-T3) and is **not** cleared on lock; it is reloaded from disk
//! on the next unlock.

use uuid::Uuid;

/// Maximum entries retained (D-6). Old entries fall off the back when exceeded.
pub(crate) const RECENTS_CAP: usize = 50;

/// A bounded MRU list of entry UUIDs, most-recent first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Recents {
    order: Vec<Uuid>,
}

impl Recents {
    /// An empty list.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Hydrate from a persisted list (newest first). Truncated to [`RECENTS_CAP`]
    /// and de-duplicated (first occurrence wins) so a hand-edited or
    /// older-schema `tui.toml` can't introduce duplicates or unbounded growth.
    pub(crate) fn from_persisted(list: &[Uuid]) -> Self {
        let mut order: Vec<Uuid> = Vec::with_capacity(list.len().min(RECENTS_CAP));
        for &uuid in list {
            if !order.contains(&uuid) {
                order.push(uuid);
                if order.len() == RECENTS_CAP {
                    break;
                }
            }
        }
        Self { order }
    }

    /// Move `uuid` to the front (most-recently-used). If it was already present
    /// it is de-duplicated; the list is capped at [`RECENTS_CAP`], dropping the
    /// least-recently-used tail.
    pub(crate) fn bump(&mut self, uuid: Uuid) {
        self.order.retain(|&u| u != uuid);
        self.order.insert(0, uuid);
        self.order.truncate(RECENTS_CAP);
    }

    /// Forget `uuid` entirely (D-6). Wired by the delete path (T5.2).
    pub(crate) fn remove(&mut self, uuid: Uuid) {
        self.order.retain(|&u| u != uuid);
    }

    /// The 0-based position of `uuid` (0 = most recent), or `None` if absent.
    /// Drives the `RecentlyUsed` sort.
    pub(crate) fn rank(&self, uuid: Uuid) -> Option<usize> {
        self.order.iter().position(|&u| u == uuid)
    }

    /// The list as a slice (newest first) for persistence into `tui.toml`.
    pub(crate) fn as_slice(&self) -> &[Uuid] {
        &self.order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuids(n: usize) -> Vec<Uuid> {
        (0..n).map(|_| Uuid::new_v4()).collect()
    }

    #[test]
    fn bump_moves_to_front_and_dedups() {
        let ids = uuids(3);
        let mut r = Recents::new();
        r.bump(ids[0]);
        r.bump(ids[1]);
        r.bump(ids[2]);
        // Most-recent first: 2, 1, 0.
        assert_eq!(r.as_slice(), &[ids[2], ids[1], ids[0]]);
        // Re-bumping an existing entry moves it to the front without duplicating.
        r.bump(ids[0]);
        assert_eq!(r.as_slice(), &[ids[0], ids[2], ids[1]]);
        assert_eq!(r.as_slice().len(), 3, "no duplicate introduced");
    }

    #[test]
    fn rank_reflects_recency_order() {
        let ids = uuids(2);
        let mut r = Recents::new();
        r.bump(ids[0]);
        r.bump(ids[1]);
        assert_eq!(r.rank(ids[1]), Some(0), "most-recent is rank 0");
        assert_eq!(r.rank(ids[0]), Some(1));
        assert_eq!(r.rank(Uuid::new_v4()), None, "unseen entry has no rank");
    }

    #[test]
    fn bump_caps_at_recents_cap_dropping_oldest() {
        let ids = uuids(RECENTS_CAP + 5);
        let mut r = Recents::new();
        for &id in &ids {
            r.bump(id);
        }
        assert_eq!(r.as_slice().len(), RECENTS_CAP, "list is bounded");
        // The 5 oldest fell off the back; the most-recent is the last bumped.
        assert_eq!(r.rank(ids[ids.len() - 1]), Some(0));
        for old in &ids[0..5] {
            assert_eq!(r.rank(*old), None, "oldest entries evicted past the cap");
        }
    }

    #[test]
    fn remove_forgets_the_entry() {
        let ids = uuids(2);
        let mut r = Recents::new();
        r.bump(ids[0]);
        r.bump(ids[1]);
        r.remove(ids[0]);
        assert_eq!(r.rank(ids[0]), None);
        assert_eq!(r.as_slice(), &[ids[1]]);
    }

    #[test]
    fn from_persisted_dedups_and_caps() {
        let ids = uuids(3);
        // A list with a duplicate and (conceptually) hand-edited content.
        let persisted = vec![ids[0], ids[1], ids[0], ids[2]];
        let r = Recents::from_persisted(&persisted);
        assert_eq!(
            r.as_slice(),
            &[ids[0], ids[1], ids[2]],
            "first occurrence wins; order otherwise preserved"
        );

        let many = uuids(RECENTS_CAP + 10);
        let r = Recents::from_persisted(&many);
        assert_eq!(r.as_slice().len(), RECENTS_CAP);
    }
}
